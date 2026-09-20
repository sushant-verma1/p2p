//! Length-delimited framing — `architecture.md` §5.
//!
//! `u32` big-endian length, then that many `postcard` bytes. QUIC does not
//! preserve message boundaries within a stream, so the framing is still
//! required even though the transport is reliable and ordered.
//!
//! The length is checked against [`MAX_FRAME_SIZE`] before it is used for
//! anything at all. A peer that announces four gigabytes gets an error and a
//! closed connection, not an allocation.

use crate::wire::WireType;
use crate::CoreError;

/// `architecture.md` §5: anything larger closes the connection.
pub const MAX_FRAME_SIZE: usize = 64 * 1024;

/// Width of the big-endian length prefix.
pub const LENGTH_PREFIX: usize = 4;

/// Appends one complete frame — prefix and body — to `out`.
///
/// Validates before serializing, so a value that a peer would have to reject
/// never leaves this process.
pub fn encode<T: WireType>(value: &T, out: &mut Vec<u8>) -> Result<(), CoreError> {
    value.validate()?;
    let body = postcard::to_stdvec(value)?;
    let size = body.len();
    if size > MAX_FRAME_SIZE {
        return Err(CoreError::FrameTooLarge { size });
    }
    out.reserve(LENGTH_PREFIX + size);
    // Lossless: `size` is at most 64 KiB by the check above.
    out.extend_from_slice(&(size as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(())
}

/// The body length announced by a prefix, or [`CoreError::FrameTooLarge`].
///
/// This is the whole defence, and it is one comparison: nothing downstream
/// sees a number larger than [`MAX_FRAME_SIZE`].
pub fn frame_len(prefix: [u8; LENGTH_PREFIX]) -> Result<usize, CoreError> {
    let size = u32::from_be_bytes(prefix) as usize;
    if size > MAX_FRAME_SIZE {
        return Err(CoreError::FrameTooLarge { size });
    }
    Ok(size)
}

/// Takes one frame off the front of `src`, appending its body to `out` and
/// returning the number of bytes consumed.
///
/// `Ok(None)` means `src` does not hold a whole frame yet — the caller reads
/// more and tries again. The size check happens first, so an over-size frame is
/// reported immediately rather than after waiting for bytes that would never
/// be allowed anyway.
pub fn read_frame(src: &[u8], out: &mut Vec<u8>) -> Result<Option<usize>, CoreError> {
    let Some(prefix) = src.first_chunk::<LENGTH_PREFIX>() else {
        return Ok(None);
    };
    let size = frame_len(*prefix)?;
    let end = LENGTH_PREFIX + size;
    let Some(body) = src.get(LENGTH_PREFIX..end) else {
        return Ok(None);
    };
    out.extend_from_slice(body);
    Ok(Some(end))
}

/// Decodes a frame body, then checks every bound on it.
///
/// The only way to turn wire bytes into a [`WireType`]: validation is not
/// something a call site can forget to do.
pub fn decode<T: WireType>(body: &[u8]) -> Result<T, CoreError> {
    let value: T = postcard::from_bytes(body)?;
    value.validate()?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ConnectionStatus, PROTOCOL_VERSION};
    use crate::UserId;

    fn sample() -> ConnectionStatus {
        ConnectionStatus {
            version: PROTOCOL_VERSION,
            from_user_id: UserId::from_bytes([7; 32]),
        }
    }

    #[test]
    fn a_frame_is_a_big_endian_length_and_a_body() {
        let mut buf = Vec::new();
        encode(&sample(), &mut buf).unwrap();
        let body_len = buf.len() - LENGTH_PREFIX;
        assert_eq!(buf[..LENGTH_PREFIX], (body_len as u32).to_be_bytes());

        let mut body = Vec::new();
        assert_eq!(read_frame(&buf, &mut body).unwrap(), Some(buf.len()));
        assert_eq!(decode::<ConnectionStatus>(&body).unwrap(), sample());
    }

    #[test]
    fn two_frames_in_one_buffer_are_read_one_at_a_time() {
        let mut buf = Vec::new();
        encode(&sample(), &mut buf).unwrap();
        let first = buf.len();
        encode(&sample(), &mut buf).unwrap();

        let mut body = Vec::new();
        assert_eq!(read_frame(&buf, &mut body).unwrap(), Some(first));
        body.clear();
        assert_eq!(
            read_frame(&buf[first..], &mut body).unwrap(),
            Some(buf.len() - first)
        );
    }

    #[test]
    fn a_partial_frame_asks_for_more() {
        let mut buf = Vec::new();
        encode(&sample(), &mut buf).unwrap();
        let mut body = Vec::new();
        for take in 0..buf.len() {
            assert_eq!(
                read_frame(&buf[..take], &mut body).unwrap(),
                None,
                "{take} bytes looked like a whole frame"
            );
            assert!(body.is_empty());
        }
    }

    #[test]
    fn the_limit_itself_is_allowed() {
        let at_limit = frame_len((MAX_FRAME_SIZE as u32).to_be_bytes()).unwrap();
        assert_eq!(at_limit, MAX_FRAME_SIZE);
        assert!(frame_len((MAX_FRAME_SIZE as u32 + 1).to_be_bytes()).is_err());
    }
}
