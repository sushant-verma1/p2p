//! The binary's half of the TUI seam — `architecture.md` §2.
//!
//! Two channels and nothing else cross between the runtime and the screen:
//!
//! - **TUI → core**, a [`Request`] with a `oneshot` for the answer. The TUI
//!   thread sends with `blocking_send` and waits with `blocking_recv`; it is
//!   not a runtime thread and never calls `block_on`.
//! - **core → TUI**, a [`Notice`], which carries a user ID and no payload. The
//!   core sends it with `try_send` and does not care whether it arrives: the
//!   store holds what the notice describes, so a dropped one costs a redraw
//!   that the next notice asks for anyway. Only a full channel drops one, and
//!   a full channel is sixty-odd notices still queued to wake the TUI.
//!
//! That asymmetry is the point. A payload on the core → TUI channel would put
//! the session task's progress behind the render loop's; a notification cannot.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use tokio::sync::{mpsc, oneshot};

use p2pchat_core::UserId;
use p2pchat_crypto::{derive_conversation_id, invite};
use p2pchat_store::Peer;
use p2pchat_tui::{ConnState, Conversation, Core, Cursor, Line, Notice, Pending, Preview};

use crate::node::{Config, Node, Phase};
use crate::Event;

/// Depth of the TUI → core channel. One request is in flight at a time — the
/// TUI thread blocks on the answer — so this is only slack.
const REQUESTS: usize = 8;

/// Depth of the core → TUI channel. Deep enough that a busy session does not
/// lose the notice that matters while the screen is drawing, shallow enough
/// that a stalled TUI is not holding a megabyte of them.
const NOTICES: usize = 64;

/// What the screen knows how to ask for. One variant per [`Core`] method.
enum Request {
    Conversations(oneshot::Sender<Vec<Conversation>>),
    Pending(oneshot::Sender<Vec<Pending>>),
    Page {
        peer: UserId,
        before: Option<Cursor>,
        reply: oneshot::Sender<Vec<Line>>,
    },
    Send {
        peer: UserId,
        body: String,
    },
    Decide {
        from: UserId,
        accept: bool,
    },
    Verify(UserId),
    Import {
        blob: String,
        reply: oneshot::Sender<Result<Preview, String>>,
    },
    Connect(UserId),
}

/// The one thing about a connection that cannot be read back — M9e.
///
/// F-25's column is not stored anywhere: `Node::sessions` says who is
/// connected and `Node::connecting` says who is being reached, and
/// [`conversations`] asks both on every question the screen puts. This holds
/// only the leftover — that the *last* attempt failed — which is history and
/// so has no source to be read from.
///
/// Nothing else may go in here. A remembered `Connecting` is what kept the
/// screen on "connecting" for ever when a dial failed: the state was written
/// once and only an event could clear it, and the failing path had no event.
/// A `std::sync` mutex, held for a hash lookup and never across an await.
///
/// The value is why, in one line — M12: a failure the user cannot read the
/// cause of is a failure they cannot fix.
type Failed = Arc<Mutex<HashMap<UserId, String>>>;

/// Starts the node and runs the TUI on *this* thread.
///
/// The runtime's worker threads are somewhere else. This one does nothing but
/// draw and read keys, which is what F-21 asks for: `crossterm`'s reader
/// blocks, and a blocking read on a runtime thread starves everything sharing
/// it.
pub fn run(config: Config) -> Result<()> {
    // Piped or redirected, there is no screen to draw and nothing to read
    // keys from. Exiting quietly would make the binary look broken — it is
    // the no-argument invocation, so it is also what someone gets by running
    // `p2pchat` in the wrong place. agent.md §2: a fatal startup error, before
    // the TUI owns the terminal, is the one thing that goes to stderr.
    if !std::io::stdout().is_terminal() {
        tracing::warn!("stdout is not a terminal; there is nothing to draw on");
        bail!("a terminal is required: stdout is not a tty; see p2pchat --help");
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // The node itself is kept alive by the tasks `start` spawned; the gates
    // are what want the handle.
    let (mut core, mut notices, _node) = runtime.block_on(start(config))?;
    p2pchat_tui::run(&mut core, &mut notices)?;
    Ok(())
}

/// Everything that has to happen inside the runtime before the screen exists.
///
/// Public so a test can stand where `run` stands: `p2pchat_tui::run` is a
/// keystroke loop over a [`Core`], and everything it can reach is on the other
/// side of what this returns. A gate below this line drives a different
/// program from the one the user runs.
pub async fn start(config: Config) -> Result<(Channel, mpsc::Receiver<Notice>, Arc<Node>)> {
    let (node, events) = Node::start(config).await?;

    let (requests, inbox) = mpsc::channel(REQUESTS);
    let (notices, screen) = mpsc::channel(NOTICES);
    let failed: Failed = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(serve(
        Arc::clone(&node),
        inbox,
        notices.clone(),
        Arc::clone(&failed),
    ));
    tokio::spawn(bridge(events, notices, failed));

    Ok((
        Channel {
            me: node.me,
            requests,
        },
        screen,
        node,
    ))
}

// ---------------------------------------------------------------------------
// TUI → core
// ---------------------------------------------------------------------------

/// The TUI's view of the node: a channel, and the blocking calls around it.
pub struct Channel {
    /// Fixed for the life of the process, so it is not worth a round trip.
    me: UserId,
    requests: mpsc::Sender<Request>,
}

impl Channel {
    /// Ask and wait. `fallback` is what the screen shows when the core has
    /// stopped answering — which happens once, while the process is exiting.
    fn ask<T>(&mut self, make: impl FnOnce(oneshot::Sender<T>) -> Request, fallback: T) -> T {
        let (reply, answer) = oneshot::channel();
        if self.requests.blocking_send(make(reply)).is_err() {
            return fallback;
        }
        answer.blocking_recv().unwrap_or(fallback)
    }

    /// Say, and carry on. The answer, when there is one, arrives as a
    /// [`Notice`].
    fn tell(&mut self, request: Request) {
        let _ = self.requests.blocking_send(request);
    }
}

impl Core for Channel {
    fn me(&mut self) -> UserId {
        self.me
    }

    fn conversations(&mut self) -> Vec<Conversation> {
        self.ask(Request::Conversations, Vec::new())
    }

    fn pending(&mut self) -> Vec<Pending> {
        self.ask(Request::Pending, Vec::new())
    }

    fn page(&mut self, peer: UserId, before: Option<Cursor>) -> Vec<Line> {
        self.ask(
            |reply| Request::Page {
                peer,
                before,
                reply,
            },
            Vec::new(),
        )
    }

    fn send(&mut self, peer: UserId, body: String) {
        self.tell(Request::Send { peer, body });
    }

    fn decide(&mut self, from: UserId, accept: bool) {
        self.tell(Request::Decide { from, accept });
    }

    fn verify(&mut self, peer: UserId) {
        self.tell(Request::Verify(peer));
    }

    fn import(&mut self, blob: &str) -> Result<Preview, String> {
        let blob = blob.to_owned();
        self.ask(
            |reply| Request::Import { blob, reply },
            Err("the node is not answering".to_owned()),
        )
    }

    fn connect(&mut self, peer: UserId) {
        self.tell(Request::Connect(peer));
    }
}

// ---------------------------------------------------------------------------
// core → TUI
// ---------------------------------------------------------------------------

/// Turns the node's events into notifications.
///
/// Every `try_send` here is deliberate, and so is every ignored error: §2's
/// rule is that the core does not wait for the screen.
async fn bridge(mut events: mpsc::Receiver<Event>, notices: mpsc::Sender<Notice>, failed: Failed) {
    while let Some(event) = events.recv().await {
        let notice = match event {
            // Not "the peer is connected" — `Node::sessions` is what says
            // that, and it is asked again on the redraw this notice provokes.
            // Only the failure is forgotten here, because it is over.
            Event::Connected { peer, .. } => {
                mark(&failed, peer, None);
                let _ = notices.try_send(Notice::Peers);
                Notice::Changed(peer)
            }
            Event::Closed { peer } => {
                let _ = notices.try_send(Notice::Peers);
                Notice::Changed(peer)
            }
            // F-25: the phase changed, so the peer list has to be read again.
            // What it changed to is in `Node::phases`, which `conversations`
            // asks on every question the screen puts.
            Event::Phase { .. } => Notice::Peers,
            Event::DialFailed { peer, reason } => {
                mark(&failed, peer, Some(reason));
                Notice::Peers
            }
            Event::Sent { peer, .. }
            | Event::Received { peer, .. }
            | Event::Delivered { peer, .. } => Notice::Changed(peer),
            Event::Requested { .. } => Notice::Requests,
        };
        let _ = notices.try_send(notice);
    }
}

fn mark(failed: &Failed, peer: UserId, why: Option<String>) {
    if let Ok(mut failed) = failed.lock() {
        match why {
            Some(why) => failed.insert(peer, why),
            None => failed.remove(&peer),
        };
    }
}

// ---------------------------------------------------------------------------
// Answering the screen
// ---------------------------------------------------------------------------

async fn serve(
    node: Arc<Node>,
    mut inbox: mpsc::Receiver<Request>,
    notices: mpsc::Sender<Notice>,
    failed: Failed,
) {
    // Where to dial a peer, learned from the invite the user pasted. An invite
    // is the only thing that carries an address; a peer that reached us
    // through the public node dials us back itself.
    let mut addrs: HashMap<UserId, Vec<SocketAddr>> = HashMap::new();

    while let Some(request) = inbox.recv().await {
        match request {
            Request::Conversations(reply) => {
                let _ = reply.send(conversations(&node, &failed).await);
            }
            Request::Pending(reply) => {
                let pending = node
                    .store
                    .pending_requests()
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|request| Pending {
                        from: request.from_user_id,
                        display_name: request.display_name,
                    })
                    .collect();
                let _ = reply.send(pending);
            }
            Request::Page {
                peer,
                before,
                reply,
            } => {
                let _ = reply.send(page(&node, peer, before).await);
            }
            Request::Send { peer, body } => {
                if let Err(error) = node.send(peer, body).await {
                    tracing::warn!(%peer, %error, "the message was not queued");
                }
                let _ = notices.try_send(Notice::Changed(peer));
            }
            Request::Decide { from, accept } => {
                match node.decide(from, accept).await {
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%from, %error, "the decision was not recorded"),
                }
                let _ = notices.try_send(Notice::Requests);
                let _ = notices.try_send(Notice::Peers);
            }
            Request::Verify(peer) => {
                if let Err(error) = node.store.set_verified(peer, true).await {
                    tracing::warn!(%peer, %error, "the peer was not marked verified");
                }
                let _ = notices.try_send(Notice::Peers);
            }
            Request::Import { blob, reply } => {
                let _ = reply.send(import(&node, &mut addrs, &blob, &notices).await);
            }
            // F-05: this arrives only after the fingerprint has been on the
            // screen — see `p2pchat_tui::App::overlay_key`.
            Request::Connect(peer) => {
                let Some(addr) = addrs.get(&peer).and_then(|addrs| addrs.first()).copied() else {
                    tracing::warn!(%peer, "no address for this peer; nothing to dial");
                    mark(
                        &failed,
                        peer,
                        Some("no address for this peer: paste their invite again".to_owned()),
                    );
                    let _ = notices.try_send(Notice::Peers);
                    continue;
                };

                // Nothing is written here to say "connecting" — M9e. The node
                // records the attempt before it sends anything, and
                // `Node::connecting` is what the column is read from.
                mark(&failed, peer, None);

                // Spawned: this takes seconds, and the screen's next question
                // must not queue behind it.
                let node = Arc::clone(&node);
                let failed = Arc::clone(&failed);
                let notices = notices.clone();
                tokio::spawn(async move {
                    // §10, M9d: the address in an invite is the *public*
                    // node's, so the way in is a connection request and not a
                    // dial. `request_connection` records our acceptance of the
                    // peer — reading a fingerprint and pressing Enter on it is
                    // the user accepting them — and keeps asking until they
                    // answer. We dial when they say yes.
                    if let Err(error) = node.request_connection(peer, addr).await {
                        tracing::warn!(%peer, ?error, "the connection request failed");
                        mark(&failed, peer, Some(format!("{error:#}")));
                    }
                    // Either way: the attempt has moved on, so re-read.
                    let _ = notices.try_send(Notice::Peers);
                    // The success case is the `Connected` event: one place
                    // decides what "connected" means, and it is the one both
                    // directions go through.
                });
            }
        }
    }
}

async fn conversations(node: &Node, failed: &Failed) -> Vec<Conversation> {
    let peers = node.store.peers().await.unwrap_or_default();
    // Both read afresh, on every question the screen asks. That is the whole
    // of M9e's fix: a notice is a reason to call this again, never the thing
    // that decides the answer, so a notice that is dropped — and `try_send`
    // drops them by design when the screen is behind — costs one late redraw.
    let live = node.sessions().await;
    let trying = node.connecting().await;
    // F-25's two missing states — M10. Read the same way and for the same
    // reason: a phase lasts exactly as long as the task that is in it.
    let phases = node.phases();
    let failed = failed.lock().ok();

    peers
        .into_iter()
        .map(|peer| {
            let failure = failed
                .as_ref()
                .and_then(|failed| failed.get(&peer.user_id).cloned());
            let state = if live.contains(&peer.user_id) {
                ConnState::Established
            } else if let Some(phase) = phases.get(&peer.user_id) {
                match phase {
                    Phase::Connecting => ConnState::Connecting,
                    Phase::Handshaking => ConnState::Handshaking,
                    Phase::Reconnecting => ConnState::Reconnecting,
                }
            // The failure before the stored request — M12c. The request now
            // outlives a failed dial so the poller can dial again, and ranked
            // above the failure it would hide the reason and put the screen
            // back on "connecting" for ever. A retry in progress still shows,
            // as its phase above; between retries the user reads why.
            } else if failure.is_some() {
                ConnState::Failed
            } else if trying.contains(&peer.user_id) {
                ConnState::Connecting
            } else {
                ConnState::Disconnected
            };
            Conversation {
                // Only while it is the state on screen: a reason beside
                // "connected" would be about an attempt that is over.
                failure: failure.filter(|_| state == ConnState::Failed),
                state,
                peer: peer.user_id,
                display_name: peer.display_name,
                verified: peer.verified,
            }
        })
        .collect()
}

/// One page, oldest first.
///
/// The store answers newest first, which is what a scrollback query wants and
/// not what a transcript reads like.
async fn page(node: &Node, peer: UserId, before: Option<Cursor>) -> Vec<Line> {
    let conversation_id = derive_conversation_id(&node.me, &peer);
    let before = before.map(|cursor| p2pchat_store::Cursor {
        msg_seq: cursor.msg_seq,
        message_id: cursor.message_id,
    });

    let mut page = match node.store.page(conversation_id, before).await {
        Ok(page) => page,
        Err(error) => {
            tracing::warn!(%peer, %error, "the page could not be read");
            return Vec::new();
        }
    };
    page.reverse();
    page.into_iter()
        .map(|message| Line {
            mine: message.sender_id == node.me,
            message_id: message.message_id,
            msg_seq: message.msg_seq,
            body: String::from_utf8_lossy(&message.body).into_owned(),
            status: message.status,
        })
        .collect()
}

/// F-05: parse, verify, remember — and do not connect.
async fn import(
    node: &Node,
    addrs: &mut HashMap<UserId, Vec<SocketAddr>>,
    blob: &str,
    notices: &mpsc::Sender<Notice>,
) -> Result<Preview, String> {
    let invite = invite::parse(blob.trim(), invite::now()).map_err(|error| error.to_string())?;
    let body = &invite.body;

    let now = crate::session::now_ms() / 1000;
    node.store
        .upsert_peer(Peer {
            user_id: body.user_id,
            identity_pk: body.identity_pk,
            display_name: Some(body.display_name.clone()),
            first_seen: now,
            last_seen: None,
            // Both are the user's to give, and the user has given neither: an
            // invite is a claim, not a decision.
            verified: false,
            accepted: false,
        })
        .await
        .map_err(|error| error.to_string())?;

    addrs.insert(body.user_id, body.addrs.clone());
    let _ = notices.try_send(Notice::Peers);

    Ok(Preview {
        peer: body.user_id,
        display_name: body.display_name.clone(),
        addrs: body.addrs.len(),
    })
}
