#![forbid(unsafe_code)]

mod dht;
mod logging;
mod paths;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use p2pchat::{Config, Event, Node};
use p2pchat_core::UserId;
use p2pchat_crypto::{derive_conversation_id, invite, keystore};
use p2pchat_store::{db_path, Store, PAGE_SIZE};
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(version, about = "Decentralized peer-to-peer terminal chat")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Listen port for the private node. Zero asks the OS.
    #[arg(long, default_value_t = 0)]
    private_port: u16,

    /// Listen port for the public node. Omitted, no public node runs, and
    /// nobody can send this node a connection request.
    #[arg(long)]
    public_port: Option<u16>,

    /// Advisory, carried in invites and requests. Nobody has to believe it.
    #[arg(long, default_value = "")]
    name: String,

    /// A public node address to advertise, repeatable, at most four. No
    /// default: this process cannot know which of its addresses is reachable
    /// from outside, so it is told — and without it there is nothing to put in
    /// an invite and nowhere to send an accepted requester.
    ///
    /// Global, and readable from `config.toml` as `addr`, so it need not be
    /// retyped every launch. `P2PCHAT_ADDR` overrides both, F-27.
    #[arg(long = "addr", global = true)]
    addrs: Vec<SocketAddr>,

    /// Where an accepted requester is told to dial this node privately — M9d.
    ///
    /// Defaults to `--addr`'s host with the private port, which is right
    /// whenever both endpoints live on the same host. Override it when they do
    /// not — a different forwarded port, say. `P2PCHAT_PRIVATE_ADDR` overrides
    /// this in turn, F-27.
    #[arg(long = "private-addr", global = true)]
    private_addr: Option<SocketAddr>,

    /// A public node to ask for a reachability dial-back, repeatable — M14.
    /// Asked in order until one answers. None, and the node never tests and
    /// counts itself a client. `bootstrap` in `config.toml`, and
    /// `P2PCHAT_BOOTSTRAP` overrides both, comma-separated.
    #[arg(long = "bootstrap", global = true)]
    bootstrap: Vec<SocketAddr>,

    /// The IP both endpoints bind to. Every interface by default, or no host
    /// but this one could reach the node. This is *not* what invites
    /// advertise — that is `--addr`, and nothing derives one from the other.
    /// `P2PCHAT_BIND_ADDR` overrides it, F-27.
    ///
    /// Global, so `p2pchat --bind` and `p2pchat node --bind` are the same flag
    /// rather than two that drift apart.
    #[arg(long, global = true, default_value_t = IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    bind: IpAddr,
}

#[derive(Subcommand)]
enum Command {
    /// Print this node's user ID and fingerprint.
    Whoami,

    /// Print a pasteable invite blob for this node — F-04.
    Invite {
        /// Display name to carry. Advisory only: whoever receives it must not
        /// trust it, and the fingerprint is what identifies you.
        #[arg(long, default_value = "")]
        name: String,
    },

    /// Run a node, reading commands from stdin and printing events to stdout.
    ///
    /// The debug driver until the TUI arrives in M9. It is deliberately
    /// line-oriented in both directions: a person can drive it by hand and a
    /// test can drive it through a pipe.
    Node {
        /// Listen port for the private node. Zero asks the OS, which is how
        /// two nodes share a machine.
        #[arg(long, default_value_t = 0)]
        private_port: u16,

        /// Listen port for the public node. Omitted, no public node runs.
        #[arg(long)]
        public_port: Option<u16>,

        #[arg(long, default_value = "")]
        name: String,
    },

    /// Bind both endpoints as a node would, print what they bound and what
    /// they advertise, and flag what cannot work — M12. Run it on the host
    /// before sharing an invite: a wrong address found here costs nothing,
    /// found by a peer it costs a timeout that looks like every other one.
    Check {
        /// As for `node`, and the same flags the chat is launched with.
        #[arg(long, default_value_t = 0)]
        private_port: u16,

        #[arg(long)]
        public_port: Option<u16>,
    },

    /// Print the stored conversation with a peer, oldest first.
    ///
    /// Reads the database directly, so it works on a node that is no longer
    /// running — which is the point.
    History {
        /// The peer's 64-character user ID.
        peer: String,
    },

    /// Query public STUN servers for this host's reflexive address and
    /// report whether its NAT can ever be hole-punched — M13.
    ///
    /// It asks from the private endpoint's own socket, bound exactly as a
    /// node binds it, so the mapping reported is the one QUIC traffic gets
    /// — M13a. That socket is the node's: stop a running node first.
    ///
    /// Read-only: nothing here is wired into dialling, invites, or `--addr`.
    /// M17 publishes the address a dial-back observed instead; the reflexive
    /// address is M18's.
    Nat {
        /// As for `node`, and the same flag the chat is launched with. Zero
        /// asks the OS, which reports on a port no later run will reuse.
        #[arg(long, default_value_t = 0)]
        private_port: u16,
    },

    /// Run a DHT node and nothing else, driven over stdin and stdout — M16.
    ///
    /// The simulation's driver (`netem/dht.py`), as `node` is the netem
    /// harness's. No store, no sessions, no reachability test: the harness
    /// says who is a member. `--bootstrap` is where lookups start.
    Dht {
        /// A client: holds no routing state, serves nothing.
        #[arg(long)]
        client: bool,

        #[arg(long, default_value_t = 0)]
        private_port: u16,

        /// A member's public node. Required unless `--client`.
        #[arg(long)]
        public_port: Option<u16>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Held until the process exits so the appender flushes.
    let _log_guard = logging::init().context("initialise logging")?;

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "p2pchat starting");

    let bind = bind_ip(cli.bind);
    let config_dir = paths::config_dir()?;
    let file = file_config(&config_dir);
    let advertise = addr_list(ADDR_ENV, cli.addrs, file.addr);
    let bootstrap = addr_list(BOOTSTRAP_ENV, cli.bootstrap, file.bootstrap);
    let private_advertise = private_advertise(cli.private_addr, file.private_addr);

    match cli.command {
        Some(Command::Whoami) => whoami(),
        Some(Command::Invite { name }) => print_invite(&name, advertise),
        Some(Command::Node {
            private_port,
            public_port,
            name,
        }) => runtime()?.block_on(run(
            bind,
            private_port,
            public_port,
            name,
            advertise,
            private_advertise,
            bootstrap,
        )),
        Some(Command::Check {
            private_port,
            public_port,
        }) => runtime()?.block_on(check(
            bind,
            private_port,
            public_port,
            &advertise,
            private_advertise,
        )),
        Some(Command::History { peer }) => runtime()?.block_on(history(&peer)),
        Some(Command::Nat { private_port }) => runtime()?.block_on(nat(bind, private_port)),
        Some(Command::Dht {
            client,
            private_port,
            public_port,
        }) => runtime()?.block_on(dht::run(
            bind,
            private_port,
            (!client).then_some(public_port).flatten(),
            client,
            advertise,
            bootstrap,
        )),
        // No subcommand: the chat itself — M9. The TUI runs on this thread
        // and the runtime is started underneath it, so `runtime()` is not
        // used here.
        None => p2pchat::ui::run(Config {
            config_dir,
            data_dir: paths::data_dir()?,
            private_bind: SocketAddr::new(bind, cli.private_port),
            public_bind: cli.public_port.map(|port| SocketAddr::new(bind, port)),
            advertise,
            private_advertise,
            display_name: cli.name,
            bootstrap,
        }),
    }
}

/// `config.toml` — F-27, M9d. Every value in it is also a flag and an
/// environment variable; it exists so that the addresses this host advertises
/// need not be retyped at every launch.
#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    /// `addr = ["203.0.113.4:47100"]`, the same list `--addr` builds.
    #[serde(default)]
    addr: Vec<SocketAddr>,
    #[serde(default)]
    private_addr: Option<SocketAddr>,
    /// `bootstrap = ["198.51.100.1:47100"]`, the list `--bootstrap` builds.
    #[serde(default)]
    bootstrap: Vec<SocketAddr>,
}

/// Reads `config.toml` from the config directory, or defaults.
///
/// A missing file is the ordinary case and says nothing. A malformed one is
/// logged and ignored rather than fatal, for the reason [`bind_ip`] gives: a
/// node that will not start because of a stale config file is worse than one
/// that starts with the flags it was given.
fn file_config(dir: &std::path::Path) -> FileConfig {
    let path = dir.join("config.toml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return FileConfig::default();
    };
    toml::from_str(&text).unwrap_or_else(|error| {
        tracing::warn!(path = %path.display(), %error, "config.toml is malformed and was ignored");
        FileConfig::default()
    })
}

/// F-27's `--addr` and `--private-addr`, in `techstack.md`.
const ADDR_ENV: &str = "P2PCHAT_ADDR";
const PRIVATE_ADDR_ENV: &str = "P2PCHAT_PRIVATE_ADDR";
const BOOTSTRAP_ENV: &str = "P2PCHAT_BOOTSTRAP";

/// Environment, then flag, then file — F-27: the override wins over both.
fn addr_list(env: &'static str, flag: Vec<SocketAddr>, file: Vec<SocketAddr>) -> Vec<SocketAddr> {
    if let Some(value) = env_var(env) {
        // Comma-separated, because one variable has to carry what a repeatable
        // flag carries. Any unparseable entry drops the whole override rather
        // than silently advertising a shorter list.
        match value.split(',').map(str::parse).collect() {
            Ok(addrs) => return addrs,
            Err(_) => tracing::warn!(env, "the override is not a list of addresses"),
        }
    }
    if !flag.is_empty() {
        return flag;
    }
    file
}

fn private_advertise(flag: Option<SocketAddr>, file: Option<SocketAddr>) -> Option<SocketAddr> {
    if let Some(value) = env_var(PRIVATE_ADDR_ENV) {
        match value.parse() {
            Ok(addr) => return Some(addr),
            Err(_) => tracing::warn!(env = PRIVATE_ADDR_ENV, "the override is not an address"),
        }
    }
    flag.or(file)
}

/// An environment variable that is set to something. Empty is treated as
/// unset, so `P2PCHAT_ADDR=` in a shell does not mean "advertise nothing".
fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Built here rather than with `#[tokio::main]` so that `whoami` and `invite`
/// stay what they were: two synchronous functions that do not start a runtime.
fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

// ---------------------------------------------------------------------------
// The debug node
// ---------------------------------------------------------------------------

/// Everything this prints is tab-separated and one record per line: `ready`
/// once, then `event` and `ok`/`err` lines as they happen.
///
/// stdout here carries full user IDs and message bodies. That is the opposite
/// of what the *log* may hold (agent.md §2), and it is the point of a debug
/// driver: the operator asked for it and nothing else is reading the pipe.
async fn run(
    bind: IpAddr,
    private_port: u16,
    public_port: Option<u16>,
    name: String,
    addrs: Vec<SocketAddr>,
    private_advertise: Option<SocketAddr>,
    bootstrap: Vec<SocketAddr>,
) -> Result<()> {
    let (node, mut events) = Node::start(Config {
        config_dir: paths::config_dir()?,
        data_dir: paths::data_dir()?,
        private_bind: SocketAddr::new(bind, private_port),
        public_bind: public_port.map(|port| SocketAddr::new(bind, port)),
        advertise: addrs,
        private_advertise,
        display_name: name,
        bootstrap,
    })
    .await?;

    // The fourth field is what an accepted requester is told to dial — M9d.
    // `-` for a node that has none, which is a node that cannot accept.
    println!(
        "ready\t{}\t{}\t{}\t{}",
        node.me.to_hex(),
        node.private_addr()?,
        node.public_addr()
            .map_or_else(|| "-".to_owned(), |addr| addr.to_string()),
        node.private_advertise()
            .map_or_else(|| "-".to_owned(), |addr| addr.to_string())
    );

    // stdin is blocking and there is no async reader for it without another
    // tokio feature. One thread, one channel.
    let (lines, mut commands) = mpsc::channel::<String>(16);
    std::thread::spawn(move || {
        for line in std::io::stdin().lines() {
            match line {
                Ok(line) => {
                    if lines.blocking_send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    loop {
        tokio::select! {
            Some(event) = events.recv() => report(&event),
            line = commands.recv() => match line {
                Some(line) => if !command(&node, line.trim()).await {
                    break;
                },
                // stdin closed: so is the session.
                None => break,
            },
        }
    }

    Ok(())
}

/// F-27's environment override for `--bind` — listed in `techstack.md`.
const BIND_ADDR_ENV: &str = "P2PCHAT_BIND_ADDR";

/// The IP the endpoints bind to: the environment override if it parses, the
/// flag otherwise.
///
/// The environment wins over the flag, as F-27 requires of every config value,
/// and an unparseable override is reported and ignored rather than being a
/// startup failure — the same shape as `NodeKind::port`.
fn bind_ip(flag: IpAddr) -> IpAddr {
    match std::env::var(BIND_ADDR_ENV) {
        Ok(value) => value.parse().unwrap_or_else(|_| {
            tracing::warn!(
                env = BIND_ADDR_ENV,
                "bind address override is not an IP address"
            );
            flag
        }),
        Err(_) => flag,
    }
}

fn report(event: &Event) {
    match event {
        Event::Connected { peer, initiator } => {
            println!("event\tsession\t{}\t{}", peer.to_hex(), initiator.to_hex())
        }
        Event::Sent {
            message_id,
            msg_seq,
            ..
        } => println!("event\tsent\t{message_id}\t{}", msg_seq.get()),
        Event::Received {
            peer,
            message_id,
            msg_seq,
            body,
        } => println!(
            "event\trecv\t{}\t{message_id}\t{}\t{body}",
            peer.to_hex(),
            msg_seq.get()
        ),
        Event::Delivered {
            message_id, status, ..
        } => println!("event\tdelivered\t{message_id}\t{status:?}"),
        Event::Closed { peer } => println!("event\tclosed\t{}", peer.to_hex()),
        Event::Phase { peer } => println!("event\tphase\t{}", peer.to_hex()),
        Event::DialFailed { peer, reason } => {
            println!("event\tdial-failed\t{}\t{reason}", peer.to_hex())
        }
        Event::Requested {
            from,
            display_name,
            state,
        } => println!(
            "event\trequest\t{}\t{state:?}\t{display_name}",
            from.to_hex()
        ),
    }
}

/// Runs one line. `false` means stop.
async fn command(node: &std::sync::Arc<Node>, line: &str) -> bool {
    let (verb, rest) = match line.split_once(char::is_whitespace) {
        Some((verb, rest)) => (verb, rest.trim()),
        None => (line, ""),
    };

    if verb.is_empty() {
        return true;
    }
    if verb == "quit" {
        return false;
    }

    match run_command(node, verb, rest).await {
        Ok(answer) => println!("ok\t{verb}\t{answer}"),
        Err(error) => println!("err\t{verb}\t{error}"),
    }
    true
}

async fn run_command(node: &std::sync::Arc<Node>, verb: &str, rest: &str) -> Result<String> {
    Ok(match verb {
        // `connect <addr> [<user-id>]` — the user ID is the one from the
        // invite, and passing it is what makes the handshake check who
        // answered.
        // `connect <user-id>` alone: look the peer up in the DHT and dial
        // what its record says — M17.
        "connect" if rest.len() == 64 && !rest.contains(':') => {
            node.connect(user_id(rest)?).await?.to_hex()
        }
        "connect" => {
            let (addr, expected) = match rest.split_once(char::is_whitespace) {
                Some((addr, peer)) => (addr, Some(user_id(peer.trim())?)),
                None => (rest, None),
            };
            let peer = node
                .dial(addr.parse().context("not an address")?, expected)
                .await?;
            peer.to_hex()
        }
        "send" => {
            let (peer, body) = rest
                .split_once(char::is_whitespace)
                .context("send <user-id> <text>")?;
            node.send(user_id(peer)?, body.to_owned()).await?;
            "queued".to_owned()
        }
        // `request <addr> <user-id>` — both come from the same invite. The
        // user ID is not optional: it is who the request is *for*, and the
        // peer this node will dial when the answer comes back accepted (M9d).
        "request" => {
            let (addr, peer) = rest
                .split_once(char::is_whitespace)
                .context("request <addr> <user-id>")?;
            format!(
                "{:?}",
                node.request_connection(user_id(peer)?, addr.parse().context("not an address")?)
                    .await?
            )
        }
        "requests" => {
            let pending = node.store.pending_requests().await?;
            let mut out = format!("{} pending", pending.len());
            for request in pending {
                out.push_str(&format!(
                    "\n{}\t{}",
                    request.from_user_id.to_hex(),
                    request.display_name
                ));
            }
            out
        }
        // The user's decision about a *peer* — architecture.md §10. It resolves
        // a queued request when there is one, and stands on its own when there
        // is not: a peer whose invite was pasted never queued anything, and it
        // still has to be accepted before either side will hold a session.
        "accept" | "reject" => {
            let resolved = node.decide(user_id(rest)?, verb == "accept").await?;
            format!(
                "{rest}\t{}",
                if resolved {
                    "request resolved"
                } else {
                    "no request was pending"
                }
            )
        }
        "peers" => {
            let peers = node.store.peers().await?;
            let mut out = format!("{} peers", peers.len());
            for peer in peers {
                out.push_str(&format!(
                    "\n{}\t{}\t{}\t{}",
                    peer.user_id.to_hex(),
                    peer.user_id,
                    if peer.verified {
                        "verified"
                    } else {
                        "unverified"
                    },
                    if peer.accepted {
                        "accepted"
                    } else {
                        "unaccepted"
                    }
                ));
            }
            out
        }
        // F-09: the user compared the fingerprint out of band.
        "verify" => {
            if !node.store.set_verified(user_id(rest)?, true).await? {
                bail!("no such peer");
            }
            rest.to_owned()
        }
        "sessions" => format!("{}", node.session_count().await),
        // M14a: one dial-back through the member at `<addr>`, as
        // `forwarded <bool> reached <bool> arrived <addr|->`. For measuring;
        // changes no role.
        "dialback" => match node
            .dial_back_once(rest.parse().context("dialback <member-addr>")?)
            .await
        {
            Some(answer) => format!(
                "forwarded\t{}\treached\t{}\tarrived\t{}",
                answer.forwarded,
                answer.reached,
                answer
                    .arrived
                    .map_or_else(|| "-".to_owned(), |addr| addr.to_string())
            ),
            None => bail!("the member did not answer"),
        },
        // M14: `member <addr>` or `client`.
        "role" => match node.role() {
            p2pchat::Role::Member(addr) => format!("member\t{addr}"),
            p2pchat::Role::Client => "client".to_owned(),
        },
        other => bail!("unknown command {other}"),
    })
}

/// 64 hex characters. Not `UserId::from_str`: a user ID has exactly one text
/// form in this project, and it is produced by `to_hex`.
pub(crate) fn user_id(text: &str) -> Result<UserId> {
    let text = text.trim();
    if text.len() != 64 {
        bail!("a user id is 64 hex characters");
    }

    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .context("a user id is hexadecimal")?;
    }
    Ok(UserId::from_bytes(bytes))
}

/// `msg_seq  status  sender  message_id  body`, oldest first.
async fn history(peer: &str) -> Result<()> {
    let identity = keystore::load(&keystore::key_path(&paths::config_dir()?))?;
    let peer = user_id(peer)?;
    let conversation_id = derive_conversation_id(&identity.user_id(), &peer);

    let store = Store::open(db_path(&paths::data_dir()?)).await?;
    let mut cursor = None;
    let mut rows = Vec::new();
    loop {
        let page = store.page(conversation_id, cursor).await?;
        let full = page.len() == PAGE_SIZE;
        cursor = page.last().map(|message| message.cursor());
        rows.extend(page);
        if !full {
            break;
        }
    }

    // `page` is newest first, which is what scrollback wants and not what
    // reading a transcript wants.
    rows.reverse();
    for message in rows {
        println!(
            "{}\t{:?}\t{}\t{}\t{}",
            message.msg_seq.get(),
            message.status,
            message.sender_id.to_hex(),
            message.message_id,
            String::from_utf8_lossy(&message.body)
        );
    }

    store.close().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Self-check
// ---------------------------------------------------------------------------

/// `p2pchat check` — M12. Binds the endpoints and nothing else: no store, no
/// dialling, no polling, so it can run beside a stopped node without touching
/// its state. What it cannot see is whether the outside can reach this host;
/// it says so rather than implying a clean run means a reachable node.
async fn check(
    bind: IpAddr,
    private_port: u16,
    public_port: Option<u16>,
    advertise: &[SocketAddr],
    private_advertise: Option<SocketAddr>,
) -> Result<()> {
    use p2pchat_net::{server_endpoint, NodeKind};

    let private = server_endpoint(SocketAddr::new(bind, private_port), NodeKind::Private)
        .with_context(|| {
            format!("bind the private endpoint on UDP {private_port}: is a node already running?")
        })?
        .local_addr()?;
    let public = match public_port {
        Some(port) => Some(
            server_endpoint(SocketAddr::new(bind, port), NodeKind::Public)
                .with_context(|| {
                    format!("bind the public endpoint on UDP {port}: is a node already running?")
                })?
                .local_addr()?,
        ),
        None => None,
    };
    let dial_back =
        p2pchat::node::derive_private_advertise(private_advertise, advertise, private.port());

    let list = |addrs: &[SocketAddr]| {
        if addrs.is_empty() {
            "-".to_owned()
        } else {
            addrs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    println!(
        "private  bound {private}  advertised {}",
        list(&dial_back.into_iter().collect::<Vec<_>>())
    );
    match public {
        Some(public) => println!("public   bound {public}  advertised {}", list(advertise)),
        None => println!("public   none  advertised {}", list(advertise)),
    }

    let mut problems = Vec::new();
    for addr in advertise.iter().chain(&dial_back) {
        if let Some(why) = unroutable(addr.ip()) {
            problems.push(format!("{addr} is {why}: nobody outside can dial it"));
        }
    }
    match public {
        Some(public) => {
            for addr in advertise.iter().filter(|addr| addr.port() != public.port()) {
                problems.push(format!(
                    "{addr} advertises port {} but the public endpoint is on {} - \
                     right only if a router forwards one to the other",
                    addr.port(),
                    public.port()
                ));
            }
        }
        None if !advertise.is_empty() => problems.push(
            "--addr is set but --public-port is not: the invite points at an endpoint that \
             does not exist"
                .to_owned(),
        ),
        None => println!(
            "note     no --addr and no --public-port: this node can send requests and \
             nobody can send it one"
        ),
    }
    if private_port == 0 && !advertise.is_empty() && private_advertise.is_none() {
        problems.push(format!(
            "--private-port is 0, so the OS chose {} and it changes every launch: pick one \
             (47101) so a firewall rule can name it",
            private.port()
        ));
    }
    if let Some(explicit) = private_advertise {
        if explicit.port() != private.port() {
            println!(
                "note     --private-addr {explicit} differs from the bound port {}: right only \
                 if a router forwards one to the other",
                private.port()
            );
        }
    }

    let mut ports = Vec::from_iter(public.map(|public| public.port()));
    ports.push(private.port());
    println!(
        "open     inbound {} on this host's firewall and the cloud security group - UDP, \
         not TCP: QUIC is UDP and a TCP rule does nothing",
        ports
            .iter()
            .map(|port| format!("UDP {port}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "note     this checks only this host. Whether those addresses reach it from outside \
         can only be seen from outside: have a peer connect, and if they get \"no answer\", \
         read what it says to check"
    );

    for problem in &problems {
        println!("problem  {problem}");
    }
    if !problems.is_empty() {
        bail!("{} problem(s) above", problems.len());
    }
    Ok(())
}

/// Why nobody on the internet can dial `ip`, or `None` if they might.
/// `None` is not "reachable": a public IP can still sit behind a closed port.
fn unroutable(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            if v4.is_unspecified() {
                Some("the unspecified address, which is a bind address and not a destination")
            } else if v4.is_loopback() {
                Some("loopback")
            } else if v4.is_private() {
                Some("a private LAN address (RFC 1918) - advertise the public IP instead")
            } else if v4.is_link_local() {
                Some("link-local")
            } else if a == 100 && (b & 0xC0) == 64 {
                // 100.64.0.0/10, RFC 6598.
                Some("carrier-grade NAT space (100.64/10): this host is behind CGNAT")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            if v6.is_unspecified() {
                Some("the unspecified address, which is a bind address and not a destination")
            } else if v6.is_loopback() {
                Some("loopback")
            } else if first & 0xfe00 == 0xfc00 {
                Some("a unique local address (fc00::/7)")
            } else if first & 0xffc0 == 0xfe80 {
                Some("link-local")
            } else {
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// NAT discovery — M13
// ---------------------------------------------------------------------------

/// `p2pchat nat` — M13, M13a. Read-only, like `check`: it binds the private
/// endpoint as a node would, asks each of `stun::DEFAULT_SERVERS` for that
/// socket's reflexive address, and reports what they agree or disagree on.
/// Nothing it learns is used anywhere else in this process.
async fn nat(bind: IpAddr, private_port: u16) -> Result<()> {
    use p2pchat_net::{node_endpoint, NodeKind};

    // `endpoint` lives to the end of the function: dropping it would close
    // the socket `socket` sends on.
    let (endpoint, socket) = node_endpoint(SocketAddr::new(bind, private_port), NodeKind::Private)
        .with_context(|| {
            format!("bind the private endpoint on UDP {private_port}: is a node already running?")
        })?;
    println!("socket     {}", endpoint.local_addr()?);

    let mut servers = Vec::new();
    for &(label, host) in p2pchat_net::stun::DEFAULT_SERVERS {
        match tokio::net::lookup_host(host).await {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => servers.push((label, addr)),
                None => println!("{label:<10} {host:<28} no DNS answer"),
            },
            Err(error) => println!("{label:<10} {host:<28} DNS lookup failed: {error}"),
        }
    }

    let report =
        p2pchat_net::stun::discover(&socket, &servers, p2pchat_net::stun::SERVER_TIMEOUT).await;

    for probe in &report.probes {
        match &probe.result {
            Ok(addr) => println!("{:<10} {:<28} reflexive {addr}", probe.label, probe.server),
            Err(error) => println!(
                "{:<10} {:<28} no answer: {error}",
                probe.label, probe.server
            ),
        }
    }

    use p2pchat_net::stun::Mapping;
    let (mapping, punchable) = match report.mapping {
        Mapping::EndpointIndependent => ("endpoint-independent", true),
        Mapping::AddressOrPortDependent => (
            "address- or port-dependent (symmetric) - no relay means this can never be punched",
            false,
        ),
        Mapping::Unknown => (
            "unknown - fewer than two independent servers agreed, so this is not a guess",
            false,
        ),
    };
    println!("mapping    {mapping}");
    println!("punchable  {}", if punchable { "yes" } else { "no" });
    if report.no_nat == Some(true) {
        println!("note       the reflexive address matches a local address: no NAT on this path");
    }
    if let Some(note) = container_note(report.mapping, container()) {
        println!("note       {note}");
    }

    Ok(())
}

/// The container runtime this process is inside, if it can tell — M13b.
///
/// Each marker is one the runtime itself creates: Docker writes `/.dockerenv`,
/// Podman `/run/.containerenv`, and systemd-nspawn, LXC and Podman set
/// `container` in PID 1's environment, which a process started by `exec`
/// usually inherits. Not finding one proves nothing, so [`container_note`]
/// still names the case.
fn container() -> Option<String> {
    if std::path::Path::new("/.dockerenv").exists() {
        return Some("Docker".to_owned());
    }
    if std::path::Path::new("/run/.containerenv").exists() {
        return Some("Podman".to_owned());
    }
    env_var("container")
}

/// What to say about a symmetric result that may be the container's NAT
/// rather than the network's — M13b.
///
/// Docker's bridge network (and Docker Desktop's VM under it) gives a
/// container a different outside port per destination. Inside one, every
/// network classifies as symmetric, and the result says nothing about the
/// carrier. Someone will run this in Docker and conclude their carrier is
/// symmetric, so the line says which NAT was measured.
fn container_note(
    mapping: p2pchat_net::stun::Mapping,
    container: Option<String>,
) -> Option<String> {
    if mapping != p2pchat_net::stun::Mapping::AddressOrPortDependent {
        return None;
    }
    Some(match container {
        Some(runtime) => format!(
            "this is running inside a {runtime} container, so the NAT measured is the \
             container's own, which is symmetric whatever the network beyond it is. Run \
             `p2pchat nat` on the host itself to classify the network (`--network host` \
             does that only on a Linux host: Docker Desktop's host is a NATed VM)"
        ),
        None => "if this is running in a container or VM with NAT networking (Docker's default \
                 bridge, Docker Desktop, WSL2's NAT mode), that NAT is the likely cause: it is \
                 symmetric whatever the network beyond it is. Run `p2pchat nat` on the host \
                 itself to classify the network"
            .to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// F-28: one line on stdout and nothing else, so `p2pchat invite | xclip`
/// works. Everything that is not the blob goes to the log.
fn print_invite(name: &str, addrs: Vec<SocketAddr>) -> Result<()> {
    let identity = keystore::load_or_create(&keystore::key_path(&paths::config_dir()?))?;
    let invite =
        invite::create(&identity, name, addrs, invite::now()).context("build the invite")?;

    tracing::info!(user = %identity.user_id(), "invite generated");
    println!("{}", invite::encode(&invite).context("encode the invite")?);

    Ok(())
}

/// The one place allowed to write to stdout: a CLI subcommand whose entire
/// purpose is to print a value the user has to read and compare. The TUI is not
/// running, so there is no display to corrupt.
fn whoami() -> Result<()> {
    let path = keystore::key_path(&paths::config_dir()?);
    let identity = keystore::load_or_create(&path)?;

    tracing::info!(user = %identity.user_id(), "loaded identity");

    println!("user id     {}", identity.user_id().to_hex());
    println!("fingerprint {}", identity.user_id());

    if !keystore::PERMISSIONS_ENFORCED {
        tracing::warn!(
            path = %path.display(),
            "key file permissions are not verified on this platform"
        );
        println!(
            "warning     key file permissions are not verified on this platform; \
             {} is protected only by the account it lives under",
            path.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2pchat_net::stun::Mapping;

    /// M13b: a symmetric result from inside a detected container names the
    /// container, and one from anywhere else still names containers as the
    /// likely cause. Neither is said about a result that is not symmetric.
    #[test]
    fn a_symmetric_result_names_the_container_nat() {
        let inside = container_note(Mapping::AddressOrPortDependent, Some("Docker".to_owned()))
            .expect("a symmetric result is qualified");
        assert!(inside.contains("inside a Docker container"), "{inside}");
        assert!(inside.contains("on the host"), "{inside}");

        let unknown = container_note(Mapping::AddressOrPortDependent, None)
            .expect("a symmetric result is qualified even with no container found");
        assert!(unknown.contains("Docker"), "{unknown}");
        assert!(unknown.contains("likely cause"), "{unknown}");

        for mapping in [Mapping::EndpointIndependent, Mapping::Unknown] {
            assert_eq!(container_note(mapping, Some("Docker".to_owned())), None);
        }
    }
}
