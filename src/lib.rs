//! pq-mtls-cost: banco de handshakes mTLS (TLS 1.3, certificados ECDSA P-256 en
//! ambos lados) que compara el intercambio de claves X25519 contra el híbrido
//! X25519MLKEM768 usando rustls + aws-lc-rs.
//!
//! Todo corre sobre TCP real en 127.0.0.1 para que `tc qdisc ... netem` sobre
//! `lo` afecte a las mediciones.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::client::Resumption;
use rustls::crypto::aws_lc_rs::{self as provider, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::{ClientConfig, ClientConnection, HandshakeKind, RootCertStore, ServerConfig, ServerConnection};
use serde::Serialize;

/// Grupo de intercambio de claves que ofrece el cliente (uno solo, para que no
/// haya HelloRetryRequest y la comparación sea limpia).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Group {
    #[serde(rename = "X25519")]
    X25519,
    #[serde(rename = "X25519MLKEM768")]
    X25519MlKem768,
}

impl Group {
    pub fn kx(self) -> &'static dyn SupportedKxGroup {
        match self {
            Group::X25519 => kx_group::X25519,
            Group::X25519MlKem768 => kx_group::X25519MLKEM768,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Group::X25519 => "X25519",
            Group::X25519MlKem768 => "X25519MLKEM768",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "x25519" => Some(Group::X25519),
            "x25519mlkem768" | "mlkem" | "hybrid" => Some(Group::X25519MlKem768),
            _ => None,
        }
    }
}

/// PKI efímera: una CA ECDSA P-256 que firma el certificado del servidor y el
/// del cliente, más una CA "ajena" que firma un cliente que debe ser rechazado.
pub struct Pki {
    pub ca: CertificateDer<'static>,
    pub server_chain: Vec<CertificateDer<'static>>,
    pub server_key: Vec<u8>,
    pub client_chain: Vec<CertificateDer<'static>>,
    pub client_key: Vec<u8>,
    pub rogue_client_chain: Vec<CertificateDer<'static>>,
    pub rogue_client_key: Vec<u8>,
}

fn ca(cn: &str) -> (CertificateParams, KeyPair, CertificateDer<'static>) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("keygen CA");
    let mut p = CertificateParams::new(Vec::<String>::new()).expect("params CA");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, cn);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = p.self_signed(&key).expect("self-sign CA");
    (p, key, cert.der().clone())
}

fn leaf(
    issuer: &Issuer<'_, &KeyPair>,
    cn: &str,
    sans: Vec<String>,
    eku: ExtendedKeyUsagePurpose,
) -> (CertificateDer<'static>, Vec<u8>) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("keygen leaf");
    let mut p = CertificateParams::new(sans).expect("params leaf");
    p.distinguished_name.push(DnType::CommonName, cn);
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![eku];
    let cert = p.signed_by(&key, issuer).expect("sign leaf");
    (cert.der().clone(), key.serialize_der())
}

impl Pki {
    pub fn generate() -> Self {
        let (ca_params, ca_key, ca_der) = ca("pq-mtls-cost CA");
        let issuer = Issuer::from_params(&ca_params, &ca_key);
        let (srv, srv_key) = leaf(
            &issuer,
            "localhost",
            vec!["localhost".into()],
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let (cli, cli_key) = leaf(
            &issuer,
            "client.service",
            vec!["client.service".into()],
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let (rogue_params, rogue_key, _rogue_ca) = ca("otra CA");
        let rogue_issuer = Issuer::from_params(&rogue_params, &rogue_key);
        let (rcli, rcli_key) = leaf(
            &rogue_issuer,
            "intruso.service",
            vec!["intruso.service".into()],
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        Pki {
            server_chain: vec![srv, ca_der.clone()],
            client_chain: vec![cli, ca_der.clone()],
            rogue_client_chain: vec![rcli],
            ca: ca_der,
            server_key: srv_key,
            client_key: cli_key,
            rogue_client_key: rcli_key,
        }
    }

    fn roots(&self) -> RootCertStore {
        let mut r = RootCertStore::empty();
        r.add(self.ca.clone()).expect("add CA");
        r
    }
}

fn key(der: &[u8]) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec()))
}

/// Proveedor aws-lc-rs con los grupos dados.
pub fn provider_with(groups: Vec<&'static dyn SupportedKxGroup>) -> Arc<CryptoProvider> {
    let mut p = provider::default_provider();
    p.kx_groups = groups;
    Arc::new(p)
}

/// Servidor: acepta ambos grupos, exige certificado de cliente de la CA propia.
pub fn server_config(pki: &Pki, resumption: bool) -> Arc<ServerConfig> {
    let prov = provider_with(vec![kx_group::X25519MLKEM768, kx_group::X25519]);
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(pki.roots()), prov.clone())
        .build()
        .expect("client verifier");
    let mut cfg = ServerConfig::builder_with_provider(prov)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .with_client_cert_verifier(verifier)
        .with_single_cert(pki.server_chain.clone(), key(&pki.server_key))
        .expect("server cert");
    if resumption {
        cfg.send_tls13_tickets = 1;
    } else {
        cfg.send_tls13_tickets = 0;
        cfg.session_storage = Arc::new(NoServerSessionStorage {});
    }
    Arc::new(cfg)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientIdentity {
    Valid,
    Rogue,
    None,
}

/// Cliente: ofrece un único grupo y presenta (o no) certificado.
pub fn client_config(pki: &Pki, group: Group, resumption: bool, id: ClientIdentity) -> Arc<ClientConfig> {
    let prov = provider_with(vec![group.kx()]);
    let b = ClientConfig::builder_with_provider(prov)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .with_root_certificates(pki.roots());
    let mut cfg = match id {
        ClientIdentity::Valid => b
            .with_client_auth_cert(pki.client_chain.clone(), key(&pki.client_key))
            .expect("client cert"),
        ClientIdentity::Rogue => b
            .with_client_auth_cert(pki.rogue_client_chain.clone(), key(&pki.rogue_client_key))
            .expect("rogue cert"),
        ClientIdentity::None => b.with_no_client_auth(),
    };
    cfg.resumption = if resumption {
        Resumption::in_memory_sessions(64)
    } else {
        Resumption::disabled()
    };
    Arc::new(cfg)
}

/// Bytes del primer vuelo del cliente (registro(s) TLS con el ClientHello),
/// tal como se escribirían al socket.
pub fn client_hello_bytes(cfg: Arc<ClientConfig>) -> usize {
    let name = ServerName::try_from("localhost").unwrap();
    let mut c = ClientConnection::new(cfg, name).expect("client conn");
    let mut out = Vec::new();
    while c.wants_write() {
        c.write_tls(&mut out).expect("write_tls");
    }
    out.len()
}

/// CPU (user+sys) consumida por el hilo actual, en microsegundos.
pub fn thread_cpu_us() -> u64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // RUSAGE_THREAD es específico de Linux.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut ru) };
    assert_eq!(rc, 0, "getrusage(RUSAGE_THREAD) falló");
    let tv = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
    tv(ru.ru_utime) + tv(ru.ru_stime)
}

/// TcpStream que cuenta bytes leídos y escritos.
pub struct Counting<S> {
    pub inner: S,
    pub rd: u64,
    pub wr: u64,
}
impl<S: Read> Read for Counting<S> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(b)?;
        self.rd += n as u64;
        Ok(n)
    }
}
impl<S: Write> Write for Counting<S> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(b)?;
        self.wr += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Servidor de eco de 1 byte, un hilo por conexión. Acumula CPU de los hilos
/// de conexión y cuenta handshakes completos/fallidos.
pub struct Server {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    pub cpu_us: Arc<AtomicU64>,
    pub ok: Arc<AtomicU64>,
    pub failed: Arc<AtomicU64>,
    handle: Option<JoinHandle<()>>,
}

impl Server {
    pub fn start(cfg: Arc<ServerConfig>) -> Server {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = l.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let cpu_us = Arc::new(AtomicU64::new(0));
        let ok = Arc::new(AtomicU64::new(0));
        let failed = Arc::new(AtomicU64::new(0));
        let (s2, c2, o2, f2) = (stop.clone(), cpu_us.clone(), ok.clone(), failed.clone());
        let handle = std::thread::spawn(move || {
            for conn in l.incoming() {
                if s2.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(tcp) = conn else { continue };
                let (cfg, c3, o3, f3) = (cfg.clone(), c2.clone(), o2.clone(), f2.clone());
                std::thread::spawn(move || {
                    let t0 = thread_cpu_us();
                    let r = serve_one(cfg, tcp);
                    c3.fetch_add(thread_cpu_us() - t0, Ordering::SeqCst);
                    match r {
                        Ok(()) => o3.fetch_add(1, Ordering::SeqCst),
                        Err(_) => f3.fetch_add(1, Ordering::SeqCst),
                    };
                });
            }
        });
        Server { addr, stop, cpu_us, ok, failed, handle: Some(handle) }
    }

    /// Espera a que el servidor haya contabilizado `n` conexiones.
    pub fn wait_for(&self, n: u64) {
        let t = Instant::now();
        while self.ok.load(Ordering::SeqCst) + self.failed.load(Ordering::SeqCst) < n {
            assert!(t.elapsed() < Duration::from_secs(30), "servidor no terminó {n} conexiones");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn serve_one(cfg: Arc<ServerConfig>, tcp: TcpStream) -> io::Result<()> {
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    let conn = ServerConnection::new(cfg).map_err(io::Error::other)?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let mut b = [0u8; 1];
    tls.read_exact(&mut b)?;
    tls.write_all(&b)?;
    tls.conn.send_close_notify();
    tls.flush()?;
    Ok(())
}

/// Resultado de un handshake del lado del cliente.
#[derive(Debug, Clone)]
pub struct Handshake {
    pub latency_ns: u64,
    pub resumed: bool,
    pub group: Option<&'static str>,
    pub bytes_c2s: u64,
    pub bytes_s2c: u64,
}

/// Un handshake mTLS completo: TCP connect + TLS 1.3 + eco de 1 byte (el byte
/// vuelve solo si el servidor ya validó el certificado del cliente).
pub fn one_handshake(cfg: Arc<ClientConfig>, addr: SocketAddr) -> io::Result<Handshake> {
    let t = Instant::now();
    let tcp = TcpStream::connect(addr)?;
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    let name = ServerName::try_from("localhost").unwrap();
    let conn = ClientConnection::new(cfg, name).map_err(io::Error::other)?;
    let mut tls = rustls::StreamOwned::new(conn, Counting { inner: tcp, rd: 0, wr: 0 });
    tls.write_all(b"x")?;
    let mut b = [0u8; 1];
    tls.read_exact(&mut b)?;
    let latency_ns = t.elapsed().as_nanos() as u64;
    if &b != b"x" {
        return Err(io::Error::other("eco incorrecto"));
    }
    let resumed = tls.conn.handshake_kind() == Some(HandshakeKind::Resumed);
    let group = tls
        .conn
        .negotiated_key_exchange_group()
        .map(|g| match g.name() {
            rustls::NamedGroup::X25519 => "X25519",
            rustls::NamedGroup::X25519MLKEM768 => "X25519MLKEM768",
            _ => "otro",
        });
    // Drenar el resto (tickets/close_notify) para que el servidor cierre limpio.
    let mut sink = Vec::new();
    let _ = tls.read_to_end(&mut sink);
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(Handshake {
        latency_ns,
        resumed,
        group,
        bytes_c2s: tls.sock.wr,
        bytes_s2c: tls.sock.rd,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub group: &'static str,
    pub resumption: bool,
    pub handshakes: u64,
    pub warmup: u64,
    pub resumed: u64,
    pub wall_s: f64,
    pub handshakes_per_s: f64,
    pub client_cpu_us_per_hs: f64,
    pub server_cpu_us_per_hs: f64,
    pub client_hello_bytes: usize,
    pub bytes_c2s_per_hs: f64,
    pub bytes_s2c_per_hs: f64,
    pub p50_us: f64,
    pub p90_us: f64,
    pub p99_us: f64,
    pub p999_us: f64,
    pub max_us: f64,
}

pub fn percentile(sorted: &[u64], q: f64) -> u64 {
    assert!(!sorted.is_empty());
    let idx = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len()) - 1;
    sorted[idx]
}

/// Corre `n` handshakes secuenciales (más `warmup` descartados) y devuelve el
/// reporte. Falla si algún handshake no negoció el grupo pedido o si, con
/// resumption, alguno no se reanudó.
pub fn run(pki: &Pki, group: Group, resumption: bool, n: u64, warmup: u64) -> Result<Report, String> {
    let server = Server::start(server_config(pki, resumption));
    let ccfg = client_config(pki, group, resumption, ClientIdentity::Valid);
    let ch = client_hello_bytes(client_config(pki, group, false, ClientIdentity::Valid));
    for _ in 0..warmup.max(1) {
        one_handshake(ccfg.clone(), server.addr).map_err(|e| format!("warmup: {e}"))?;
    }
    server.wait_for(warmup.max(1));
    let srv_cpu0 = server.cpu_us.load(Ordering::SeqCst);
    let ok0 = server.ok.load(Ordering::SeqCst);
    let mut lat = Vec::with_capacity(n as usize);
    let (mut resumed, mut c2s, mut s2c) = (0u64, 0u64, 0u64);
    let cpu0 = thread_cpu_us();
    let t = Instant::now();
    for i in 0..n {
        let h = one_handshake(ccfg.clone(), server.addr).map_err(|e| format!("handshake {i}: {e}"))?;
        if h.group != Some(group.name()) {
            return Err(format!("handshake {i}: grupo negociado {:?} != {}", h.group, group.name()));
        }
        if h.resumed {
            resumed += 1;
        }
        c2s += h.bytes_c2s;
        s2c += h.bytes_s2c;
        lat.push(h.latency_ns);
    }
    let wall = t.elapsed().as_secs_f64();
    let cli_cpu = thread_cpu_us() - cpu0;
    server.wait_for(warmup.max(1) + n);
    let srv_ok = server.ok.load(Ordering::SeqCst) - ok0;
    if srv_ok != n {
        return Err(format!("servidor completó {srv_ok} de {n}"));
    }
    let srv_cpu = server.cpu_us.load(Ordering::SeqCst) - srv_cpu0;
    if resumption && resumed != n {
        return Err(format!("resumption pedida pero solo {resumed}/{n} se reanudaron"));
    }
    if !resumption && resumed != 0 {
        return Err(format!("resumption desactivada pero {resumed} se reanudaron"));
    }
    lat.sort_unstable();
    let us = |v: u64| v as f64 / 1000.0;
    let nf = n as f64;
    Ok(Report {
        group: group.name(),
        resumption,
        handshakes: n,
        warmup: warmup.max(1),
        resumed,
        wall_s: wall,
        handshakes_per_s: nf / wall,
        client_cpu_us_per_hs: cli_cpu as f64 / nf,
        server_cpu_us_per_hs: srv_cpu as f64 / nf,
        client_hello_bytes: ch,
        bytes_c2s_per_hs: c2s as f64 / nf,
        bytes_s2c_per_hs: s2c as f64 / nf,
        p50_us: us(percentile(&lat, 0.50)),
        p90_us: us(percentile(&lat, 0.90)),
        p99_us: us(percentile(&lat, 0.99)),
        p999_us: us(percentile(&lat, 0.999)),
        max_us: us(*lat.last().unwrap()),
    })
}
