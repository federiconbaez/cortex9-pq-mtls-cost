use pq_mtls_cost::*;

fn pki() -> Pki {
    Pki::generate()
}

#[test]
fn negocia_el_grupo_pedido_en_ambos_modos() {
    let p = pki();
    for g in [Group::X25519, Group::X25519MlKem768] {
        let srv = Server::start(server_config(&p, false));
        let h =
            one_handshake(client_config(&p, g, false, ClientIdentity::Valid), srv.addr).unwrap();
        assert_eq!(h.group, Some(g.name()));
        assert!(!h.resumed);
    }
}

#[test]
fn servidor_rechaza_cliente_sin_certificado() {
    let p = pki();
    let srv = Server::start(server_config(&p, false));
    let r = one_handshake(
        client_config(&p, Group::X25519MlKem768, false, ClientIdentity::None),
        srv.addr,
    );
    assert!(
        r.is_err(),
        "mTLS no exigido: el cliente sin certificado recibió eco"
    );
    srv.wait_for(1);
    assert_eq!(srv.ok.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn servidor_rechaza_cliente_de_otra_ca() {
    let p = pki();
    let srv = Server::start(server_config(&p, false));
    let r = one_handshake(
        client_config(&p, Group::X25519, false, ClientIdentity::Rogue),
        srv.addr,
    );
    assert!(r.is_err(), "cliente firmado por otra CA aceptado");
    srv.wait_for(1);
    assert_eq!(srv.failed.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn resumption_reanuda_y_sigue_usando_el_grupo() {
    let p = pki();
    for g in [Group::X25519, Group::X25519MlKem768] {
        let srv = Server::start(server_config(&p, true));
        let c = client_config(&p, g, true, ClientIdentity::Valid);
        let first = one_handshake(c.clone(), srv.addr).unwrap();
        assert!(!first.resumed);
        for _ in 0..5 {
            let h = one_handshake(c.clone(), srv.addr).unwrap();
            assert!(h.resumed, "{}: no se reanudó", g.name());
            // TLS 1.3 psk_dhe_ke: la reanudación vuelve a hacer intercambio de claves.
            assert_eq!(h.group, Some(g.name()));
        }
    }
}

#[test]
fn sin_resumption_nunca_reanuda() {
    let p = pki();
    let srv = Server::start(server_config(&p, false));
    let c = client_config(&p, Group::X25519, false, ClientIdentity::Valid);
    for _ in 0..5 {
        assert!(!one_handshake(c.clone(), srv.addr).unwrap().resumed);
    }
}

#[test]
fn clienthello_hibrido_crece_por_la_clave_mlkem() {
    // ML-KEM-768 encapsulation key = 1184 bytes (FIPS 203); el key share
    // híbrido es mlkem_ek || x25519 (1184 + 32) contra 32 de X25519 solo.
    let p = pki();
    let a = client_hello_bytes(client_config(
        &p,
        Group::X25519,
        false,
        ClientIdentity::Valid,
    ));
    let b = client_hello_bytes(client_config(
        &p,
        Group::X25519MlKem768,
        false,
        ClientIdentity::Valid,
    ));
    assert_eq!(b - a, 1184, "x25519={a} híbrido={b}");
}

#[test]
fn run_produce_reporte_coherente() {
    let p = pki();
    for res in [false, true] {
        let r = run(&p, Group::X25519MlKem768, res, 50, 2).unwrap();
        assert_eq!(r.handshakes, 50);
        assert_eq!(r.resumed, if res { 50 } else { 0 });
        assert!(r.handshakes_per_s > 0.0);
        assert!(r.client_cpu_us_per_hs > 0.0 && r.server_cpu_us_per_hs > 0.0);
        assert!(r.p50_us <= r.p99_us && r.p99_us <= r.max_us);
    }
}

#[test]
fn percentil_es_nearest_rank() {
    let v: Vec<u64> = (1..=100).collect();
    assert_eq!(percentile(&v, 0.5), 50);
    assert_eq!(percentile(&v, 0.99), 99);
    assert_eq!(percentile(&v, 1.0), 100);
    assert_eq!(percentile(&[7], 0.99), 7);
}
