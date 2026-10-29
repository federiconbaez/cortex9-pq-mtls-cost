# cortex9-pq-mtls-cost

**¿Cuánto cuesta pasar mTLS entre servicios a intercambio de claves híbrido post-cuántico?**
Banco reproducible en Rust con [rustls](https://github.com/rustls/rustls) 0.23.46 (proveedor aws-lc-rs):
TLS 1.3, certificados **ECDSA P-256 en ambos lados** (el servidor exige certificado de cliente),
comparando `X25519` contra `X25519MLKEM768` ([RFC 10024](https://www.rfc-editor.org/rfc/rfc10024)),
con y sin resumption, sobre TCP real (para que `netem` afecte).

## Tesis

En mTLS, la verificación de dos cadenas ECDSA domina el costo del handshake, así que el híbrido
debería costar poco en CPU relativa y nada en latencia cuando la red tiene RTT de verdad. Con
resumption (TLS 1.3 `psk_dhe_ke`, que **vuelve a hacer intercambio de claves**) el costo relativo
del híbrido debería ser mayor, porque ya no se verifican certificados.

## Resultados (CI, GitHub Actions `ubuntu-24.04`, run [40814470333](https://github.com/federiconbaez/cortex9-pq-mtls-cost/actions/runs/40814470333))

Mediana de 5 rondas × 5000 handshakes secuenciales (loopback) y 3 rondas × 600 (netem).
Tablas completas, con min–máx y p99.9: [`results/SUMMARY.md`](results/SUMMARY.md). Crudos: [`results/raw/`](results/raw/).

**Sin netem (loopback, CI):**

| modo | grupo | hs/s | CPU cliente µs/hs | CPU servidor µs/hs | p50 µs | p99 µs |
|---|---|---|---|---|---|---|
| completo | X25519 | 2372 | 232.6 | 109.9 | 401 | 469 |
| completo | X25519MLKEM768 | 2061 | 274.6 | 143.1 | 464 | 528 |
| resumption | X25519 | 4184 | 142.8 | 94.1 | 216 | 279 |
| resumption | X25519MLKEM768 | 3364 | 183.2 | 124.4 | 274 | 340 |

Híbrido / X25519: completo **−13 % hs/s**, CPU cliente ×1.18, servidor ×1.30;
resumption **−20 % hs/s**, CPU cliente ×1.28, servidor ×1.32.

**Bytes en el cable (idénticos en todas las redes):** ClientHello 232 → 1416 B (+1184);
por handshake c→s +1183…1185 B y s→c +1087…1089 B. Coincide con RFC 10024 §4.1–4.2
(share de cliente 1216 = 1184 ML-KEM + 32 X25519; share de servidor 1120 = 1088 + 32);
un test (`clienthello_hibrido_crece_por_la_clave_mlkem`) fija el +1184.

**Con netem en `lo` (`delay 5ms` ⇒ RTT 10 ms):** p50 ≈ 31 ms en los cuatro casos (TCP + vuelo TLS +
eco = 3 RTT); el híbrido cambia p50 y p99 en ≤ 0.5 % (×1.000–×1.005). Con `mtu 1500` en `lo` tampoco
hay diferencia: el ClientHello híbrido (1416 B) todavía entra en un segmento.
Con `loss 1%` la p99 salta a ~1.06–1.08 s en ambos grupos (retransmisión con RTO de 1 s); con 600
handshakes por ronda esa cola es ruido de muestreo, no una diferencia entre grupos.

Box de desarrollo (VM compartida, sin netem): mismo signo, más ruido: completo −13 % hs/s, resumption −25 %
(`results/raw/box-loopback.jsonl`).

## Qué se mide y cómo

- **hs/s**: handshakes secuenciales, un cliente, una conexión por vez (incluye `connect()` TCP).
- **Latencia**: desde `connect()` hasta recibir el eco de 1 byte; el byte vuelve solo después de que el
  servidor validó el certificado del cliente. p50/p99/p99.9 por *nearest rank*.
- **CPU**: `getrusage(RUSAGE_THREAD)` user+sys, separado para el hilo cliente y para los hilos de
  conexión del servidor, dividido por handshakes.
- **Bytes**: contados en un wrapper del `TcpStream` del cliente (lo que realmente se escribe/lee).
- El cliente ofrece **un solo grupo** (sin HelloRetryRequest); el servidor acepta ambos.
  Cada corrida falla si un handshake negoció otro grupo, si con resumption alguno no se reanudó, o si
  sin resumption alguno se reanudó.

```bash
cargo test --release                      # 8 tests
N=5000 WARMUP=100 REPS=5 scripts/bench.sh mi-red   # -> results/raw/mi-red.jsonl
sudo scripts/netem.sh apply rtt10         # o rtt10-mtu1500 / rtt10-loss1; FATAL si no puede
N=600 WARMUP=20 REPS=3 scripts/bench.sh mi-red-rtt10
sudo scripts/netem.sh clear
python3 scripts/summarize.py              # results/SUMMARY.md; falla si p50 < 2*RTT (netem no actuó)
```

## Qué NO está probado

- **Concurrencia**: un solo cliente secuencial; no medí throughput con muchos núcleos ni colas de accept.
- **Redes reales**: netem en loopback no reproduce middleboxes, MSS pequeños ni initcwnd distintos.
  Con MTU 1500 el ClientHello híbrido cabe en un segmento; con MTU menores (túneles) podría no caber.
- **Firmas post-cuánticas** (ML-DSA en certificados): fuera de alcance; los certificados son ECDSA P-256.
- **Otras pilas** (OpenSSL, BoringSSL, Go): solo rustls + aws-lc-rs.
- **Hardware**: runners compartidos de GitHub y una VM; los valores absolutos dependen de la CPU
  (ver `results/raw/ci-env.txt`). Los cocientes son lo comparable.
- La cola con pérdida (p99.9) no es estadísticamente significativa con estas muestras.

## Fuentes leídas

- RFC 10024, *PQ/T Hybrid Key Agreement Mechanisms for TLS 1.3* — tamaños de shares (§4.1, §4.2).
- Código de rustls 0.23.46: `crypto::aws_lc_rs::kx_group::{X25519, X25519MLKEM768}`, feature
  `prefer-post-quantum` (no usada: el grupo se fija explícitamente en `CryptoProvider::kx_groups`).

## English summary

Reproducible rustls benchmark of mutual-TLS (ECDSA P-256 certs on both sides) with X25519 vs the
hybrid X25519MLKEM768. On GitHub Actions loopback the hybrid costs −13 % handshakes/s on full
handshakes and −20 % with resumption (TLS 1.3 resumption still runs the key exchange); it adds
+1184 B client→server and +1088 B server→client. With a 10 ms RTT (netem) latency differences
vanish (≤ 0.5 % on p50/p99). Single sequential client only; not tested on real networks or other TLS stacks.

Licencia: Apache-2.0.
