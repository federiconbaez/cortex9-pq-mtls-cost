# Resumen (mediana entre rondas)

Generado por `scripts/summarize.py` desde `results/raw/*.jsonl`. CPU = user+sys por hilo (getrusage RUSAGE_THREAD); latencia = TCP connect + handshake mTLS + eco de 1 byte.

## Red: `box-loopback`

| modo | grupo | hs/s (mín–máx) | CPU cliente µs/hs | CPU servidor µs/hs | ClientHello B | B c→s/hs | B s→c/hs | p50 µs | p99 µs | p99.9 µs |
|---|---|---|---|---|---|---|---|---|---|---|
| completo | X25519 | 1223 (1163–1255) | 291.1 | 254.3 | 232 | 1220 | 1189 | 761 | 1419 | 1797 |
| completo | X25519MLKEM768 | 1070 (1001–1213) | 343.6 | 305.2 | 1416 | 2403 | 2278 | 892 | 1669 | 2943 |
| resumption | X25519 | 2803 (2557–2983) | 132.4 | 154.9 | 232 | 454 | 369 | 257 | 988 | 1234 |
| resumption | X25519MLKEM768 | 2100 (1883–2255) | 178.4 | 226.0 | 1416 | 1638 | 1457 | 366 | 1078 | 1347 |

Híbrido / X25519 (mediana):

- completo: hs/s x0.874, CPU cliente x1.180, CPU servidor x1.200, bytes c→s +1183, s→c +1089, p50 x1.171, p99 x1.176
- resumption: hs/s x0.749, CPU cliente x1.347, CPU servidor x1.460, bytes c→s +1184, s→c +1088, p50 x1.426, p99 x1.091

## Red: `ci-loopback`

| modo | grupo | hs/s (mín–máx) | CPU cliente µs/hs | CPU servidor µs/hs | ClientHello B | B c→s/hs | B s→c/hs | p50 µs | p99 µs | p99.9 µs |
|---|---|---|---|---|---|---|---|---|---|---|
| completo | X25519 | 2372 (2363–2383) | 232.6 | 109.9 | 232 | 1220 | 1189 | 401 | 469 | 586 |
| completo | X25519MLKEM768 | 2061 (2054–2102) | 274.6 | 143.1 | 1416 | 2402 | 2276 | 464 | 528 | 653 |
| resumption | X25519 | 4184 (4140–4226) | 142.8 | 94.1 | 232 | 454 | 369 | 216 | 279 | 311 |
| resumption | X25519MLKEM768 | 3364 (3312–3372) | 183.2 | 124.4 | 1416 | 1638 | 1457 | 274 | 340 | 382 |

Híbrido / X25519 (mediana):

- completo: hs/s x0.869, CPU cliente x1.181, CPU servidor x1.302, bytes c→s +1182, s→c +1087, p50 x1.158, p99 x1.125
- resumption: hs/s x0.804, CPU cliente x1.283, CPU servidor x1.322, bytes c→s +1184, s→c +1088, p50 x1.271, p99 x1.221

## Red: `ci-rtt10`

| modo | grupo | hs/s (mín–máx) | CPU cliente µs/hs | CPU servidor µs/hs | ClientHello B | B c→s/hs | B s→c/hs | p50 µs | p99 µs | p99.9 µs |
|---|---|---|---|---|---|---|---|---|---|---|
| completo | X25519 | 32 (32–32) | 465.4 | 271.9 | 232 | 1219 | 1190 | 31168 | 31351 | 31450 |
| completo | X25519MLKEM768 | 32 (32–32) | 525.9 | 313.5 | 1416 | 2402 | 2276 | 31254 | 31469 | 31946 |
| resumption | X25519 | 32 (32–32) | 278.3 | 216.2 | 232 | 454 | 369 | 30820 | 31001 | 31221 |
| resumption | X25519MLKEM768 | 32 (32–32) | 327.1 | 257.3 | 1416 | 1638 | 1457 | 30926 | 31059 | 31199 |

Híbrido / X25519 (mediana):

- completo: hs/s x0.997, CPU cliente x1.130, CPU servidor x1.153, bytes c→s +1183, s→c +1086, p50 x1.003, p99 x1.004
- resumption: hs/s x0.997, CPU cliente x1.176, CPU servidor x1.190, bytes c→s +1184, s→c +1088, p50 x1.003, p99 x1.002

## Red: `ci-rtt10-loss1`

| modo | grupo | hs/s (mín–máx) | CPU cliente µs/hs | CPU servidor µs/hs | ClientHello B | B c→s/hs | B s→c/hs | p50 µs | p99 µs | p99.9 µs |
|---|---|---|---|---|---|---|---|---|---|---|
| completo | X25519 | 18 (15–20) | 356.8 | 201.1 | 232 | 1218 | 1189 | 30760 | 1058199 | 1090995 |
| completo | X25519MLKEM768 | 15 (12–18) | 409.7 | 236.7 | 1416 | 2403 | 2277 | 30810 | 1075766 | 2074811 |
| resumption | X25519 | 18 (16–20) | 222.7 | 167.7 | 232 | 454 | 369 | 30487 | 1065786 | 1093569 |
| resumption | X25519MLKEM768 | 15 (15–18) | 278.1 | 204.4 | 1416 | 1638 | 1457 | 30556 | 1072690 | 1270774 |

Híbrido / X25519 (mediana):

- completo: hs/s x0.824, CPU cliente x1.148, CPU servidor x1.177, bytes c→s +1185, s→c +1088, p50 x1.002, p99 x1.017
- resumption: hs/s x0.814, CPU cliente x1.249, CPU servidor x1.218, bytes c→s +1184, s→c +1088, p50 x1.002, p99 x1.006

## Red: `ci-rtt10-mtu1500`

| modo | grupo | hs/s (mín–máx) | CPU cliente µs/hs | CPU servidor µs/hs | ClientHello B | B c→s/hs | B s→c/hs | p50 µs | p99 µs | p99.9 µs |
|---|---|---|---|---|---|---|---|---|---|---|
| completo | X25519 | 32 (32–32) | 423.9 | 249.1 | 232 | 1219 | 1188 | 30956 | 31266 | 31382 |
| completo | X25519MLKEM768 | 32 (32–32) | 463.0 | 269.4 | 1416 | 2404 | 2277 | 30953 | 31249 | 31503 |
| resumption | X25519 | 33 (33–33) | 215.6 | 188.3 | 232 | 454 | 369 | 30515 | 30712 | 30956 |
| resumption | X25519MLKEM768 | 33 (33–33) | 307.2 | 255.0 | 1416 | 1638 | 1457 | 30675 | 30843 | 31032 |

Híbrido / X25519 (mediana):

- completo: hs/s x0.999, CPU cliente x1.092, CPU servidor x1.082, bytes c→s +1185, s→c +1089, p50 x1.000, p99 x0.999
- resumption: hs/s x0.996, CPU cliente x1.424, CPU servidor x1.354, bytes c→s +1184, s→c +1088, p50 x1.005, p99 x1.004
