#!/usr/bin/env bash
# Aplica o quita un perfil netem sobre lo. Falla en voz alta si no puede.
# uso: sudo scripts/netem.sh apply rtt10|rtt10-mtu1500|rtt10-loss1 ; sudo scripts/netem.sh clear
set -euo pipefail
TC=$(command -v tc || echo /sbin/tc)
[ -x "$TC" ] || { echo "FATAL: tc no encontrado" >&2; exit 1; }
cmd=${1:?apply|clear}; prof=${2:-}
case "$cmd" in
  clear)
    "$TC" qdisc del dev lo root 2>/dev/null || true
    ip link set dev lo mtu 65536
    ;;
  apply)
    "$TC" qdisc del dev lo root 2>/dev/null || true
    ip link set dev lo mtu 65536
    case "$prof" in
      rtt10)         args="delay 5ms" ;;
      rtt10-mtu1500) args="delay 5ms"; ip link set dev lo mtu 1500 ;;
      rtt10-loss1)   args="delay 5ms loss 1%" ;;
      *) echo "FATAL: perfil desconocido '$prof'" >&2; exit 1 ;;
    esac
    # shellcheck disable=SC2086
    if ! "$TC" qdisc add dev lo root netem $args; then
      echo "FATAL: no se pudo aplicar netem ($args) en lo (¿falta sch_netem o permisos?)" >&2
      exit 1
    fi
    "$TC" qdisc show dev lo | grep -q "netem" || { echo "FATAL: netem no aparece en lo" >&2; exit 1; }
    echo "netem aplicado en lo: $("$TC" qdisc show dev lo | head -1); mtu $(cat /sys/class/net/lo/mtu)"
    ;;
  *) echo "uso: $0 apply PERFIL | clear" >&2; exit 1 ;;
esac
