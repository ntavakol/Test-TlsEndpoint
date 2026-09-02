#!/usr/bin/env bash
#
# test-tlsendpoint.sh
#
# Tests any TLS-wrapped TCP service: reachability, negotiated protocol and
# cipher, leaf certificate detail, hostname/SAN match, chain validation, and
# what the server actually presents on the wire.
#
# Bash companion to Test-TlsEndpoint.ps1. Same diagnostics, same output shape,
# driven by openssl instead of .NET.
#
# SECURITY NOTE
#   This script deliberately does not abort on an invalid certificate. A
#   rejected certificate cannot be inspected, and inspection is the point.
#   Findings are reported, never enforced. Do not reuse this pattern to
#   suppress validation in production clients.
#
# Requires: bash 3.2+, openssl 1.1.1+ (1.0.2 works with reduced SAN detail).
# No root. No extra packages.

set -u

VERSION='1.0.0'
PROGNAME=${0##*/}

# ---------------------------------------------------------------- defaults
HOST_ARG=''
PORT_ARG=''
SNI=''
TLS_VERSION='auto'
TIMEOUT=5
EXPIRY_WARNING_DAYS=30
SHOW_WIRE_CHAIN=0
SEND_SYSLOG=0
MESSAGE='tls endpoint connectivity test'
SYSLOG_HOST=''
APP_NAME='tlstest'
PRIORITY=134            # facility 16 (local0), severity 6 (info)
COUNT=1
SEND_RAW=''
HAVE_RAW=0
READ_RESPONSE=0
JSON=0
QUIET=0
USE_COLOR=auto
TARGETS_FILE=''
DNS_SERVER=''
COMPARE=0

WORKDIR=''
WORST_EXIT=0
OPENSSL_HELP=''
PAYLOAD_SENT=0

# exit codes
EX_OK=0
EX_USAGE=1
EX_TCP=2
EX_HANDSHAKE=3
EX_CERT=4
EX_DNS=5

SEP='--------------------------------------------------------------------'

# ------------------------------------------------------------------ output
C_RED=''; C_GREEN=''; C_YELLOW=''; C_RESET=''

setup_color() {
    local want=$USE_COLOR
    if [ "$want" = auto ]; then
        if [ -n "${NO_COLOR-}" ] || [ ! -t 1 ]; then want=never; else want=always; fi
    fi
    if [ "$want" = always ]; then
        C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
        C_YELLOW=$'\033[33m'; C_RESET=$'\033[0m'
    fi
}

say()  { [ "$QUIET" -eq 1 ] && return 0; printf '%s\n' "$*"; }
ok()   { [ "$QUIET" -eq 1 ] && return 0; printf '%s%s%s\n' "$C_GREEN"  "$*" "$C_RESET"; }
warn() { [ "$QUIET" -eq 1 ] && return 0; printf '%s%s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }
bad()  { [ "$QUIET" -eq 1 ] && return 0; printf '%s%s%s\n' "$C_RED"    "$*" "$C_RESET"; }
die()  { printf '%s%s%s\n' "$C_RED" "$PROGNAME: $*" "$C_RESET" >&2; exit "$EX_USAGE"; }

heading() {
    [ "$QUIET" -eq 1 ] && return 0
    printf '\n%s\n%s\n%s\n' "$SEP" "$1" "$SEP"
}

usage() {
    cat <<'USAGE_EOF'
test-tlsendpoint.sh - diagnose TLS problems on any TCP service

USAGE
  test-tlsendpoint.sh <host> <port> [options]
  test-tlsendpoint.sh --targets endpoints.txt [options]

CONNECTION
  --sni NAME              Server name for the SNI extension and SAN matching.
                          Defaults to <host>. Set when connecting by IP.
  --tls-version VER       auto (default), 1.0, 1.1, 1.2, 1.3
  --timeout SECONDS       Connect and read timeout. Default 5.
  --dns-server ADDR       Resolve the name against this DNS server rather
                          than the system resolver. Takes an IP address.
                          Bypasses the hosts file: this asks what that
                          server says, which is the point of asking it.
  --compare               Resolve through the system resolver as well and
                          report both answers side by side. Needs
                          --dns-server. The endpoint tested is still the one
                          --dns-server points at.
  --expiry-warning-days N Warn when the leaf expires within N days. Default 30.
  --show-wire-chain       Print full detail of every certificate the server
                          sends, not just the summary count.

PAYLOAD
  --send-syslog           Send an RFC 5424 message with RFC 5425 octet framing.
  --message TEXT          Syslog MSG body only, no PRI. Default a test string.
  --syslog-host NAME      Syslog HOSTNAME field. Default the local hostname.
  --app-name NAME         Syslog APP-NAME field. Default tlstest.
  --priority N            PRI value 0-191. Default 134 (local0.info).
  --count N               Messages to send over one connection. Default 1.
  --send-raw TEXT         Write an arbitrary string to the session.
                          Understands \n, \r, \t and \\.
  --read-response         Read and print what the server sends back.

OUTPUT
  --json                  Emit one JSON object per target instead of a report.
  --quiet                 Suppress the human-readable report.
  --color WHEN            auto (default), always, never.
  --targets FILE          Read targets from FILE, one "host port" or
                          "host:port" per line. Use - for stdin.
  -h, --help              This help.
  --version               Print version.

EXIT CODES
  0 success   1 usage   2 TCP failed   3 handshake failed   4 certificate problem
  5 name did not resolve

EXAMPLES
  test-tlsendpoint.sh syslog.example.com 6514
  test-tlsendpoint.sh mail.example.com 465 --show-wire-chain
  test-tlsendpoint.sh 192.0.2.10 636 --sni dc01.example.com
  test-tlsendpoint.sh www.example.com 443 --tls-version 1.2
  test-tlsendpoint.sh www.example.com 443 --dns-server 8.8.4.4
  test-tlsendpoint.sh www.example.com 443 --dns-server 8.8.4.4 --compare
  test-tlsendpoint.sh syslog.example.com 6514 --send-syslog --count 3
  test-tlsendpoint.sh www.example.com 443 --read-response \
      --send-raw 'GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n'
  test-tlsendpoint.sh --targets endpoints.txt --quiet --json > report.jsonl
USAGE_EOF
}

# ----------------------------------------------------------------- helpers
lower() { printf '%s' "${1-}" | tr '[:upper:]' '[:lower:]'; }

is_uint() { case ${1-} in ''|*[!0-9]*) return 1;; *) return 0;; esac; }

need_value() { [ "$2" -gt 0 ] || die "$1 requires a value"; }

# run a command with a wall-clock limit, using timeout(1) when available and
# a watchdog subshell when it is not (stock macOS ships no timeout)
with_timeout() {
    local secs=$1; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@"
        return $?
    fi
    if command -v gtimeout >/dev/null 2>&1; then
        gtimeout "$secs" "$@"
        return $?
    fi
    "$@" &
    local pid=$! rc=0
    ( sleep "$secs"; kill -TERM "$pid" 2>/dev/null ) >/dev/null 2>&1 &
    local watchdog=$!
    wait "$pid"; rc=$?
    kill -TERM "$watchdog" 2>/dev/null
    wait "$watchdog" 2>/dev/null
    return $rc
}

# match a whole option in the s_client help, so -tls1 is not satisfied by
# the presence of -tls1_2
openssl_supports() {
    printf '%s\n' "$OPENSSL_HELP" | grep -qE -- "(^|[[:space:]])$1([[:space:]]|$)"
}

# an address literal is already resolved; anything else is a name
is_ip_literal() {
    case $1 in
        *:*)                         return 0 ;;   # IPv6
        *[!0-9.]*)                   return 1 ;;
        [0-9]*.[0-9]*.[0-9]*.[0-9]*) return 0 ;;   # IPv4 dotted quad
        *)                           return 1 ;;
    esac
}

# addresses recorded for a name in the hosts file. Consulted first because the
# DNS-only fallbacks below cannot see it, and a name defined only there
# resolves perfectly well for the connect that follows.
hosts_file_lookup() {
    local name=$1 f win
    set -- /etc/hosts
    if command -v cygpath >/dev/null 2>&1 && [ -n "${SYSTEMROOT-}" ]; then
        win=$(cygpath -u "$SYSTEMROOT" 2>/dev/null) &&
            set -- "$@" "$win/System32/drivers/etc/hosts"
    fi
    for f in "$@"; do
        [ -r "$f" ] || continue
        awk -v n="$(lower "$name")" '
            { sub(/#.*/, "") }
            NF < 2 { next }
            { for (i = 2; i <= NF; i++) if (tolower($i) == n) { print $1; next } }
        ' "$f" 2>/dev/null
    done
}

# addresses out of an nslookup answer, skipping the resolver's own address,
# which precedes the first Name: line
nslookup_addresses() {
    awk '
        /^Name:/ { seen = 1; cont = 0; next }
        seen && /^Address(es)?:/ {
            sub(/^Address(es)?:[[:space:]]*/, ""); cont = 1
            if ($0 != "") print
            next
        }
        seen && cont && /^[[:space:]]+[0-9a-fA-F.:]+[[:space:]]*$/ {
            gsub(/[[:space:]]/, ""); print; next
        }
        { cont = 0 }
    ' | sort -u
}

# Ask one named server directly. Returns 3 when nothing on PATH can do that,
# which is a configuration error rather than a lookup failure: quietly falling
# back to the system resolver would answer a different question than the one
# asked.
resolve_via_server() {
    local name=$1 server=$2 out
    if command -v dig >/dev/null 2>&1; then
        out=$( { with_timeout "$TIMEOUT" dig +short "@$server" -t A    "$name" 2>/dev/null
                 with_timeout "$TIMEOUT" dig +short "@$server" -t AAAA "$name" 2>/dev/null
               } | grep -E '^[0-9a-fA-F.:]+$' | sort -u)
    elif command -v host >/dev/null 2>&1; then
        out=$(with_timeout "$TIMEOUT" host "$name" "$server" 2>/dev/null |
              sed -n 's/.* has \(IPv6 \)*address //p' | sort -u)
    elif command -v nslookup >/dev/null 2>&1; then
        out=$(with_timeout "$TIMEOUT" nslookup "$name" "$server" 2>/dev/null | nslookup_addresses)
    else
        return 3
    fi
    [ -n "$out" ] && { printf '%s\n' "$out"; return 0; }
    return 1
}

# Addresses for a name, one per line, empty output if it does not resolve.
# getent goes through getaddrinfo, exactly like the connect that follows, so
# it is trusted outright; the rest are fallbacks for systems without it.
# Returns 2, distinct from a lookup failure, when no resolver tool exists.
# resolve_host NAME [SERVER]; SERVER defaults to --dns-server, and an empty
# second argument forces the system resolver even when --dns-server is set,
# which is what --compare needs.
resolve_host() {
    local name=$1 out
    local server=${2-$DNS_SERVER}

    # A named server is a question about that server, so the hosts file and
    # the system resolver are deliberately bypassed.
    if [ -n "$server" ]; then
        resolve_via_server "$name" "$server"
        return $?
    fi

    out=$(hosts_file_lookup "$name")
    [ -n "$out" ] && { printf '%s\n' "$out"; return 0; }

    if command -v getent >/dev/null 2>&1; then
        out=$(with_timeout "$TIMEOUT" getent ahosts "$name" 2>/dev/null | awk '{print $1}')
        [ -z "$out" ] &&
            out=$(with_timeout "$TIMEOUT" getent hosts "$name" 2>/dev/null | awk '{print $1}')
        out=$(printf '%s\n' "$out" | sort -u | sed '/^$/d')
        [ -n "$out" ] && { printf '%s\n' "$out"; return 0; }
        return 1
    fi

    if command -v dscacheutil >/dev/null 2>&1; then     # macOS
        out=$(with_timeout "$TIMEOUT" dscacheutil -q host -a name "$name" 2>/dev/null |
              sed -n 's/^ipv*6*_address: *//p' | sort -u)
        [ -n "$out" ] && { printf '%s\n' "$out"; return 0; }
        return 1
    fi

    if command -v dig >/dev/null 2>&1; then
        out=$( { with_timeout "$TIMEOUT" dig +short -t A    "$name" 2>/dev/null
                 with_timeout "$TIMEOUT" dig +short -t AAAA "$name" 2>/dev/null
               } | grep -E '^[0-9a-fA-F.:]+$' | sort -u)
        [ -n "$out" ] && { printf '%s\n' "$out"; return 0; }
        return 1
    fi

    if command -v host >/dev/null 2>&1; then
        out=$(with_timeout "$TIMEOUT" host "$name" 2>/dev/null |
              sed -n 's/.* has \(IPv6 \)*address //p' | sort -u)
        [ -n "$out" ] && { printf '%s\n' "$out"; return 0; }
        return 1
    fi

    if command -v nslookup >/dev/null 2>&1; then
        out=$(with_timeout "$TIMEOUT" nslookup "$name" 2>/dev/null | nslookup_addresses)
        [ -n "$out" ] && { printf '%s\n' "$out"; return 0; }
        return 1
    fi

    return 2
}

# "host:port", bracketing bare IPv6 literals
hostport() {
    case $1 in
        *:*:*) printf '[%s]:%s' "$1" "$2" ;;
        *)     printf '%s:%s'   "$1" "$2" ;;
    esac
}

# seconds since epoch for an openssl date string, non-zero if neither date(1)
# dialect understands it
to_epoch() {
    local s=$1 out
    out=$(date -d "$s" +%s 2>/dev/null) && { printf '%s' "$out"; return 0; }
    out=$(date -j -f '%b %e %H:%M:%S %Y %Z' "$s" +%s 2>/dev/null) && { printf '%s' "$out"; return 0; }
    out=$(date -j -f '%b %d %H:%M:%S %Y %Z' "$s" +%s 2>/dev/null) && { printf '%s' "$out"; return 0; }
    return 1
}

# RFC 5424 TIMESTAMP, portable across GNU and BSD date. The fractional part
# is optional in the RFC, so it is omitted rather than shelled out for.
rfc5424_stamp() {
    local s
    s=$(date +%Y-%m-%dT%H:%M:%S%z) || return 1
    # 2026-09-02T14:03:11+0100 -> 2026-09-02T14:03:11+01:00
    printf '%s' "$s" | sed -E 's/([+-][0-9]{2})([0-9]{2})$/\1:\2/'
}

# expand backslash escapes in --send-raw. printf %b is the portable spelling
# and adds no trailing newline, which matters for protocols that count bytes.
interpret_escapes() { printf '%b' "$1"; }

json_str() {
    local s=${1-}
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\r'/}
    s=${s//$'\t'/\\t}
    s=${s//$'\n'/\\n}
    printf '"%s"' "$s"
}

json_num() { local v=${1-}; if [ -z "$v" ]; then printf 'null'; else printf '%s' "$v"; fi; }

# null when no comparison was asked for, which is not the same as a disagreement
json_tribool() {
    case ${1-} in
        1) printf 'true' ;;
        0) printf 'false' ;;
        *) printf 'null' ;;
    esac
}

json_bool() { if [ "${1-0}" = 1 ]; then printf 'true'; else printf 'false'; fi; }

# newline-separated stdin -> JSON array of strings
json_array() {
    local first=1 line
    printf '['
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        [ $first -eq 0 ] && printf ','
        json_str "$line"
        first=0
    done
    printf ']'
}

cleanup() { [ -n "$WORKDIR" ] && rm -rf "$WORKDIR"; }

# keep the most severe outcome across all targets
note_exit() {
    [ "$1" -gt "$WORST_EXIT" ] && WORST_EXIT=$1
    return 0
}

# --------------------------------------------------------------- arguments
parse_args() {
    local positional=0
    while [ $# -gt 0 ]; do
        case $1 in
            --sni)                 need_value "$1" $(($# - 1)); SNI=$2; shift 2 ;;
            --tls-version|--tls)   need_value "$1" $(($# - 1)); TLS_VERSION=$(lower "$2"); shift 2 ;;
            --dns-server)          need_value "$1" $(($# - 1)); DNS_SERVER=$2; shift 2 ;;
            --compare)             COMPARE=1; shift ;;
            --timeout)             need_value "$1" $(($# - 1)); TIMEOUT=$2; shift 2 ;;
            --expiry-warning-days) need_value "$1" $(($# - 1)); EXPIRY_WARNING_DAYS=$2; shift 2 ;;
            --show-wire-chain)     SHOW_WIRE_CHAIN=1; shift ;;
            --send-syslog)         SEND_SYSLOG=1; shift ;;
            --message)             need_value "$1" $(($# - 1)); MESSAGE=$2; shift 2 ;;
            --syslog-host)         need_value "$1" $(($# - 1)); SYSLOG_HOST=$2; shift 2 ;;
            --app-name)            need_value "$1" $(($# - 1)); APP_NAME=$2; shift 2 ;;
            --priority)            need_value "$1" $(($# - 1)); PRIORITY=$2; shift 2 ;;
            --count)               need_value "$1" $(($# - 1)); COUNT=$2; shift 2 ;;
            --send-raw)            need_value "$1" $(($# - 1)); SEND_RAW=$2; HAVE_RAW=1; shift 2 ;;
            --read-response)       READ_RESPONSE=1; shift ;;
            --json)                JSON=1; shift ;;
            --quiet)               QUIET=1; shift ;;
            --color)               need_value "$1" $(($# - 1)); USE_COLOR=$(lower "$2"); shift 2 ;;
            --targets)             need_value "$1" $(($# - 1)); TARGETS_FILE=$2; shift 2 ;;
            --version)             printf '%s %s\n' "$PROGNAME" "$VERSION"; exit 0 ;;
            -h|--help)             usage; exit 0 ;;
            --)                    shift; break ;;
            -*)                    die "unknown option '$1' (try --help)" ;;
            *)
                if   [ $positional -eq 0 ]; then HOST_ARG=$1; positional=1
                elif [ $positional -eq 1 ]; then PORT_ARG=$1; positional=2
                else die "unexpected argument '$1'"
                fi
                shift ;;
        esac
    done

    is_uint "$TIMEOUT" && [ "$TIMEOUT" -ge 1 ] || die "--timeout must be a positive whole number of seconds"
    is_uint "$EXPIRY_WARNING_DAYS" || die "--expiry-warning-days must be a whole number"
    is_uint "$PRIORITY" && [ "$PRIORITY" -le 191 ] || die "--priority must be 0-191"
    is_uint "$COUNT" && [ "$COUNT" -ge 1 ] && [ "$COUNT" -le 1000 ] || die "--count must be 1-1000"
    case $USE_COLOR in auto|always|never) ;; *) die "--color must be auto, always or never" ;; esac
}

tls_flag() {
    case $TLS_VERSION in
        auto)                printf '' ;;
        1.0|tls1|tls1.0|tls) printf -- '-tls1' ;;
        1.1|tls1.1|tls11)    printf -- '-tls1_1' ;;
        1.2|tls1.2|tls12)    printf -- '-tls1_2' ;;
        1.3|tls1.3|tls13)    printf -- '-tls1_3' ;;
        *) die "--tls-version must be auto, 1.0, 1.1, 1.2 or 1.3" ;;
    esac
}

# ------------------------------------------------------------ certificates
# hostname match, including the rule that a wildcard covers exactly one label
# and that label must actually be present
name_matches() {
    local expected san_file n suffix label
    expected=$(lower "$1")
    san_file=$2
    [ -s "$san_file" ] || return 1
    while IFS= read -r n || [ -n "$n" ]; do
        [ -z "$n" ] && continue
        n=$(lower "$n")
        [ "$n" = "$expected" ] && return 0
        case $n in
            '*.'*)
                suffix=${n#\*}                       # ".example.com"
                case $expected in
                    *"$suffix")
                        label=${expected%"$suffix"}
                        if [ -n "$label" ]; then
                            case $label in
                                *.*) ;;              # more than one label, no match
                                *)   return 0 ;;
                            esac
                        fi
                        ;;
                esac
                ;;
        esac
    done < "$san_file"
    return 1
}

# first PEM block in the s_client transcript
extract_leaf() {
    awk '/-----BEGIN CERTIFICATE-----/ { n++ }
         n == 1 { print }
         /-----END CERTIFICATE-----/ { if (n == 1) exit }' "$1"
}

cert_field() { openssl x509 -noout -in "$2" "$1" 2>/dev/null | sed 's/^[^=]*= *//'; }

subject_of() { openssl x509 -noout -subject -nameopt RFC2253 -in "$1" 2>/dev/null | sed 's/^subject= *//'; }
issuer_of()  { openssl x509 -noout -issuer  -nameopt RFC2253 -in "$1" 2>/dev/null | sed 's/^issuer= *//'; }

# ------------------------------------------------------------------- probe
run_one() {
    local host=$1 port=$2
    local sni=${SNI:-$host}
    local connect=$host
    local target; target=$(hostport "$host" "$port")
    local dir="$WORKDIR/target-$$-$RANDOM"
    mkdir -p "$dir" || die "cannot create work directory"

    # result fields, read back by emit_result
    local r_tcp=0 r_proto='' r_cipher='' r_bits='' r_kex=''
    local r_subject='' r_issuer='' r_notbefore='' r_notafter='' r_days=''
    local r_sigalg='' r_keysize='' r_fingerprint=''
    local r_namematch=0 r_chainvalid=0 r_verify='' r_wirecount='' r_sent=0
    local r_rootsent=0
    local r_error=''
    local sanfile="$dir/san.txt"
    : > "$sanfile"
    local addrfile="$dir/addrs.txt"
    : > "$addrfile"
    local sysaddrfile="$dir/sysaddrs.txt"
    : > "$sysaddrfile"
    local r_agree=''
    local rc=$EX_OK

    # ------------------------------------------------------------ DNS first
    # A name that does not resolve can never connect, and reporting that as a
    # refused connection sends the reader after a firewall that is not there.
    if ! is_ip_literal "$host"; then
        local addrs rrc
        addrs=$(resolve_host "$host"); rrc=$?
        local via=''
        [ -n "$DNS_SERVER" ] && via=" via $DNS_SERVER"
        if [ $rrc -eq 3 ]; then
            die "--dns-server needs dig, host or nslookup on PATH"
        fi
        if [ $rrc -eq 1 ]; then
            r_error="DNS resolution failed: '$host' did not resolve${via}"
            bad "DNS resolution for '$host'$via failed. The name did not resolve, so the service was never contacted."
            if [ -n "$DNS_SERVER" ]; then
                warn "That is the answer from $DNS_SERVER alone. Another resolver may well differ."
            else
                warn "Check the resolver rather than the endpoint: the host, the search domain, or a split-horizon zone."
            fi
            emit_result; note_exit $EX_DNS; return $EX_DNS
        fi
        if [ $rrc -eq 0 ] && [ "$COMPARE" -eq 1 ]; then
            # the system resolver's own answer, for the side-by-side
            local sys_addrs sys_rc sys_shown
            sys_addrs=$(resolve_host "$host" ""); sys_rc=$?
            printf '%s\n' "$sys_addrs" | sed '/^$/d' > "$sysaddrfile"
            if [ $sys_rc -eq 0 ] &&
               [ "$(printf '%s\n' "$sys_addrs" | sort)" = "$(printf '%s\n' "$addrs" | sort)" ]; then
                r_agree=1
            else
                r_agree=0
            fi
            # the verdict is settled above, because it belongs in the JSON
            # whether or not anything is printed
            if [ "$QUIET" -eq 0 ]; then
                if [ $sys_rc -eq 0 ]; then
                    sys_shown=$(printf '%s' "$sys_addrs" | tr '\n' ' ' | sed 's/ $//; s/ /, /g')
                else
                    sys_shown='did not resolve'
                fi
                heading "Resolver comparison"
                say "$(printf '  %-22s %s' 'system resolver' "$sys_shown")"
                say "$(printf '  %-22s %s' "$DNS_SERVER" \
                    "$(printf '%s' "$addrs" | tr '\n' ' ' | sed 's/ $//; s/ /, /g')")"
                if [ "$r_agree" -eq 1 ]; then
                    ok "The two resolvers agree."
                else
                    warn "The two resolvers disagree. The endpoint tested below is the one $DNS_SERVER points at."
                fi
            fi
        fi

        if [ $rrc -eq 0 ]; then
            printf '%s\n' "$addrs" > "$addrfile"
            # the comparison table above already showed this
            [ "$COMPARE" -eq 0 ] &&
                say "Resolved $host$via to $(printf '%s' "$addrs" | tr '\n' ' ' | sed 's/ $//; s/ /, /g')"
            # A named server is only really honoured if its answer is the
            # one connected to. Leaving the connect to the system resolver
            # would let it quietly overrule the flag. IPv4 is preferred
            # because a host with no IPv6 route fails confusingly.
            if [ -n "$DNS_SERVER" ]; then
                connect=$(printf '%s\n' "$addrs" | grep -v ':' | head -1)
                [ -z "$connect" ] && connect=$(printf '%s\n' "$addrs" | head -1)
                target=$(hostport "$connect" "$port")
                say "Connecting to $connect, validating the name '$sni'"
            fi
        fi
        # rrc 2 means no resolver tool was found; say nothing and let the
        # connect below speak for itself
    fi

    # -------------------------------------------------------- TCP reachable
    if with_timeout "$TIMEOUT" bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$connect" "$port" >/dev/null 2>&1; then
        r_tcp=1
    elif command -v nc >/dev/null 2>&1 &&
         with_timeout "$TIMEOUT" nc -z "$connect" "$port" >/dev/null 2>&1; then
        r_tcp=1
    fi

    if [ $r_tcp -eq 0 ]; then
        r_error="TCP connect failed: refused or timed out after ${TIMEOUT}s"
        bad "TCP connect to $target failed: refused or timed out after ${TIMEOUT}s"
        emit_result; note_exit $EX_TCP; return $EX_TCP
    fi
    ok "TCP $target open"

    # -------------------------------------------------------- TLS handshake
    local out="$dir/s_client.txt"
    local vflag; vflag=$(tls_flag)
    local -a cmd
    cmd=(openssl s_client -connect "$target" -showcerts)
    [ -n "$sni" ] && cmd[${#cmd[@]}]='-servername' && cmd[${#cmd[@]}]="$sni"
    if [ -n "$vflag" ]; then
        if ! openssl_supports "$vflag"; then
            r_error="this openssl build does not support $vflag"
            bad "This openssl build does not support $vflag."
            emit_result; note_exit $EX_HANDSHAKE; return $EX_HANDSHAKE
        fi
        cmd[${#cmd[@]}]="$vflag"
    fi

    with_timeout "$TIMEOUT" "${cmd[@]}" </dev/null >"$out" 2>&1

    if ! grep -q -- '-----BEGIN CERTIFICATE-----' "$out"; then
        local detail
        detail=$(grep -m1 -E 'error|alert|failure|no peer certificate' "$out" | sed 's/^[[:space:]]*//')
        [ -z "$detail" ] && detail='no certificate returned'
        r_error="TLS handshake failed: $detail"
        bad "TLS handshake failed: $detail"
        warn "The server may require a client certificate, or offers no protocol in common."
        emit_result; note_exit $EX_HANDSHAKE; return $EX_HANDSHAKE
    fi

    # The SSL-Session block is the richer source but is not reliably reached on
    # a TLS 1.3 connection, so fall back to the "New, <proto>, Cipher is <c>"
    # line that openssl prints as soon as the handshake completes.
    r_proto=$(sed -n 's/^[[:space:]]*Protocol[[:space:]]*:[[:space:]]*//p' "$out" | head -1)
    [ -z "$r_proto" ] && r_proto=$(sed -n 's/^New, \([^,]*\), Cipher is .*/\1/p' "$out" | head -1)
    [ "$r_proto" = '(NONE)' ] && r_proto=''

    r_cipher=$(sed -n 's/^[[:space:]]*Cipher[[:space:]]*:[[:space:]]*//p' "$out" | head -1)
    [ -z "$r_cipher" ] && r_cipher=$(sed -n 's/^New, [^,]*, Cipher is \(.*\)/\1/p' "$out" | head -1)
    [ "$r_cipher" = '(NONE)' ] && r_cipher=''

    r_kex=$(sed -n 's/^Server Temp Key:[[:space:]]*//p' "$out" | head -1)
    [ -z "$r_kex" ] && r_kex=$(sed -n 's/^Peer signature type:[[:space:]]*//p' "$out" | head -1)
    # size of the key exchange group, not the symmetric cipher strength, which
    # openssl does not report for TLS 1.3 ciphersuites
    r_bits=$(printf '%s' "$r_kex" | sed -n 's/.*, \([0-9]*\) bits.*/\1/p')

    say "Negotiated: ${r_proto:-unknown} / ${r_cipher:-unknown}${r_kex:+ / KeyExchange $r_kex}"
    case $r_proto in
        TLSv1|TLSv1.1|SSLv3)
            warn "Server negotiated a deprecated protocol. TLS 1.2 is the practical minimum." ;;
    esac

    # ----------------------------------------------------- leaf certificate
    local leaf="$dir/leaf.pem"
    extract_leaf "$out" > "$leaf"

    r_subject=$(subject_of "$leaf")
    r_issuer=$(issuer_of "$leaf")
    r_notbefore=$(cert_field -startdate "$leaf")
    r_notafter=$(cert_field -enddate "$leaf")
    r_fingerprint=$(openssl x509 -noout -fingerprint -sha256 -in "$leaf" 2>/dev/null | sed 's/^.*=//; s/://g')
    r_sigalg=$(openssl x509 -noout -text -in "$leaf" 2>/dev/null |
               sed -n 's/^[[:space:]]*Signature Algorithm:[[:space:]]*//p' | head -1)
    r_keysize=$(openssl x509 -noout -text -in "$leaf" 2>/dev/null |
                sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p' | head -1)

    local now_epoch end_epoch start_epoch
    now_epoch=$(date +%s)
    end_epoch=$(to_epoch "$r_notafter") || end_epoch=''
    start_epoch=$(to_epoch "$r_notbefore") || start_epoch=''
    [ -n "$end_epoch" ] && r_days=$(( (end_epoch - now_epoch) / 86400 ))

    heading 'Leaf certificate'
    say "Subject     : $r_subject"
    say "Issuer      : $r_issuer"
    say "NotBefore   : $r_notbefore"
    say "NotAfter    : $r_notafter"
    say "DaysLeft    : ${r_days:-unknown}"
    say "SigAlg      : ${r_sigalg:-unknown}"
    say "KeySize     : ${r_keysize:-unknown}"
    say "SHA256      : $r_fingerprint"
    say ''

    # openssl answers the expiry question even where date(1) cannot parse
    if ! openssl x509 -noout -in "$leaf" -checkend 0 >/dev/null 2>&1; then
        if [ -n "$r_days" ]; then
            bad "Certificate EXPIRED $(( -r_days )) days ago."
        else
            bad "Certificate has EXPIRED."
        fi
        rc=$EX_CERT
    elif ! openssl x509 -noout -in "$leaf" -checkend $(( EXPIRY_WARNING_DAYS * 86400 )) >/dev/null 2>&1; then
        warn "Certificate expires in ${r_days:-fewer than $EXPIRY_WARNING_DAYS} days."
    fi

    if [ -n "$start_epoch" ] && [ "$start_epoch" -gt "$now_epoch" ]; then
        bad "Certificate is not valid until $r_notbefore. Check clock sync on the client."
        rc=$EX_CERT
    fi

    # --------------------------------------------------------- SAN matching
    local santext
    santext=$(openssl x509 -noout -ext subjectAltName -in "$leaf" 2>/dev/null |
              grep -v 'Subject Alternative Name')
    if [ -z "$santext" ]; then
        santext=$(openssl x509 -noout -text -in "$leaf" 2>/dev/null |
                  grep -A1 'Subject Alternative Name' | tail -1)
    fi

    if [ -z "$santext" ]; then
        bad "No Subject Alternative Name extension. Most modern clients will reject this certificate."
        rc=$EX_CERT
    else
        # the trailing newline matters: without it the last name is a partial
        # line that "read" hands back with a false return, and gets dropped
        printf '%s\n' "$santext" | tr ',' '\n' |
            sed 's/^[[:space:]]*//; s/[[:space:]]*$//' |
            sed -n 's/^DNS://p; s/^IP Address://p; s/^IP://p' > "$sanfile"

        say "SAN: $(tr '\n' ' ' < "$sanfile" | sed 's/[[:space:]]*$//')"

        if name_matches "$sni" "$sanfile"; then
            r_namematch=1
            ok "SAN matches '$sni'"
        else
            bad "SAN does NOT match '$sni'. Clients validating hostname will reject this."
            rc=$EX_CERT
        fi
    fi

    # ------------------------------------------------ chain and trust store
    heading "Chain as validated against this host's trust store"

    local chain_lines
    # keep openssl's own indentation, which nests i:/a:/v: under their subject.
    # openssl interleaves a PEM block after every depth, so skip those rather
    # than stopping at the first one, or only the leaf is ever shown. The
    # chain block ends at the lone "---" separator.
    chain_lines=$(awk '/^Certificate chain/          { grab = 1; next }
                       grab && /^---$/               { grab = 0 }
                       /-----BEGIN CERTIFICATE-----/ { skip = 1 }
                       /-----END CERTIFICATE-----/   { skip = 0; next }
                       grab && !skip                 { print }' "$out")
    if [ -n "$chain_lines" ]; then
        printf '%s\n' "$chain_lines" | while IFS= read -r line; do say "$line"; done
    else
        warn 'No chain data returned.'
    fi

    r_verify=$(sed -n 's/^[[:space:]]*Verify return code:[[:space:]]*//p' "$out" | tail -1)
    case $r_verify in
        '0 '*)
            r_chainvalid=1
            ok "Chain validates against this host's trust store." ;;
        *)
            r_chainvalid=0
            warn "Chain status: ${r_verify:-unknown}"
            grep -E '^verify (error|return code)' "$out" | sort -u |
                while IFS= read -r line; do warn "  $line"; done
            rc=$EX_CERT ;;
    esac
    say "Verify return code: ${r_verify:-unknown}"
    say "Note: the local OS may supply intermediates from its own cache or fetch them via AIA."
    say "      A constrained client (appliance, IoT, embedded agent) often will not."

    # -------------------------------- what the server actually sends on wire
    heading 'Certificates presented on the wire'

    r_wirecount=$(grep -c -- '-----BEGIN CERTIFICATE-----' "$out" | tr -d ' ')
    say "Certificates sent by server: $r_wirecount"

    # split the presented certificates out, so the last one can be examined
    awk -v dir="$dir" '
        /-----BEGIN CERTIFICATE-----/ { n++; grab = 1 }
        grab { print > (dir "/wire-" n ".pem") }
        /-----END CERTIFICATE-----/   { grab = 0 }' "$out"

    if [ "$SHOW_WIRE_CHAIN" -eq 1 ] && [ "$QUIET" -eq 0 ]; then
        local idx=0 f
        while [ $idx -lt "$r_wirecount" ]; do
            idx=$((idx + 1))
            f="$dir/wire-$idx.pem"
            [ -f "$f" ] || continue
            say "[$((idx - 1))] $(subject_of "$f")"
            say "     issuer  : $(issuer_of "$f")"
            say "     expires : $(cert_field -enddate "$f")"
        done
    fi

    # A root is self-signed: it issues itself. Counting certificates is not a
    # sound test, because a cross-signed intermediate makes a perfectly correct
    # chain three certificates long.
    local last="$dir/wire-$r_wirecount.pem"
    if [ -f "$last" ] && [ "$(subject_of "$last")" = "$(issuer_of "$last")" ]; then
        r_rootsent=1
    fi

    if [ "$r_wirecount" -le 1 ]; then
        warn "Leaf only. Clients that do not fetch intermediates via AIA cannot build a path."
        warn "Rebuild the server certificate as leaf followed by intermediates."
    elif [ "$r_rootsent" -eq 1 ]; then
        warn "The chain ends in a self-signed root, which the server need not send."
        warn "Harmless for most clients, but some embedded stacks reject it."
    elif [ "$r_wirecount" -eq 2 ]; then
        ok "Leaf plus intermediate presented."
    else
        ok "Leaf plus $((r_wirecount - 1)) intermediates presented."
    fi

    # -------------------------------------------------------------- payload
    if [ "$SEND_SYSLOG" -eq 1 ] || [ "$HAVE_RAW" -eq 1 ] || [ "$READ_RESPONSE" -eq 1 ]; then
        heading 'Test payload'
        send_payload "$target" "$sni" "$dir"
        r_sent=$PAYLOAD_SENT
    fi

    emit_result
    note_exit $rc
    return $rc
}

# -------------------------------------------------------------- payload leg
# Sent on its own connection so the inspection transcript above stays clean.
# All --count messages still ride a single connection, which is the point of
# the flag: it catches collectors that drop on connection reuse.
send_payload() {
    local target=$1 sni=$2 dir=$3
    PAYLOAD_SENT=0

    if [ "$SEND_SYSLOG" -eq 1 ]; then
        case $(printf '%s' "$MESSAGE" | sed 's/^[[:space:]]*//') in
            '<'[0-9]'>'* | '<'[0-9][0-9]'>'* | '<'[0-9][0-9][0-9]'>'*)
                bad "--message must not begin with a PRI value such as <134>."
                bad "The RFC 5424 header is generated for you. Pass the MSG body only."
                return 0 ;;
        esac
    fi

    local payload="$dir/payload.bin"
    : > "$payload"
    local n stamp body msg bytes total
    local -a preview
    preview=()

    if [ "$SEND_SYSLOG" -eq 1 ]; then
        stamp=$(rfc5424_stamp)
        n=1
        while [ "$n" -le "$COUNT" ]; do
            body=$MESSAGE
            [ "$COUNT" -gt 1 ] && body="$MESSAGE [$n of $COUNT]"
            # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
            msg="<$PRIORITY>1 $stamp $SYSLOG_HOST $APP_NAME - - - $body"
            # RFC 5425 octet counting is over bytes, not characters
            bytes=$(printf '%s' "$msg" | LC_ALL=C wc -c | tr -d ' ')
            printf '%s %s' "$bytes" "$msg" >> "$payload"
            preview[${#preview[@]}]="Sent [$n/$COUNT] $bytes bytes: $msg"
            n=$((n + 1))
        done
    fi

    if [ "$HAVE_RAW" -eq 1 ]; then
        total=$(LC_ALL=C wc -c < "$payload" | tr -d ' ')
        interpret_escapes "$SEND_RAW" >> "$payload"
        total=$(( $(LC_ALL=C wc -c < "$payload" | tr -d ' ') - total ))
        preview[${#preview[@]}]="Sent $total raw bytes."
    fi

    local vflag; vflag=$(tls_flag)
    local -a pcmd
    pcmd=(openssl s_client -connect "$target" -quiet)
    [ -n "$sni" ] && pcmd[${#pcmd[@]}]='-servername' && pcmd[${#pcmd[@]}]="$sni"
    if [ "$READ_RESPONSE" -eq 0 ] && openssl_supports '-no_ign_eof'; then
        pcmd[${#pcmd[@]}]='-no_ign_eof'
    fi
    [ -n "$vflag" ] && pcmd[${#pcmd[@]}]="$vflag"

    local resp="$dir/response.bin"
    local budget=$(( TIMEOUT + COUNT + 3 ))

    {
        cat "$payload"
        [ "$READ_RESPONSE" -eq 1 ] && sleep "$TIMEOUT"
    } | with_timeout "$budget" "${pcmd[@]}" >"$resp" 2>"$dir/response.err"
    local prc=$?

    # 124 is timeout(1) hitting its limit and 143 a SIGTERM from the fallback
    # watchdog. Both are expected when the connection is deliberately held
    # open to read a reply, so neither counts as a send failure.
    if [ $prc -ne 0 ] && [ $prc -ne 124 ] && [ $prc -ne 143 ] && [ ! -s "$resp" ]; then
        bad "Send failed: $(head -1 "$dir/response.err" 2>/dev/null)"
        return 0
    fi

    local line
    for line in ${preview[@]+"${preview[@]}"}; do
        ok "$line"
    done
    PAYLOAD_SENT=${#preview[@]}

    if [ "$SEND_SYSLOG" -eq 1 ]; then
        say "Filter the receiver on host=$SYSLOG_HOST app=$APP_NAME to confirm arrival."
    fi

    if [ "$READ_RESPONSE" -eq 1 ]; then
        if [ -s "$resp" ]; then
            local received shown=8192
            received=$(LC_ALL=C wc -c < "$resp" | tr -d ' ')
            say ''
            say "Received $received bytes:"
            if [ "$QUIET" -eq 0 ]; then
                # cap the dump, as the PowerShell version does with its single
                # 8 KB read. A web server will otherwise flood the terminal.
                head -c "$shown" "$resp"
                if [ "$received" -gt "$shown" ]; then
                    printf '\n'
                    warn "... truncated. Showing the first $shown of $received bytes."
                fi
            fi
        else
            warn "Server closed the connection without sending data, or nothing arrived within ${TIMEOUT}s."
        fi
    fi
}

# ---------------------------------------------------------------- JSON emit
# Reads the r_* locals of the calling run_one, mirroring -PassThru in the
# PowerShell version.
emit_result() {
    [ "$JSON" -eq 1 ] || return 0
    printf '{'
    printf '"host":%s,'              "$(json_str "$host")"
    printf '"port":%s,'              "$(json_num "$port")"
    printf '"sni":%s,'               "$(json_str "$sni")"
    printf '"dnsServer":%s,'         "$(json_str "$DNS_SERVER")"
    printf '"resolved":%s,'          "$(json_array < "$addrfile")"
    printf '"systemResolved":%s,'    "$(json_array < "$sysaddrfile")"
    printf '"resolversAgree":%s,'    "$(json_tribool "$r_agree")"
    printf '"tcpOpen":%s,'           "$(json_bool "$r_tcp")"
    printf '"tlsProtocol":%s,'       "$(json_str "$r_proto")"
    printf '"cipher":%s,'            "$(json_str "$r_cipher")"
    printf '"keyExchangeBits":%s,'   "$(json_num "$r_bits")"
    printf '"keyExchange":%s,'       "$(json_str "$r_kex")"
    printf '"subject":%s,'           "$(json_str "$r_subject")"
    printf '"issuer":%s,'            "$(json_str "$r_issuer")"
    printf '"notBefore":%s,'         "$(json_str "$r_notbefore")"
    printf '"notAfter":%s,'          "$(json_str "$r_notafter")"
    printf '"daysLeft":%s,'          "$(json_num "$r_days")"
    printf '"signatureAlg":%s,'      "$(json_str "$r_sigalg")"
    printf '"keySize":%s,'           "$(json_num "$r_keysize")"
    printf '"fingerprintSha256":%s,' "$(json_str "$r_fingerprint")"
    printf '"subjectAltNames":%s,'   "$(json_array < "$sanfile")"
    printf '"nameMatch":%s,'         "$(json_bool "$r_namematch")"
    printf '"chainValid":%s,'        "$(json_bool "$r_chainvalid")"
    printf '"verifyResult":%s,'      "$(json_str "$r_verify")"
    printf '"wireCertCount":%s,'     "$(json_num "$r_wirecount")"
    printf '"selfSignedRootSent":%s,' "$(json_bool "$r_rootsent")"
    printf '"sent":%s,'              "$(json_num "$r_sent")"
    printf '"error":%s'              "$(json_str "$r_error")"
    printf '}\n'
}

# --------------------------------------------------------------------- main
run_targets() {
    local src=$TARGETS_FILE line h p first=1
    [ "$src" = '-' ] && src=/dev/stdin
    [ -r "$src" ] || die "cannot read targets file '$TARGETS_FILE'"
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%%#*}
        line=$(printf '%s' "$line" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
        [ -z "$line" ] && continue
        case $line in
            *[[:space:]]*) h=${line%%[[:space:]]*}; p=${line##*[[:space:]]} ;;
            *:*)           h=${line%:*};            p=${line##*:} ;;
            *)             h=$line;                 p=${PORT_ARG:-443} ;;
        esac
        if ! is_uint "$p"; then
            bad "skipping '$line': port is not a number"
            note_exit $EX_USAGE
            continue
        fi
        if [ "$QUIET" -eq 0 ]; then
            [ $first -eq 0 ] && printf '\n%s\n' "$SEP"
            printf '== %s:%s\n' "$h" "$p"
        fi
        first=0
        run_one "$h" "$p"
    done < "$src"
}

main() {
    parse_args "$@"
    setup_color
    tls_flag >/dev/null    # validate --tls-version before doing any work
    if [ -n "$DNS_SERVER" ] && ! is_ip_literal "$DNS_SERVER"; then
        die "--dns-server takes an IP address, not '$DNS_SERVER'"
    fi
    if [ "$COMPARE" -eq 1 ] && [ -z "$DNS_SERVER" ]; then
        die "--compare needs --dns-server: it compares that server against the system resolver"
    fi

    command -v openssl >/dev/null 2>&1 ||
        die "openssl not found on PATH. Install it, or use Test-TlsEndpoint.ps1, which needs no openssl."
    OPENSSL_HELP=$(openssl s_client -help 2>&1)

    [ -n "$SYSLOG_HOST" ] || SYSLOG_HOST=$(hostname 2>/dev/null || printf '%s' "${HOSTNAME:-localhost}")

    WORKDIR=$(mktemp -d 2>/dev/null || mktemp -d -t tlsendpoint) || die "cannot create temp directory"
    trap cleanup EXIT
    trap 'cleanup; exit 130' INT
    trap 'cleanup; exit 143' TERM

    if [ -n "$TARGETS_FILE" ]; then
        run_targets
        exit "$WORST_EXIT"
    fi

    if [ -z "$HOST_ARG" ]; then
        [ -t 0 ] || die "no host given (try --help)"
        printf 'Host or IP of the TLS service: '
        read -r HOST_ARG
        [ -n "$HOST_ARG" ] || die "a host is required"
    fi
    if [ -z "$PORT_ARG" ]; then
        [ -t 0 ] || die "no port given (try --help)"
        printf 'TCP port: '
        read -r PORT_ARG
    fi
    is_uint "$PORT_ARG" && [ "$PORT_ARG" -ge 1 ] && [ "$PORT_ARG" -le 65535 ] ||
        die "port must be a number 1-65535"

    run_one "$HOST_ARG" "$PORT_ARG"
    exit "$WORST_EXIT"
}

main "$@"
