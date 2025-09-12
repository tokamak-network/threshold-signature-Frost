#!/usr/bin/env bash
set -euo pipefail

# Defaults
T=4
N=6
GID="tokamak"
OUT="out"
MSG="tokamak message to sign"
NET="hardhat"   # <— on-chain verify network

usage() {
  cat <<EOF
Usage: $0 [-t THRESHOLD] [-n TOTAL] [-g GROUP_ID] [-m MESSAGE] [-o OUT_DIR] [-N NETWORK]

  -t  threshold (min signers), default: 4
  -n  total participants (max signers), default: 6
  -g  group id string, default: "tokamak"
  -m  message (ASCII or 0x-hex), default: "tokamak message to sign"
  -o  output dir, default: out
  -N  hardhat network for on-chain verify, default: hardhat
EOF
}

while getopts ":t:n:g:m:o:N:h" opt; do
  case $opt in
    t) T="$OPTARG" ;;
    n) N="$OPTARG" ;;
    g) GID="$OPTARG" ;;
    m) MSG="$OPTARG" ;;
    o) OUT="$OPTARG" ;;
    N) NET="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage; exit 1 ;;
  esac
done

c_green=$(tput setaf 2 || true)
c_cyan=$(tput setaf 6 || true)
c_yellow=$(tput setaf 3 || true)
c_reset=$(tput sgr0 || true)

rand_pick() {
  if command -v shuf >/dev/null 2>&1; then
    shuf -n "$T"
  elif command -v gshuf >/dev/null 2>&1; then
    gshuf -n "$T"
  else
    awk 'BEGIN{srand()}{print rand(),$0}' | sort -k1,1n | cut -d' ' -f2- | head -n "$T"
  fi
}
# Clean previous outputs to ensure a fresh run
if [ -n "$OUT" ] && [ "$OUT" != "/" ]; then
  echo "${c_yellow}Cleaning output dir: ${OUT}${c_reset}"
  rm -rf -- "$OUT"
fi

mkdir -p "$OUT"

echo "${c_cyan}==> Keygen (t=${T}, n=${N}, gid=${GID}, out=${OUT})${c_reset}"
cargo run -p keygen -- --min-signers "$T" --max-signers "$N" --group-id "$GID" --out-dir "$OUT"

# Pick T participants and persist the list for R1/R2
ls -1 "$OUT"/share_*.json | rand_pick > "$OUT/participants.txt"
echo "Selected participants (${T}):"
cat "$OUT/participants.txt"

# Round 1 (per participant)
while IFS= read -r SHARE; do
  echo "${c_cyan}==> Round1 for ${SHARE}${c_reset}"
  cargo run -p signing -- round1 --share "$SHARE"
done < "$OUT/participants.txt"

# Round 2 (per participant)
while IFS= read -r SHARE; do
  echo "${c_cyan}==> Round2 for ${SHARE} using r1 dir ${OUT}${c_reset}"
  cargo run -p signing -- round2 --share "$SHARE" --round1-dir "$OUT" --message "$MSG"
done < "$OUT/participants.txt"

# Aggregate and Verify
echo "${c_cyan}==> Aggregate${c_reset}"
cargo run -p signing -- aggregate --group "$OUT/group.json" --round1-dir "$OUT" --round2-dir "$OUT" --out "$OUT/signature.json"

echo "${c_green}==> Verify (Rust)${c_reset}"
cargo run -p offchain-verify -- --signature "$OUT/signature.json"

# On-chain verification (Hardhat)
echo "${c_green}==> Verify (on-chain via Hardhat: ${NET})${c_reset}"
(
  cd onchain-verify || exit 1
  # Ensure a **local** Hardhat is installed to avoid HHE22
  if [ ! -x node_modules/.bin/hardhat ]; then
    echo "Installing local Hardhat (onchain-verify)…"
    if command -v pnpm >/dev/null 2>&1 && [ -f pnpm-lock.yaml ]; then
      pnpm install --frozen-lockfile
    elif command -v yarn >/dev/null 2>&1 && [ -f yarn.lock ]; then
      yarn install --frozen-lockfile
    elif [ -f package-lock.json ]; then
      npm ci
    else
      npm i --no-fund --no-audit --silent
    fi
  fi
  SIG="../${OUT}/signature.json" node_modules/.bin/hardhat run scripts/verify-signature.ts --network "${NET}"
)

# Show the signature JSON
echo "${c_yellow}-- signature.json --${c_reset}"
cat "$OUT/signature.json" || true
echo
