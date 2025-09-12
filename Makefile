# Defaults (override like: make t=3 n=5 gid=mygroup out=run1 msg="hello")
t ?= 4
n ?= 6
gid ?= tokamak
out ?= out
msg ?= tokamak message to sign
net ?= hardhat     # <— hardhat network name for on-chain verify

.PHONY: all keygen select round1 round2 aggregate verify clean onchain-verify all-onchain

all: clean keygen select round1 round2 aggregate verify

keygen:
	cargo run -p keygen -- --min-signers $(t) --max-signers $(n) --group-id $(gid) --out-dir $(out)

# Select a random set of $(t) participants and persist to $(out)/participants.txt
select:
	@set -e; \
	files=$$(ls $(out)/share_*.json 2>/dev/null || true); \
	if [ -z "$$files" ]; then echo "No share_*.json in $(out). Run 'make keygen' first."; exit 1; fi; \
	mkdir -p "$(out)"; \
	printf "%s\n" $$files | awk -v t=$(t) 'BEGIN{srand();} {a[NR]=$$0} END{n=NR; for(i=1;i<=n;i++){j=int(rand()*n)+1; tmp=a[i]; a[i]=a[j]; a[j]=tmp;} lim=t<n?t:n; for(i=1;i<=lim;i++) print a[i]}' > "$(out)/participants.txt"; \
	echo "Selected participants ($(t)):"; cat "$(out)/participants.txt"

# Round 1: run once per selected participant listed in participants.txt
round1:
	@set -e; \
	if [ ! -f "$(out)/participants.txt" ]; then $(MAKE) select; fi; \
	while IFS= read -r f; do \
	  echo "==> Round1 for $$f"; \
	  cargo run -p signing -- round1 --share "$$f"; \
	done < "$(out)/participants.txt"

# Round 2: each selected participant signs using ALL round1 files in $(out)
round2:
	@set -e; \
	if [ ! -f "$(out)/participants.txt" ]; then $(MAKE) select; fi; \
	while IFS= read -r f; do \
	  echo "==> Round2 for $$f using r1 dir $(out)"; \
	  cargo run -p signing -- round2 --share "$$f" --round1-dir "$(out)" --message "$(msg)"; \
	done < "$(out)/participants.txt"

# Aggregate: single run consuming per-participant files from $(out)
aggregate:
	cargo run -p signing -- aggregate --group $(out)/group.json --round1-dir $(out) --round2-dir $(out) --out $(out)/signature.json

verify:
	cargo run -p offchain-verify -- --signature $(out)/signature.json

show-sig:
	@echo "-- signature.json --"
	@if command -v jq >/dev/null 2>&1; then jq . "$(out)/signature.json"; else cat "$(out)/signature.json"; fi

clean:
	rm -rf $(out)

# Verify signature.json on-chain via Hardhat (uses onchain/ project)
onchain-verify:
	cd onchain-verify && SIG="../$(out)/signature.json" npx hardhat run scripts/verify-signature.ts --network $(net)

# Full pipeline + on-chain verification
all-onchain: all onchain-verify show-sig
