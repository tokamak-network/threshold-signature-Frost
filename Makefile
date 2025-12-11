# ===== tokamak-frost Makefile =====
# Usage (examples):
#   make dkg out=run_dkg t=3 n=3 gid=mygroup bind=127.0.0.1:9034 KEY_TYPE=secp256k1
#   make all out=run_dkg t=2 n=2 gid=mygroup bind=127.0.0.1:9034 KEY_TYPE=ed25519
#   make onchain out=run_dkg
#   make all out=run_dkg t=2 n=5 gid=mygroup bind=127.0.0.1:9043 msg='tokamak message to sign' KEY_TYPE=secp256k1

SHELL := /bin/bash
.ONESHELL:
.SILENT: help

# -------- Defaults (override on CLI) --------
out   ?= run_dkg
t     ?= 2
n     ?= 2
gid   ?= mygroup
bind  ?= 127.0.0.1:9034
msg   ?= tokamak message to sign
KEY_TYPE ?= secp256k1

.PHONY: help dkg select round1 round2 aggregate offchain onchain all clean close build
.PHONY: ws-sign

build:
	cargo build --workspace

help:
	echo "Targets:"
	echo "  make dkg out=... t=... n=... gid=... bind=host:port KEY_TYPE=..."
	echo "  make all out=... t=... n=... gid=... bind=host:port msg=... KEY_TYPE=..."
	echo ""
	echo "Variables: out, t (threshold), n (participants), gid (group id), bind (host:port), msg, KEY_TYPE (secp256k1 or ed25519)"

# ----- DKG end-to-end (server + clients, write group.json/share_*.json) -----
dkg: build
	rm -rf "$(out)"
	curl -s "http://$(bind)/close" >/dev/null 2>&1 || true
	sleep 3
	PORT=$$(echo "$(bind)" | awk -F: '{print $$2}'); \
	if lsof -iTCP:$$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then \
	  echo "ERROR: Port $$PORT is still in use. Please free it and retry."; \
	  exit 1; \
	fi
	( cargo run -p fserver -- server --bind "$(bind)" & )
	HOST=$$(echo "$(bind)" | awk -F: '{print $$1}'); PORT=$$(echo "$(bind)" | awk -F: '{print $$2}'); \
	for i in $$(seq 1 300); do \
	  nc -z $$HOST $$PORT >/dev/null 2>&1 && break; \
	  sleep 0.1; \
	  if [ $$i -eq 300 ]; then echo "ERROR: server not listening on $(bind)"; exit 1; fi; \
	done

	mkdir -p users
	echo "Regenerating $(n) users into users/ with key type $(KEY_TYPE)..."; \
	rm -f users/user*.json; \
	node scripts/make_users.js users $(n) $(KEY_TYPE); \

	ls users/user*.json | sort -V | head -n $(n) | while read -r f; do node -e 'const fs=require("fs"); const u=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(u.uid+";;;"+JSON.stringify(u.roster_public_key)+"\n");' "$$f"; done | paste -sd'|' - > users/participants_pubs.txt; \
	ls users/user*.json | sort -V | head -n $(n) | while read -r f; do node -e 'const fs=require("fs"); const u=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(String(u.uid)+"\n");' "$$f"; done | paste -sd, - > users/participants_ids.txt; \

	echo "participants_pubs: $$(cat users/participants_pubs.txt)"; \

	CREATOR_KEY=$$(node -e 'const fs=require("fs"); const u=JSON.parse(fs.readFileSync("users/user1.json","utf8")); process.stdout.write(u.private_key_hex);'); \
	cargo run -p dkg -- \
	  --key-type $(KEY_TYPE) \
	  --private-key "$$CREATOR_KEY" \
	  --url "ws://$(bind)/ws" \
	  --create --min-signers "$(t)" --max-signers "$(n)" \
	  --group-id "$(gid)" \
	  --participants "$$(cat users/participants_ids.txt)" \
	  --participants-pubs "$$(cat users/participants_pubs.txt)" \
	  --out-dir "$(out)" \
	  --session-file "$(out)/session.txt" & creator_pid=$$! ; \
	sleep 0.5

	for i in $$(seq 1 100); do \
	  if [ -s "$(out)/session.txt" ]; then echo "Session: $$(cat $(out)/session.txt)"; break; fi; \
	  sleep 0.1; \
	  if [ $$i -eq 100 ]; then echo "ERROR: session.txt not created by creator"; exit 1; fi; \
	done

	pids=""; \
	for UFILE in $$(ls users/user*.json | sort -V | head -n $(n) | tail -n +2); do \
	  PRIV_KEY=$$(node -e 'const fs=require("fs"); const u=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(u.private_key_hex);' "$$UFILE"); \
	  cargo run -p dkg -- \
	    --key-type $(KEY_TYPE) \
	    --private-key "$$PRIV_KEY" \
		--url "ws://$(bind)/ws" \
		--out-dir "$(out)" \
		--session-file "$(out)/session.txt" & \
	  pids="$$pids $$!"; \
	done; \
	for p in $$pids; do wait $$p || true; done; \
	if [ -n "$$creator_pid" ]; then wait "$$creator_pid" || true; fi
	echo "DKG completed; artifacts in $(out)/"

# ----- Choose first t shares from $(out) -----
select:
	test -d "$(out)" || { echo "No $(out). Run 'make dkg' first."; exit 1; }
	sh -c 'ls "$(out)"/share_*.json >/dev/null 2>&1' || { echo "No share_*.json in $(out). Run dkg first."; exit 1; }
	echo "Selected participants ($(t)):"
	ls "$(out)"/share_*.json | head -n $(t)

# ----- Round 1 for each selected participant -----
round1:
	for f in $$(ls "$(out)"/share_*.json | head -n $(t)); do \
	  echo "==> Round1 for $$f"; \
	  cargo run -p signing -- --key-type $(KEY_TYPE) --private-key $$(node -e 'const u=JSON.parse(fs.readFileSync("users/user" + $$f.match(/\d+/)[0] + ".json","utf8")); process.stdout.write(u.private_key_hex);') round1 --share "$$f"; \
	done

# ----- Round 2 for each selected participant (message hashed with keccak) -----
round2:
	for f in $$(ls "$(out)"/share_*.json | head -n $(t)); do \
	  echo "==> Round2 for $$f using r1 dir $(out)"; \
	  pubs=$$(node -e 'const fs=require("fs"); const dir="users"; if(!fs.existsSync(dir)){process.stdout.write("");process.exit(0);} const files=fs.readdirSync(dir).filter(name=>name.startsWith("user")&&name.endsWith(".json")).sort((a,b)=>parseInt(a.replace(/\D+/g,""))-parseInt(b.replace(/\D+/g,""))); const out=files.map(name=>{ const u=JSON.parse(fs.readFileSync(dir + "/" + name, "utf8")); return u.uid + ":" + JSON.stringify(u.roster_public_key); }); process.stdout.write(out.join(","));'); \
	  if [ -z "$$pubs" ]; then echo "ERROR: could not build participants-pubs from users/. Run 'make dkg' first."; exit 1; fi; \
	  cargo run -p signing -- --key-type $(KEY_TYPE) --private-key $$(node -e 'const u=JSON.parse(fs.readFileSync("users/user" + $$f.match(/\d+/)[0] + ".json","utf8")); process.stdout.write(u.private_key_hex);') round2 --share "$$f" --round1-dir "$(out)" --message '$(msg)' --participants-pubs "$$pubs"; \
	done

# ----- Aggregate partials into signature.json -----
aggregate:
	pubs=$$(node -e 'const fs=require("fs"); const dir="users"; if(!fs.existsSync(dir)){process.stdout.write("");process.exit(0);} const files=fs.readdirSync(dir).filter(name=>name.startsWith("user")&&name.endsWith(".json")).sort((a,b)=>parseInt(a.replace(/\D+/g,""))-parseInt(b.replace(/\D+/g,""))); const out=files.map(name=>{ const u=JSON.parse(fs.readFileSync(dir + "/" + name, "utf8")); return u.uid + ";;;" + JSON.stringify(u.roster_public_key); }); process.stdout.write(out.join(","));'); \
	if [ -z "$$pubs" ]; then echo "ERROR: could not build participants-pubs from users/. Run 'make dkg' first."; exit 1; fi; \
	cargo run -p signing -- aggregate --group "$(out)/group.json" --round1-dir "$(out)" --round2-dir "$(out)" --out "$(out)/signature.json" --participants-pubs "$$pubs"; \
	echo "-- signature.json --"; \
	cat "$(out)/signature.json"

# ----- Offchain verify (Rust) -----
offchain:
	cargo run -p offchain-verify -- --signature "$(out)/signature.json"

# ----- Onchain verify (Hardhat) -----
onchain:
	cd onchain-verify && SIG="../$(out)/signature.json" npx hardhat run scripts/verify-signature.ts --network hardhat

close:
	curl -s "http://$(bind)/close" || true
	sleep 3

# ----- All: DKG -> signing -> aggregate -> offchain -> onchain -----
all: dkg select round1 round2 aggregate offchain onchain close

clean:
	rm -rf "$(out)"

# ----- Interactive signing over WebSocket (creator + followers) -----
ws-sign: build
	echo "Building..." ; \
	cargo build --workspace ; \
	test -d "$(out)" || { echo "No $(out). Run 'make dkg' first."; exit 1; } ; \
	test -f "$(out)/group.json" || { echo "Missing $(out)/group.json. Run 'make dkg' first."; exit 1; } ; \
	ls "$(out)"/share_*.json >/dev/null 2>&1 || { echo "No share_*.json in $(out). Run 'make dkg' first."; exit 1; } ; \
	curl -s "http://$(bind)/close" >/dev/null 2>&1 || true ; \
	sleep 3 ; \
	PORT=$$(echo "$(bind)" | awk -F: '{print $$2}'); \
	if lsof -iTCP:$$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then \
	  echo "ERROR: Port $$PORT is still in use. Please free it and retry."; \
	  exit 1; \
	fi ; \
	( cargo run -p fserver -- server --bind "$(bind)" & ) ; \
	HOST=$$(echo "$(bind)" | awk -F: '{print $$1}'); PORT=$$(echo "$(bind)" | awk -F: '{print $$2}'); \
	for i in $$(seq 1 300); do \
	  nc -z $$HOST $$PORT >/dev/null 2>&1 && break; \
	  sleep 0.1; \
	  if [ $$i -eq 300 ]; then echo "ERROR: server not listening on $(bind)"; exit 1; fi; \
	done ; \
	test -d users || { echo "Missing users/. Run 'make dkg' first."; exit 1; } ; \
	ls users/user*.json | sort -V | head -n $(n) | while read -r f; do node -e 'const fs=require("fs"); const u=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(u.uid+";;;"+JSON.stringify(u.roster_public_key)+"\n");' "$$f"; done | paste -sd'|' - > users/signing_pubs.txt ; \
	ls users/user*.json | sort -V | head -n $(n) | while read -r f; do node -e 'const fs=require("fs"); const u=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(String(u.uid)+"\n");' "$$f"; done | paste -sd, - > users/signing_parts.txt ; \
	node -e 'const fs=require("fs");console.log(JSON.parse(fs.readFileSync("$(out)/group.json","utf8")).group_vk_sec1_hex)' > users/signing_gvk.txt ; \
	CREATOR_KEY=$$(node -e 'const fs=require("fs"); const u=JSON.parse(fs.readFileSync("users/user1.json","utf8")); process.stdout.write(u.private_key_hex);'); \
	rm -f "$(out)/sign_session.txt" ; \
	cargo run -p signing -- \
	  --key-type $(KEY_TYPE) \
	  --private-key "$$CREATOR_KEY" \
	  ws \
	  --url "ws://$(bind)/ws" \
	  --create \
	  --group-id "$(gid)" \
	  --threshold "2" \
	  --participants "$$(cat users/signing_parts.txt)" \
	  --participants-pubs "$$(cat users/signing_pubs.txt)" \
	  --group-vk-sec1-hex "$$(cat users/signing_gvk.txt)" \
	  --message '$(msg)' \
	  --share "$$(ls "$(out)"/share_*.json | sort -V | head -n 1)" \
	  --session-file "$(out)/sign_session.txt" \
	  --out-dir "$(out)" > creator.log 2>&1 & creator_pid=$$! ; \
	echo "Debug: parts=$$(cat users/signing_parts.txt)" ; \
	echo "Debug: pubs=$$(cat users/signing_pubs.txt)" ; \
	for i in $$(seq 1 100); do \
	  if [ -s "$(out)/sign_session.txt" ]; then echo "Session: $$(cat $(out)/sign_session.txt)"; break; fi; \
	  sleep 0.1; \
	  if [ $$i -eq 100 ]; then echo "ERROR: sign_session.txt not created by creator"; exit 1; fi; \
	done ; \
	pids=""; \
	ls "$(out)"/share_*.json | sort -V | head -n $(n) | tail -n +2 | while read -r SFILE; do \
	  uid=$$(echo $$SFILE | grep -oE '[0-9]+' | sed 's/^0*//'); \
	  UFILE="users/user$$uid.json"; \
	  PRIV_KEY=$$(node -e 'const fs=require("fs"); const u=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(u.private_key_hex);' "$$UFILE"); \
	  cargo run -p signing -- \
	    --key-type $(KEY_TYPE) \
	    --private-key "$$PRIV_KEY" \
	    ws \
	    --url "ws://$(bind)/ws" \
	    --group-id "$(gid)" \
	    --share "$$SFILE" \
	    --session-file "$(out)/sign_session.txt" \
	    --out-dir "$(out)" & \
	  pids="$$pids $$!"; \
	done ; \
	for p in $$pids; do wait $$p || true; done ; \
	if [ -n "$$creator_pid" ]; then wait "$$creator_pid" || true; fi

	test -f "$(out)/signature.json" || { echo "signature.json not produced"; exit 1; }
	echo "-- signature.json --"; \
	cat "$(out)/signature.json";
	$(MAKE) offchain out=$(out)
	$(MAKE) onchain out=$(out)
	$(MAKE) close bind=$(bind)
