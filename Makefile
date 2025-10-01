# ===== tokamak-frost Makefile =====
# Usage (examples):
#   make dkg out=run_dkg t=3 n=3 gid=mygroup bind=127.0.0.1:9034
#   make all out=run_dkg t=2 n=2 gid=mygroup bind=127.0.0.1:9034
#   make onchain out=run_dkg
#
# Notes:
# - No PID file / kill logic; server is closed via /close and exits after 3s.
# - You can override variables on the command line.

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

# If you have long-term ECDSA keys in env, export per client like:
#   export DKG_ECDSA_PRIV_HEX_1=...   export DKG_ECDSA_PRIV_HEX_2=...
# The client also supports passing via --ecdsa-priv-hex but env is simpler in shell loops.

.PHONY: help dkg select round1 round2 aggregate offchain onchain all clean close
.PHONY: ws-sign

help:
	echo "Targets:"
	echo "  make dkg out=... t=... n=... gid=... bind=host:port"
	echo "  make select out=..."
	echo "  make round1 out=..."
	echo "  make round2 out=... msg='message to sign'"
	echo "  make aggregate out=..."
	echo "  make offchain out=..."
	echo "  make onchain out=..."
	echo "  make all out=... t=... n=... gid=... bind=host:port msg=..."
	echo ""
	echo "Variables: out, t (threshold), n (participants), gid (group id), bind (host:port), msg"

# ----- DKG end-to-end (server + clients, write group.json/share_*.json) -----
dkg:
	rm -rf "$(out)"
	# attempt graceful close of any old server instance on this bind (ignore errors)
	curl -s "http://$(bind)/close" >/dev/null 2>&1 || true
	sleep 3
	# ensure port is free (macOS): extract port and check listener; bail if still busy
	PORT=$$(echo "$(bind)" | awk -F: '{print $$2}'); \
	if lsof -iTCP:$$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then \
	  echo "ERROR: Port $$PORT is still in use. Please free it and retry."; \
	  exit 1; \
	fi
	# start server in background (no PID file; will close via /close)
	( cargo run -p fserver -- server --bind "$(bind)" & )
	# wait for port to listen (max ~5s)
	HOST=$$(echo "$(bind)" | awk -F: '{print $$1}'); PORT=$$(echo "$(bind)" | awk -F: '{print $$2}'); \
	for i in $$(seq 1 50); do \
	  nc -z $$HOST $$PORT >/dev/null 2>&1 && break; \
	  sleep 0.1; \
	  if [ $$i -eq 50 ]; then echo "ERROR: server not listening on $(bind)"; exit 1; fi; \
	done

	# Ensure users/ directory exists with exactly n users; regenerate cleanly if count differs
	mkdir -p users
	if [ "$$(ls users/user*.json 2>/dev/null | wc -l | tr -d ' ')" != "$(n)" ]; then \
	  echo "Regenerating $(n) users into users/ ..."; \
	  rm -f users/user*.json; \
	  node scripts/make_users.js users $(n); \
	fi

	# Show computed participants and pubs (inline)
	echo "Participants: $$((ls users/user*.json | sort -V | head -n $(n) | while read -r f; do node -e 'const fs=require("fs"); const u=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(String(u.uid)+"\n");' "$$f"; done) | paste -sd, -)"
	echo "participants_pubs: $$((ls users/user*.json | sort -V | head -n $(n) | while read -r f; do node -e 'const fs=require("fs"); const u=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(u.uid+":"+u.ecdsa_pub_sec1_hex+"\n");' "$$f"; done) | paste -sd, -)"
	DKG_ECDSA_PRIV_HEX="$$(node -e 'const fs=require("fs"); const u=JSON.parse(fs.readFileSync("users/user1.json","utf8")); process.stdout.write(u.ecdsa_priv_hex);')" \
	cargo run -p dkg -- \
	  --url "ws://$(bind)/ws" \
	  --create --min-signers "$(t)" --max-signers "$(n)" \
	  --group-id "$(gid)" \
	  --participants "$$((ls users/user*.json | sort -V | head -n $(n) | while read -r f; do node -e 'const fs=require("fs"); const u=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(String(u.uid)+"\n");' "$$f"; done) | paste -sd, -)" \
	  --participants-pubs "$$((ls users/user*.json | sort -V | head -n $(n) | while read -r f; do node -e 'const fs=require("fs"); const u=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(u.uid+":"+u.ecdsa_pub_sec1_hex+"\n");' "$$f"; done) | paste -sd, -)" \
	  --out-dir "$(out)" \
	  --session-file "$(out)/session.txt" & creator_pid=$$! ; \
	sleep 0.5

	# Wait for session file to be created by the creator (max ~10s)
	for i in $$(seq 1 100); do \
	  if [ -s "$(out)/session.txt" ]; then echo "Session: $$(cat $(out)/session.txt)"; break; fi; \
	  sleep 0.1; \
	  if [ $$i -eq 100 ]; then echo "ERROR: session.txt not created by creator"; exit 1; fi; \
	done

	# Other participants (uids 2..n)
	pids=""; \
	for UFILE in $$(ls users/user*.json | sort -V | head -n $(n) | tail -n +2); do \
	  upriv=$$(node -e 'const fs=require("fs");const u=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(u.ecdsa_priv_hex);' "$$UFILE"); \
	  DKG_ECDSA_PRIV_HEX="$$upriv" \
	  cargo run -p dkg -- \
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
	  cargo run -p signing -- round1 --share "$$f"; \
	done

# ----- Round 2 for each selected participant (message hashed with keccak) -----
round2:
	for f in $$(ls "$(out)"/share_*.json | head -n $(t)); do \
	  echo "==> Round2 for $$f using r1 dir $(out)"; \
	  pubs=$$(node -e 'const fs=require("fs"); const dir="users"; if(!fs.existsSync(dir)){process.stdout.write("");process.exit(0);} const files=fs.readdirSync(dir).filter(name=>name.startsWith("user")&&name.endsWith(".json")).sort((a,b)=>parseInt(a.replace(/\D+/g,""))-parseInt(b.replace(/\D+/g,""))); const out=files.map(name=>{ const u=JSON.parse(fs.readFileSync(dir + "/" + name, "utf8")); return u.uid + ":" + u.ecdsa_pub_sec1_hex; }); process.stdout.write(out.join(","));'); \
	  if [ -z "$$pubs" ]; then echo "ERROR: could not build participants-pubs from users/. Run 'make dkg' first."; exit 1; fi; \
	  cargo run -p signing -- round2 --share "$$f" --round1-dir "$(out)" --message '$(msg)' --participants-pubs "$$pubs"; \
	done

# ----- Aggregate partials into signature.json -----
aggregate:
	pubs=$$(node -e 'const fs=require("fs"); const dir="users"; if(!fs.existsSync(dir)){process.stdout.write("");process.exit(0);} const files=fs.readdirSync(dir).filter(name=>name.startsWith("user")&&name.endsWith(".json")).sort((a,b)=>parseInt(a.replace(/\D+/g,""))-parseInt(b.replace(/\D+/g,""))); const out=files.map(name=>{ const u=JSON.parse(fs.readFileSync(dir + "/" + name, "utf8")); return u.uid + ":" + u.ecdsa_pub_sec1_hex; }); process.stdout.write(out.join(","));'); \
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
	# graceful shutdown via /close (server shuts down ~3s later)
	curl -s "http://$(bind)/close" || true
	sleep 3
# ----- All: DKG -> signing -> aggregate -> offchain -> onchain -----
all: dkg select round1 round2 aggregate offchain onchain close

clean:
	rm -rf "$(out)"

# ----- Interactive signing over WebSocket (creator + followers) -----
ws-sign:
	# Preconditions
	test -d "$(out)" || { echo "No $(out). Run 'make dkg' first."; exit 1; }
	test -f "$(out)/group.json" || { echo "Missing $(out)/group.json. Run 'make dkg' first."; exit 1; }
	sh -c 'ls "$(out)"/share_*.json >/dev/null 2>&1' || { echo "No share_*.json in $(out). Run 'make dkg' first."; exit 1; }

	# attempt graceful close of any old server instance on this bind (ignore errors)
	curl -s "http://$(bind)/close" >/dev/null 2>&1 || true
	sleep 3
	# ensure port is free (macOS)
	PORT=$$(echo "$(bind)" | awk -F: '{print $$2}'); \
	if lsof -iTCP:$$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then \
	  echo "ERROR: Port $$PORT is still in use. Please free it and retry."; \
	  exit 1; \
	fi
	# start server in background
	( cargo run -p fserver -- server --bind "$(bind)" & )
	# wait for port to listen (max ~5s)
	HOST=$$(echo "$(bind)" | awk -F: '{print $$1}'); PORT=$$(echo "$(bind)" | awk -F: '{print $$2}'); \
	for i in $$(seq 1 50); do \
	  nc -z $$HOST $$PORT >/dev/null 2>&1 && break; \
	  sleep 0.1; \
	  if [ $$i -eq 50 ]; then echo "ERROR: server not listening on $(bind)"; exit 1; fi; \
	done

	# Build roster (first t users) and pubs
	test -d users || { echo "Missing users/. Run 'make dkg' first."; exit 1; }
	PARTS=$$(node -e 'const fs=require("fs"); const t=parseInt(process.argv[1]); const files=fs.readdirSync("users").filter(n=>n.startsWith("user")&&n.endsWith(".json")).sort((a,b)=>parseInt(a.replace(/\D+/g,""))-parseInt(b.replace(/\D+/g,""))).slice(0,t); console.log(files.map(n=>JSON.parse(fs.readFileSync("users/"+n,"utf8")).uid).join(","));' $(t))
	PUBS=$$(node -e 'const fs=require("fs"); const t=parseInt(process.argv[1]); const files=fs.readdirSync("users").filter(n=>n.startsWith("user")&&n.endsWith(".json")).sort((a,b)=>parseInt(a.replace(/\D+/g,""))-parseInt(b.replace(/\D+/g,""))).slice(0,t); console.log(files.map(n=>{const u=JSON.parse(fs.readFileSync("users/"+n,"utf8")); return u.uid+":"+u.ecdsa_pub_sec1_hex;}).join(","));' $(t))
	GVK=$$(node -e 'const fs=require("fs");console.log(JSON.parse(fs.readFileSync("$(out)/group.json","utf8")).group_vk_sec1_hex)')
	SESSION_FILE="$(out)/sign_session.txt"

	# Creator uses first participant/user and first share file
	export SIGNING_ECDSA_PRIV_HEX=$$(node -e 'const fs=require("fs"); const files=fs.readdirSync("users").filter(n=>n.startsWith("user")&&n.endsWith(".json")).sort((a,b)=>parseInt(a.replace(/\D+/g,""))-parseInt(b.replace(/\D+/g,""))); const f=files[0]; const u=JSON.parse(fs.readFileSync("users/"+f,"utf8")); process.stdout.write(u.ecdsa_priv_hex);')
	cargo run -p signing -- ws \
	  --url ws://$(bind)/ws \
	  --create \
	  --group-id "$(gid)" \
	  --threshold "$(t)" \
	  --participants "$$PARTS" \
	  --participants-pubs "$$PUBS" \
	  --group-vk-sec1-hex "$$GVK" \
	  --message '$(msg)' \
	  --share "$$([ -n "$(out)" ] && ls "$(out)"/share_*.json | sort -V | head -n 1)" \
	  --session-file "$(out)/sign_session.txt" \
	  --out-dir "$(out)" & creator_pid=$$! ; \
	sleep 0.5

	# Followers: remaining (t-1) users + shares (ordered)
	pids=""; \
	paste <(ls users/user*.json | sort -V | head -n $(t) | tail -n +2) <(ls "$(out)"/share_*.json | sort -V | head -n $(t) | tail -n +2) | \
	while read -r UFILE SFILE; do \
	  export SIGNING_ECDSA_PRIV_HEX=$$(node -e 'const fs=require("fs");const u=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(u.ecdsa_priv_hex);' "$$UFILE"); \
	  cargo run -p signing -- ws \
	    --url ws://$(bind)/ws \
	    --share "$$SFILE" \
	    --session-file "$(out)/sign_session.txt" \
	    --out-dir "$(out)" & \
	  pids="$$pids $$!"; \
	done; \
	for p in $$pids; do wait $$p || true; done; \
	if [ -n "$$creator_pid" ]; then wait "$$creator_pid" || true; fi

	# Show and verify signature
	test -f "$(out)/signature.json" || { echo "signature.json not produced"; exit 1; }
	echo "-- signature.json --"; \
	cat "$(out)/signature.json";
	$(MAKE) offchain out=$(out)
	$(MAKE) onchain out=$(out)
	$(MAKE) close bind=$(bind)
