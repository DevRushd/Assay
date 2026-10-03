BINARY := assay
PKG := ./...

CONTRACTS := assay-contracts
WASM := $(CONTRACTS)/out/assay_safety_registry.wasm

# Deployment coordinates. CONTRACT_ID is the live testnet deployment recorded in
# docs/deployment.md; override it to point the attest/read targets elsewhere.
NETWORK ?= testnet
SOURCE ?= assay-attester
CONTRACT_ID ?= CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73

.PHONY: all build test cover lint fmt vet run clean offline-test \
	contract-test contract-lint contract-build \
	build-contract deploy-testnet attest read verify-gate verify-wasm \
	eval-record eval-compare

all: build

build:
	go build -o $(BINARY) ./cmd/assay

test:
	go test -race $(PKG)

# cover prints the same per-package table CI puts in the job summary
# (scripts/coverage-report.sh), lowest coverage first. It reports; it does not
# gate. The test exit status is preserved so a failing test still fails.
cover:
	@go test -covermode=atomic -coverprofile=coverage.out $(PKG) > coverage.log 2>&1; \
	rc=$$?; cat coverage.log; echo; \
	./scripts/coverage-report.sh coverage.log coverage.out; \
	exit $$rc

fmt:
	gofmt -w .

vet:
	go vet $(PKG)

lint:
	golangci-lint run

run: build
	./$(BINARY) serve

contract-test:
	cd $(CONTRACTS) && cargo test

contract-lint:
	cd $(CONTRACTS) && cargo fmt --all -- --check
	cd $(CONTRACTS) && cargo clippy --all-targets -- -D warnings

contract-build:
	cd $(CONTRACTS) && cargo build --release --target wasm32v1-none

# build-contract produces the deployable artifact. It goes through the stellar
# CLI rather than cargo because the CLI also runs the wasm optimizer and checks
# the exported interface; contract-build above is the plain compile.
build-contract:
	stellar contract build --manifest-path $(CONTRACTS)/Cargo.toml \
		--package assay-safety-registry --out-dir $(CONTRACTS)/out

# verify-wasm rebuilds each contract from the committed source and checks the
# result against the wasm hashes recorded in docs/deployment.md. It builds into
# a temporary directory, so it never disturbs the artifact deploy-testnet would
# upload, and it never edits the document or submits a transaction.
#
# It exits 0 only when every recorded hash is reproduced. Until
# assay-contracts/rust-toolchain.toml exists (#127) the toolchain is whatever
# rustup has installed, which does not determine the bytes, so the run reports
# UNVERIFIABLE and exits 2. That is the honest answer, not a failure of the
# source. See docs/deployment.md ("Does the source still build what is
# deployed?").
verify-wasm:
	./scripts/verify-wasm-source.sh

deploy-testnet: build-contract
	stellar contract deploy --wasm $(WASM) \
		--source-account $(SOURCE) --network $(NETWORK)
	@echo
	@echo "Deployed. Record the contract ID in docs/deployment.md, then run:"
	@echo "  stellar contract invoke --id <ID> --source-account $(SOURCE) \\"
	@echo "    --network $(NETWORK) -- init --admin \$$(stellar keys address $(SOURCE))"

# attest scans ASSET live and writes the result on-chain.
#
# Every number submitted comes from `assay attestation`, which derives severity,
# the mechanic bitset, and evidence_hash from that scan. Nothing here lets a
# hand-written value reach the contract.
attest: build
	@test -n "$(ASSET)" || { echo 'usage: make attest ASSET=CODE-ISSUER'; exit 2; }
	@set -eu; \
	params=$$(./$(BINARY) attestation -raw '$(ASSET)'); \
	severity=$$(printf '%s' "$$params" | cut -f1); \
	flags=$$(printf '%s' "$$params" | cut -f2); \
	hash=$$(printf '%s' "$$params" | cut -f3); \
	sac=$$(stellar contract id asset --asset "$$(printf '%s' '$(ASSET)' | sed 's/-/:/')" --network $(NETWORK)); \
	echo "$(ASSET)"; \
	echo "  sac          $$sac"; \
	echo "  severity     $$severity"; \
	echo "  flags        $$flags"; \
	echo "  evidence     $$hash"; \
	stellar contract invoke --id $(CONTRACT_ID) --source-account $(SOURCE) --network $(NETWORK) \
		-- attest --asset "$$sac" --severity "$$severity" --flags "$$flags" --evidence_hash "$$hash"

# read calls get_safety against the deployed contract. It simulates rather than
# submits, so reading an attestation costs nothing and needs no signature.
read:
	@test -n "$(ASSET)" || { echo 'usage: make read ASSET=CODE-ISSUER'; exit 2; }
	@set -eu; \
	sac=$$(stellar contract id asset --asset "$$(printf '%s' '$(ASSET)' | sed 's/-/:/')" --network $(NETWORK)); \
	echo "$(ASSET) -> $$sac"; \
	stellar contract invoke --id $(CONTRACT_ID) --source-account $(SOURCE) --network $(NETWORK) \
		--send=no -- get_safety --asset "$$sac"

# Runs the merge gate against a commit range, the same script CI runs on every
# PR. Verify a change offline before opening the PR:
#   make verify-gate BASE=main HEAD=HEAD
verify-gate:
	@test -n "$(BASE)" || { echo 'usage: make verify-gate BASE=<sha-or-ref> HEAD=<sha-or-ref>'; exit 2; }
	./scripts/merge-gate.sh "$(BASE)" "$(HEAD)"

test-gate:
	bash ./scripts/test-merge-gate.sh

# Records the labelled corpus's classification, per subject and per check.
# Commit the result when the classifier's output is intended to change; it is
# the baseline eval-compare diffs against.
eval-record:
	go run ./cmd/eval -out docs/eval-baseline.json

# Re-captures one corpus fixture from the URLs recorded in PROVENANCE.md and
# prints a diff, so a maintainer can judge whether a moved verdict reflects a
# real change or a regression. It needs network access, so it is deliberately
# not part of `make test` or CI. A fetch that fails writes nothing.
#
#   make refresh-fixture SUBJECT=aqua-clear-verified
#   make refresh-fixture SUBJECT=aqua-clear-verified DRY_RUN=1
refresh-fixture:
	@test -n "$(SUBJECT)" || { echo 'usage: make refresh-fixture SUBJECT=<fixture-dir>'; exit 2; }
	go run ./cmd/refreshfixture -subject "$(SUBJECT)" $(if $(DRY_RUN),-dry-run,)

# Compares the current classifier against the recorded baseline and reports
# what moved: severity, mechanics and evidence separately, with undetermined
# subjects and corpus membership changes reported on their own. Exits 0 on a
# movement so it can be read as a report; add STRICT=1 to make movement fail.
eval-compare:
	@go run ./cmd/eval -compare docs/eval-baseline.json $(if $(STRICT),-strict,)

# Prints the confusion matrix over the labelled corpus, showing agreements
# and disagreements per severity level and per check with undetermined as
# its own outcome class. Sample size is printed with every result.
# Precision and recall require -precision-recall and carry a sample-size
# caveat.
eval:
	@go run ./cmd/eval -confusion -precision-recall

clean:
	rm -f $(BINARY) coverage.out coverage.html coverage.log
	rm -rf $(CONTRACTS)/out
	cd $(CONTRACTS) && cargo clean
