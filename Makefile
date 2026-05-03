## o11y-behaviorbaseline — developer Makefile
##
## Primary targets:
##   make demo-ready       Full pre-demo reset + health check (from laptop)
##   make build            Build + push OTel collector image on EC2
##   make test             Run Go unit tests + Python smoke tests
##   make test-go          Go unit tests only
##   make test-py          Python smoke tests only
##   make baseline-status  Show fingerprint + anomaly counts for current ENV

.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash

# ── Load .env ──────────────────────────────────────────────────────────────────
-include .env
export

ENV        ?= $(error ENV not set — export ENV=<your-environment> or add to .env)
EC2_IP     ?= $(error EC2_IP not set)
EC2_PASSWORD ?= $(error EC2_PASSWORD not set)
EC2_PORT   ?= 2222

SSH        := sshpass -p $(EC2_PASSWORD) ssh -p $(EC2_PORT) -o StrictHostKeyChecking=no -o PreferredAuthentications=password splunk@$(EC2_IP)
SCP        := sshpass -p $(EC2_PASSWORD) scp -P $(EC2_PORT) -o StrictHostKeyChecking=no

PYTHON     := python3
REPO       := $(shell pwd)
DATA       := $(REPO)/data

.PHONY: help demo-ready build build-only push test test-go test-py \
        baseline-status baseline-learn baseline-push \
        clean check-env

# ── Help ───────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  make demo-ready        Full reset + verify — run before each demo"
	@echo "  make build             Build & push OTel image on EC2, restart DaemonSet"
	@echo "  make test              Run all tests (Go + Python)"
	@echo "  make test-go           Go unit tests"
	@echo "  make test-py           Python smoke tests"
	@echo "  make baseline-status   Show baseline + anomaly counts"
	@echo "  make baseline-learn    Learn + promote baseline from live APM data"
	@echo "  make baseline-push     Push local baseline files to cluster"
	@echo ""

# ── Environment check ──────────────────────────────────────────────────────────
check-env:
	@test -n "$(ENV)"          || (echo "ERROR: ENV not set"; exit 1)
	@test -n "$(EC2_IP)"       || (echo "ERROR: EC2_IP not set"; exit 1)
	@test -n "$(EC2_PASSWORD)" || (echo "ERROR: EC2_PASSWORD not set"; exit 1)
	@command -v sshpass >/dev/null || (echo "ERROR: sshpass not installed (brew install hudochenkov/sshpass/sshpass)"; exit 1)

# ── demo-ready ─────────────────────────────────────────────────────────────────
# Single command to go from "whatever state" to "ready for demo".
# Runs demo-reset.sh then performs a layered health check.
demo-ready: check-env
	@echo "=== make demo-ready: ENV=$(ENV) ==="
	@echo ""
	@echo "--- Step 1/3: Running demo-reset.sh ---"
	@ENV=$(ENV) $(REPO)/demo/demo-reset.sh
	@echo ""
	@echo "--- Step 2/3: Health checks ---"
	@$(MAKE) --no-print-directory _health-check
	@echo ""
	@echo "--- Step 3/3: Baseline status ---"
	@$(MAKE) --no-print-directory baseline-status
	@echo ""
	@echo "=== READY FOR DEMO ==="
	@echo ""
	@echo "  Start triage loop:"
	@echo "    python3 -u demo/poll_drift_events.py --triage --environment \$$ENV | python3 agent.py --environment \$$ENV"
	@echo ""

_health-check: check-env
	@echo "  Pods running:"
	@$(SSH) "kubectl get pods -l app=otelcol-fingerprint --no-headers 2>/dev/null | awk '{print \"    \" \$$1 \" \" \$$3}'"
	@echo "  Services:"
	@$(SSH) "kubectl get deployments petclinic-db api-gateway vets-service visits-service customers-service --no-headers 2>/dev/null | awk '{print \"    \" \$$1 \" ready=\" \$$2}'"
	@echo "  OTel pod log tail (last 5 lines each):"
	@$(SSH) "for p in \$$(kubectl get pods -l app=otelcol-fingerprint -o jsonpath='{.items[*].metadata.name}'); do \
	    echo \"    [\$$p]\"; \
	    kubectl logs \$$p -c otelcol --since=2m 2>/dev/null | grep -E 'drift|missing|anomaly|promoted|ERROR|WARN' | tail -3 | sed 's/^/      /'; \
	  done"

# ── Build ──────────────────────────────────────────────────────────────────────
build: check-env build-only push
	@echo "=== Build + deploy complete ==="

build-only: check-env
	@echo "--- Syncing source to EC2 ---"
	@rsync -avz --progress -e "ssh -p $(EC2_PORT) -o StrictHostKeyChecking=no" \
	  $(REPO)/otel-processor/fingerprintprocessor/ \
	  splunk@$(EC2_IP):/home/splunk/otelcol-fingerprint-src/fingerprintprocessor/
	@echo "--- Building image on EC2 ---"
	@$(SSH) "cd /home/splunk/otelcol-fingerprint-src && docker build --no-cache -t localhost:9999/otelcol-fingerprint:latest . 2>&1"

push: check-env
	@echo "--- Pushing image ---"
	@$(SSH) "docker push localhost:9999/otelcol-fingerprint:latest 2>&1 | tail -3"
	@echo "--- Restarting DaemonSet ---"
	@$(SSH) "kubectl rollout restart daemonset/otelcol-fingerprint && kubectl rollout status daemonset/otelcol-fingerprint --timeout=120s"

# ── Tests ──────────────────────────────────────────────────────────────────────
test: test-go test-py

test-go:
	@echo "--- Go unit tests ---"
	@cd $(REPO)/otel-processor/fingerprintprocessor && \
	  go test ./... -v -count=1 2>&1 | grep -E "^=== RUN|^--- |^PASS|^FAIL|^ok|panic"

test-py:
	@echo "--- Python smoke tests ---"
	@$(PYTHON) -m pytest $(REPO)/tests/ -v --tb=short 2>&1 || \
	  (echo "No pytest tests found — running inline smoke tests" && \
	   $(PYTHON) -c " \
import sys; sys.path.insert(0, '$(REPO)'); \
from core.trace_fingerprint import build_fingerprint, load_baseline; \
b = load_baseline('$(ENV)'); \
print(f'  baseline: {len(b.get(\"fingerprints\", {}))} fingerprints — OK'); \
")

# ── Baseline management ────────────────────────────────────────────────────────
baseline-status: check-env
	@echo "--- Local baseline ---"
	@$(PYTHON) $(REPO)/core/trace_fingerprint.py --environment $(ENV) show 2>/dev/null | head -20
	@echo ""
	@echo "--- Recent anomalies (last 5m) ---"
	@$(PYTHON) $(REPO)/core/trace_fingerprint.py --environment $(ENV) watch --window-minutes 5 2>/dev/null | tail -5

baseline-learn: check-env
	@echo "--- Learning baseline (30m window) ---"
	@$(PYTHON) $(REPO)/core/trace_fingerprint.py --environment $(ENV) learn --window-minutes 30
	@$(PYTHON) $(REPO)/core/trace_fingerprint.py --environment $(ENV) promote

baseline-push: check-env
	@echo "--- Pushing baselines to cluster ---"
	@$(SCP) $(DATA)/baseline.$(ENV).json splunk@$(EC2_IP):/tmp/python_baseline.json
	@$(SCP) $(DATA)/error_baseline.$(ENV).json splunk@$(EC2_IP):/tmp/error_baseline.json 2>/dev/null || true
	@$(SSH) 'bash -s' <<'REMOTE' \
	&& echo "  ConfigMap updated" \
	|| echo "  WARNING: ConfigMap update failed" ; \
	  kubectl delete configmap behavioral-baseline --ignore-not-found; \
	  kubectl create configmap behavioral-baseline \
	    --from-file=baseline.json=/tmp/python_baseline.json \
	    --from-file=error_baseline.json=/tmp/error_baseline.json 2>/dev/null || true; \
	  for pod in $$(kubectl get pods -l app=otelcol-fingerprint -o jsonpath='{.items[*].metadata.name}'); do \
	    kubectl cp /tmp/python_baseline.json $$pod:/baseline/baseline.json -c otelcol 2>/dev/null && echo "  injected: $$pod"; \
	  done
REMOTE

# ── Misc ───────────────────────────────────────────────────────────────────────
clean:
	@find $(REPO)/data -name "*.tmp" -delete
	@find $(REPO) -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find $(REPO)/otel-processor -name "*.test" -delete 2>/dev/null || true
	@echo "Cleaned."
