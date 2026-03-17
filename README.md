onboard.py is the controller. It owns a state file (onboarding_state.json) and runs on a schedule:

bash# Daily cron — fully automatic
0 6 * * * cd /opt/behavioral-baseline && python onboard.py --auto >> onboard.log 2>&1

# After a deployment in CI/CD
python onboard.py --environment $DEPLOY_ENV

# Preview without changes
python onboard.py --auto --dry-run

The three things it handles automatically:
New environment — a deployment.environment value appears in APM that's not in the state file → runs provision_detectors.py --environment <env> then trace_fingerprint.py --environment <env> learn
Updated environment — services have been added or removed since last run (configurable threshold via SERVICE_CHANGE_THRESHOLD) → re-runs the same provisioning and re-baselining. The --teardown + recreate cycle ensures detectors stay accurate as the topology evolves.
Removed environment — an environment that was active is no longer seen in APM → optionally tears down its detectors (--teardown-removed flag, off by default to be safe).
Every action emits an AUDIT category custom event to Splunk (behavioral_baseline.onboarded, behavioral_baseline.torn_down) so the onboarding history is itself observable in your platform.
