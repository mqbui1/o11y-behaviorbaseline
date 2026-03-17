# Once: build baseline from last 2 hours of traces
python trace_fingerprint.py learn --window-minutes 120

# Every 5 minutes via cron: check for drift
*/5 * * * * python trace_fingerprint.py watch --window-minutes 5
