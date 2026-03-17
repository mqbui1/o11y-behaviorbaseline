# Daily cron — fully automatic
0 6 * * * cd /opt/behavioral-baseline && python onboard.py --auto >> onboard.log 2>&1

# After a deployment in CI/CD
python onboard.py --environment $DEPLOY_ENV

# Preview without changes
python onboard.py --auto --dry-run
