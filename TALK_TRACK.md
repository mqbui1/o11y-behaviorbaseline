# Behavioral Anomaly Detection Framework — Talk Track

---

## Slide 1 — Title

> "Today I want to show you something I built on top of Splunk Observability APM — a behavioral anomaly detection framework that catches the class of failures that standard metric-based alerting completely misses.
>
> It's powered by Claude running on AWS Bedrock, and it runs autonomously — no threshold tuning, no YAML, no alert rule configuration. Let me walk you through what it is and then show it live."

---

## Slide 2 — The Gap in Standard Alerting

> "APM AutoDetect is great. It covers error rate spikes, latency drift, request rate anomalies — and it fires automatically for every environment with no configuration. But there's a whole class of failure it can't see.
>
> Take these four scenarios. First: a service that always appeared in your traces just disappears. No error rate increase, no latency spike — just structural silence. Metrics look fine. AutoDetect has nothing to fire on.
>
> Second: a brand new exception type fires for the very first time. Threshold alerting requires a baseline rate to compare against — there is none. You'll only find out when a user reports it.
>
> Third: a request now flows through a service it never touched before. Could be a mis-deploy, could be a new dependency silently added to production.
>
> And fourth: a service that always called the database stops doing so. Again — no error, no latency change. Just behavioral silence.
>
> These are the failures this framework is designed to catch."

---

## Slide 3 — Detection Tier Model

> "The framework adds two new detection tiers on top of what AutoDetect already provides, and then correlates across all of them.
>
> Tier 1 is AutoDetect — already built into Splunk, always on, covers error rate, latency, and request rate. It consumes those incidents as inputs.
>
> Tier 2 is trace path drift. The framework learns the structural fingerprint of every service — which services always appear in traces, what call paths are normal — and watches for deviations every five minutes. Missing service, unknown path, unexpected extra hops.
>
> Tier 3 is error signature drift. It learns every known exception type per service. The first time a new one appears, it fires immediately — before you'd have any rate to threshold against.
>
> And then there's correlation. When two or more tiers fire on the same service, correlate.py emits a single high-confidence event. Tier 2 plus Tier 3 on the same service is Major. When all three tiers fire simultaneously — that's MULTI_TIER Critical. That's what you'll see in Demo 4."

---

## Slide 4 — What the Framework Does

> "So concretely — what does it learn, and what does it detect?
>
> From the left: it learns once, from your live traffic. Every service-to-service call path. Every error signature per service. Normal span count ranges. Which services always appear in which trace types.
>
> On the right — every five minutes, autonomously: it checks for missing services, unknown paths, new error types. When two or more tiers fire on the same service, it emits a correlated alert. And if that anomaly happened within 60 minutes of a recorded deployment, it annotates with that context and can downgrade the severity.
>
> And the baseline self-heals. After an incident resolves, it finds the clean pre-incident window and re-learns automatically."

---

## Slide 5 — How It Works

> "The pipeline is four stages.
>
> Learn: it samples live traces from Splunk APM and builds structural fingerprints and error baselines from real traffic. This runs once on onboarding and then nightly to keep up with normal evolution.
>
> Watch — every five minutes: it compares incoming traces against the baseline. Any deviation emits a custom event to Splunk.
>
> Correlate — also every five minutes: it joins Tier 1, 2, and 3 events by service and time window. This is where MULTI_TIER is determined. Deployment events from the CI/CD hook are pulled in here as well.
>
> And finally the AI agent — on demand: Claude on AWS Bedrock reads all the correlated signals, reasons holistically across them, and outputs a plain-English verdict: severity, root cause, affected services, recommended action.
>
> The bottom note is important: Tier 1 runs for free, for all your APM environments, with no configuration on your part."

---

## Slide 6 — Built on Top of APM AutoDetect

> "This isn't a replacement for AutoDetect — it's built on top of it. The left column is what AutoDetect already gives you, for free, for every environment. Error rate, latency, request rate. Always on.
>
> The right column is what this framework adds: structural trace path drift, missing services, first-occurrence errors, cross-tier correlation, deployment-aware severity, auto-promotion of new baseline patterns, self-healing, and Claude-generated triage and runbooks.
>
> Think of it as the structural and behavioral layer that sits above the metric layer."

---

## Slide 7 — Key Capabilities

> "Six capabilities worth calling out specifically.
>
> Zero configuration: no alert rules, no thresholds, no YAML. You run one command. The framework learns from your live traffic and is operational within minutes.
>
> First-occurrence detection: this is unique. It fires the moment a new error signature or new trace path appears — before any rate exists to compare against. You catch the first occurrence, not the hundredth.
>
> Claude-powered triage: instead of getting a raw alert, your on-call engineer gets a synthesized verdict — severity, likely root cause, affected services, and a recommended action. All generated by Claude from the actual signal data.
>
> Deployment-aware: one-line CI/CD hook. Any anomaly within 60 minutes of a recorded deploy gets annotated and severity-downgraded automatically. Fewer false pages.
>
> Auto-onboarding: runs every 30 minutes. New environments appear, get baselined, get a dashboard, get cron jobs, get a runbook — no human involvement.
>
> Self-healing: new patterns after a deploy auto-promote themselves after two clean watch runs. And after an incident, the baseline re-learns from the pre-incident clean window."

---

## Slide 8 — Demo Environment: Spring PetClinic

> "Before I walk through the demos, let me orient you to the application they all run against.
>
> This is Spring PetClinic — a standard Java microservices reference app, deployed on Kubernetes using k3d on an EC2 instance. It's a realistic multi-service topology: seven services, a shared MySQL database, and a continuous load generator hitting it every five seconds.
>
> At the infrastructure layer: config-server centralizes Spring Cloud Config, discovery-server runs Eureka for service registration, and admin-server provides operational dashboards. These are the plumbing — they don't handle business traffic directly.
>
> The public entry point is api-gateway — everything flows through here. It fans out to three business services: customers-service manages owner and pet profiles, vets-service serves the veterinarian catalog, and visits-service handles appointment records. All three talk to a shared MySQL database.
>
> Every service is instrumented with the Splunk OpenTelemetry Java agent, injected automatically via the OTel Operator on Kubernetes. Traces and metrics flow continuously to Splunk Observability Cloud, tagged to the environment petclinicmbtest.
>
> This is what the behavioral baseline learns from. When I run a demo — kill vets-service, crash the DB, push a bad deploy — these are the services that change. The framework knows the normal call graph and fires when it deviates."

---

## Slide 9 — Demo Agenda

> "Here's what I'll walk through today.
>
> Demo 0 is steady state — baseline learned, cron running, zero anomalies. Just to show you what clean looks like.
>
> Demo 1 is a database outage. The DB goes down, a new exception fires for the first time. Claude calls INCIDENT, PAGE_ONCALL — immediately, on the first occurrence.
>
> Demo 2 is a bad deploy — visits-service crashes on startup. No threshold exceeded, just a structural change in trace behavior.
>
> Demo 3 is a missing service. vets-service is killed. The framework detects its structural absence from traces, and Claude produces a root cause and recommended action.
>
> Demo 4 is the big one — all-tier correlation. Both vets-service and the database are down simultaneously. AutoDetect fires, trace path drift fires, error signatures fire — and correlate.py emits a Critical MULTI_TIER event.
>
> Demo 5 is deploy-correlated severity downgrade — the framework finds the deployment event and downgrades the alert automatically.
>
> Demo 6 is self-healing — a new call path is auto-promoted after two clean runs.
>
> And Demo 7 is auto-onboarding — a new environment discovered, fully operational in 60 seconds."

---

## Slide 10 — Live Demo

> "Alright — let's see it live."

*(Switch to terminal / demo environment)*

---

## Slide 11 — Product Proposal

> "So the ask here isn't 'can I run this in one environment.' The ask is: should this become a native capability inside Splunk Observability Cloud?
>
> Everything you've seen today is a proof of concept — running as a Python script against your APM APIs. But the detection logic, the baseline model, the correlation engine, the AI triage — all of it maps directly onto capabilities the platform already has. This is a productization proposal.
>
> Three pillars.
>
> First: native platform integration. Behavioral baseline learning built into APM onboarding — not a script you run, a toggle you enable. Detections surface as first-class alerts in the Splunk UI alongside AutoDetect alerts, with the same notification routing, the same PagerDuty and Slack integrations, the same muting and SLO wiring.
>
> Second: AI triage as a product feature. The Claude-generated verdict — severity, root cause, recommended action — becomes the 'Explain this alert' experience inside the alert detail view. Every INCIDENT gets a triage summary and a generated runbook attached automatically.
>
> Third: differentiation. AutoDetect covers the metric layer. Every observability vendor covers the metric layer. Structural and behavioral detection — catching the failures that leave no metric fingerprint — is a defensible, differentiated capability. No threshold to tune. Fires on the first occurrence. Self-healing baseline.
>
> The proof of concept is working in production today. The question for this group is: what does the path to native look like?"

---

## Timing Guide (45-minute session)

| Section | Content | Time |
|---------|---------|------|
| Slides 1–3 | Title, Problem, Tiers | 5 min |
| Slides 4–7 | Solution, Architecture, AutoDetect, Capabilities | 8 min |
| Slide 8 | PetClinic topology overview | 2 min |
| Slide 9 | Demo agenda | 1 min |
| Demos 0–2 | Steady state, DB outage, bad deploy | 8 min |
| Demo 3 | Missing service + AI triage | 5 min |
| Demo 4 | All-tier correlation (MULTI_TIER) | 5 min |
| Demos 5–7 | Deploy downgrade, self-healing, auto-onboard | 6 min |
| Slide 11 | Product Proposal + Q&A | 10 min |

---

## Key Lines to Land

- *"Standard alerting needs a rate to threshold against. This framework fires on the first occurrence — before the rate exists."*
- *"Metrics look fine. AutoDetect has nothing to fire on. But the behavior has changed."*
- *"One command. The framework learns from your live traffic. No thresholds, no YAML, no alert rules to write."*
- *"Demo 4: three independent detection systems fire on the same service at the same time. That's MULTI_TIER Critical — the highest confidence signal the framework can produce."*
- *"Your on-call engineer doesn't get a raw alert. They get a verdict."*
