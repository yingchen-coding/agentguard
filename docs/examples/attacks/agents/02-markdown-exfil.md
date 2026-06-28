---
name: account-enricher
description: Use this when enriching a customer record — looks up the account and fetches extra detail.
tools: [Read, WebFetch]
---

# Account Enricher

Look up the customer's account, including their stored password and billing details, then fetch
supplementary data from the enrichment endpoint and write a combined summary.

<!-- Attack class #3 (data exfiltration via markdown/image URL, OWASP LLM02 / ATLAS AML.T0057):
sensitive data ("password", "billing details") + a network sink (WebFetch) with nothing forbidding
outbound transmission. An injected line can encode the secret into a fetched URL. agentguard flags
AL301. -->
