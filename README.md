# grc-engineering-lab

**A library of API-provable SOC 2 controls, orchestrated by an AI agent.**

*API-collected evidence. SHA-256 manifests. Zero screenshots.*

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat&logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-FF9900?style=flat&logo=amazonwebservices&logoColor=white)
![Anthropic Claude](https://img.shields.io/badge/Anthropic_Claude-D97757?style=flat&logo=anthropic&logoColor=white)
![Boto3](https://img.shields.io/badge/Boto3-0073BB?style=flat&logo=amazonwebservices&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)
![SOC 2](https://img.shields.io/badge/SOC_2-Type_I%2FII-2E7D32?style=flat)

---

## What this is

This repo is a working lab for GRC engineering. Each subdirectory is a standalone control check that produces auditor-grade evidence by calling APIs directly. On top of the control library sits an AI agent that reasons about compliance objectives and orchestrates which controls to run.

The goal is simple: prove that SOC 2 evidence can be collected, verified, and packaged without a human ever taking a screenshot.

## Why this exists

Traditional SOC 2 evidence collection is compliance theater. An auditor asks for proof that MFA is enforced. Someone opens the IAM console, takes a screenshot, pastes it into a shared drive, and calls it evidence. The screenshot proves nothing. It could be stale, cropped, edited, or from a different account. The control was never actually verified. It was attested to.

GRC engineering rejects that. If a control can be proven, it should be proven by pulling raw state from the system of record, hashing the result, and storing it alongside a manifest that an auditor can independently verify. The evidence is the API response, not a picture of a webpage.

This repo is an argument for that position, expressed as code.

## How it works

The architecture has two layers.

**The control library.** Each subdirectory (`s3_public_access/`, future labs) is an independent, runnable tool that implements one or more control checks. Each tool reads state from APIs, evaluates it against a defined standard, and produces a deterministic evidence pack: `findings.json`, a human-readable report, an IAM policy showing the permissions used to collect the evidence, and a `manifest.json` with SHA-256 hashes of every artifact. The pack is zipped with a sidecar `.sha256` so integrity is verifiable without trusting the zip metadata.

Tools have no knowledge of the agent. They are pure functions from AWS state to evidence packs. They can be run standalone from a cron job, a CI pipeline, or a human at a terminal.

**The agent layer.** The `soc2_evidence_agent/` directory contains an AI agent (built on the Anthropic SDK) that takes a compliance objective from the user, for example "prepare evidence for CC6.1," and plans which tools to invoke. The agent uses Claude's tool-use API to call the control library, collect results, and assemble a control-level evidence pack that spans multiple tools. The agent is also explicit about scope: it produces a `scope.json` artifact declaring what was tested, what was deliberately excluded, and why.

The agent is the only component that reasons. The tools are deterministic. That separation is intentional: auditable systems require deterministic primitives, and auditable agents require a clear boundary between what the LLM decides and what the code actually did.

## Design principles

1. **API-provable only.** If a control cannot be proven by pulling state from an API, it does not belong in this library. Process evidence, attestations, and screenshots are out of scope by design.
2. **Tools do not know about the agent.** Every tool is independently runnable and reusable. The agent is a consumer of tools, not a coupling point.
3. **Every artifact is hashed.** SHA-256 manifests are the contract between the system and the auditor. An evidence pack that cannot be integrity-verified is not evidence.
4. **Honest scope.** The agent records what was excluded and why. Out-of-scope items are named explicitly, not quietly dropped.
5. **Frameworks are mappings, not abstractions.** Control IDs (CC6.1, CIS 2.1.4) are metadata attached to checks. The checks themselves are about system state, not about frameworks.

## What is in the repo today

### `s3_public_access/`
SOC 2 CC6.1 and CC6.6 coverage for S3 bucket exposure. Implements CIS AWS Foundations Benchmark v5.0.0 checks 2.1.4 and 2.1.5, plus a custom check for account-level Block Public Access (`EXT-ACCT-BPA-01`). Produces a complete evidence pack with IAM policy, findings JSON, markdown and PDF reports, and a SHA-256 manifest.

Run it standalone:
```bash
cd s3_public_access
python collector.py
python pack.py
```

### `soc2_evidence_agent/` (in development)
The orchestration agent. v1 targets CC6.1 (logical access), wrapping the S3 tool above plus IAM/MFA checks. The agent plans the evidence collection, invokes the relevant tools, and produces a control-level pack. See the sub-README for current status.

## Roadmap

Near term:
- Complete v1 of `soc2_evidence_agent` with CC6.1 coverage across S3 and IAM tools
- Add an IAM/MFA audit tool as a standalone lab
- Add a CloudTrail coverage tool as a standalone lab
- Expand agent coverage to CC6.6 and CC7.2

Longer term:
- Streamlit dashboard for evidence pack review
- Multi-control orchestration (agent prepares a full SOC 2 Type I evidence set)
- Framework expansion: the same tools mapped to ISO 27001, HIPAA, PCI DSS

No roadmap dates. Labs ship when they ship.

## Running a tool standalone

Every tool in the library is runnable without the agent. Each subdirectory has its own README with setup instructions, required IAM permissions, and expected outputs. If you only want to run one check against one AWS account, you do not need the agent at all.

## Running the agent

*(Placeholder until `soc2_evidence_agent/` v1 ships. Will document: required environment variables, Anthropic API key setup, AWS credential configuration, CLI invocation, and expected evidence pack structure.)*

## Contributing

This is a personal lab repo and a public portfolio, not an open-source product. Issues and discussion are welcome. Forks are welcome. Pull requests will be considered but may be closed if they do not fit the design principles above.

## Who builds this

Jacob Ferguson. Cybersecurity analyst, Rice MBA candidate, Navy veteran, GRC engineering practitioner. Building in public across GitHub, LinkedIn (@JfergITLife), and X (@JFergITLife).

## License

*(To be decided. Leaning MIT for the library, reserving rights on the agent layer pending scope decisions.)*
