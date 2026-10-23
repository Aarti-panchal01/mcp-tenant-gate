# What a small MCP gateway catches, and what it still misses

## The problem

MCP makes it easy to connect an AI agent to tools. Many teams connect agents to servers they did not write. Three things go wrong.

First, the tool list is text the model reads and trusts. A server can hide instructions in a tool description, or change a description after you approved it.

Second, tool results are untrusted text. A web page or a support ticket can say "ignore your earlier instructions". The model may follow it.

Third, most MCP servers are single tenant. They search all the data they hold. Put two customers behind one server and each can read the other's records.

## What the gate does

mcp-tenant-gate sits between the agent and its MCP servers. One API key maps to one tenant. The gate applies checks in a fixed order, cheap and certain ones first.

On the way in: a tool allowlist per tenant, guards against server-side request forgery and path traversal, identity arguments such as "owner" filled by the gate and never by the model, resource ids checked against a ledger of what the tenant created, and schema checks.

On the way out: a size cap, rows from other tenants dropped, personal data redacted or blocked, and an injection scan that withholds the result or wraps it in untrusted-data markers.

At tool listing time, every definition is scanned for hidden instructions and pinned with a SHA-256 hash. If a definition changes later, the tool is quarantined. Every decision goes to an append-only audit log with a hash chain.

## How it was tested

There are three kinds of test.

**Scripted attacks.** A suite runs 20 attacks against a deliberately malicious MCP server, plus 20 normal calls. I wrote these, so they show the checks work. They do not show the gate is hard to beat.

**A held-out split.** To get a number I did not write, I used a public prompt injection dataset (deepset/prompt-injections, 662 labelled rows). I used its own train and test split. I tuned the rules and trained the classifier on the train split only, then measured the test split: 60 injections and 56 normal chat rows. I also ran 2,808 paragraphs of ordinary Python library documentation as a false positive check.

**An offline classifier.** The second layer is a small linear model over word and character n-grams, plus text folding and decoding for look-alike letters and encoded payloads.

## Results

I reran everything for this write-up.

- Test suite: 151 tests pass.
- Scripted attacks: 20 of 20 blocked, 20 of 20 normal calls passed.
- Added latency: about 1 ms median per call.

On the held-out test split of 60 injections:

| | Rules only | Rules plus classifier |
|---|---|---|
| Withheld | 14 of 60 (23%) | 27 of 60 (45%) |
| 95% interval | 14 to 35% | 33 to 58% |
| Withheld or wrapped | 17 of 60 (28%) | 46 of 60 (77%) |

False blocks: 0 of 56 normal chat rows and 0 of 2,808 library documentation paragraphs, before and after. One chat row and six documentation paragraphs were wrapped with markers, not withheld.

The classifier withheld 13 more injections than the rules and lost none.

Read that plainly. The gate still lets through more than half of unseen injections: 33 of 60 are not withheld, and 14 of 60 are not even wrapped. With 60 injections, 45% means a third to a half.

## What it still misses

Three kinds of text get through. I describe them in words only.

- **Requests that look ordinary.** Many injections in the dataset are polite task switches, such as asking the model to write something unrelated after praising its last answer. Nothing in the wording looks like an attack.
- **Role play.** A prompt that sets up a fictional scene and asks the model to act inside it. The text reads like a story, not a command.
- **Other languages and paraphrase.** The rules and the model were trained mostly on English patterns. German rows were caught about as rarely as English ones, and any language not in the data is a bigger gap.


## What I would do next

1. Run the gate in observe mode on a customer's real tool results for a week. Read the false positives with their team before enforcing anything.
2. Build a test set of injections inside tool output, not chat prompts.
3. Measure an LLM judge as a third layer. It is built and unit tested, but I have not measured it.
4. Add an HTTP front so one process serves many tenants, with identity from the customer's login system.

## Limits

- The dataset is direct user prompts, not tool output. It has near-duplicate prompts such as translations, so train and test are closer than independent samples.
- The gate cannot see what a server does with its own credentials, network or disk. Servers still need least privilege.
- Auth is API keys only, and state is in memory.
- Written in a few hours as a work sample. Not audited.

The strongest controls here do not depend on wording: allowlists, forced identity, the ownership ledger, argument guards, size caps and pins. Wording based detection is a cheap extra layer, and the numbers above show how far to trust it.
