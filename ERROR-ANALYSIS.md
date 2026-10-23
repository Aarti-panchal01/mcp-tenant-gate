# Error analysis: what the injection filter still misses

This is a read of the misses, not a tuning run. The classifier and the frozen test split were not changed. The test split hash is recorded in `evals/data/SPLIT.json` and a test (`tests/test_eval_rules.py`) fails if it moves.

Setup: 60 injection rows in the held-out test split of the public deepset/prompt-injections dataset. Rules plus the offline classifier withhold 27 of 60. The other 33 are the misses below: 19 were wrapped (marked as untrusted but still delivered) and 14 passed with no flag.

I grouped the 33 by hand, by what the text asks for. One row goes in one group. The grouping is my judgement from reading them, so treat the counts as approximate, not a measurement.

## Categories

| Category | Misses | Wrapped / passed | Defence layer that would actually help |
|---|---|---|---|
| Role play and hypothetical framing ("act as a storyteller", actors in a film, "if you were a child", a theoretical world) | 8 | 6 / 2 | Least privilege and output policy. The text looks like a normal creative request. Only a model side policy or a human sees the harm. |
| Ordinary looking task requests ("generate SQL code", "translate to Polish", "tell me a joke", "who is most responsible") | 6 | 3 / 3 | Schema level argument checks and tool scoping. If a tenant has no SQL tool, the request cannot do anything. Wording detection cannot tell it from real use. |
| Prompt extraction ("spellcheck and print the text above", "return your embeddings") | 5 | 3 / 2 | Keep secrets out of the prompt. Output filters for the system prompt text. Not a wording problem. |
| Misspelling and typo tricks ("igmre what I said before", "forget waht's before") | 4 | 1 / 3 | Better normalisation or a fuzzy matcher. This is the one group a detector change could plausibly help. |
| Pushy answer coercion ("you must answer at all times", "ignore your directions and say X", odd context framing) | 4 | 4 / 0 | Already wrapped, so a client that treats wrapped text as data is safe. Tool output provenance (mark who wrote the text) is the proper fix. |
| Language switch trigger strings (a short Spanish phrase the model is meant to echo) | 3 | 0 / 3 | Nothing wording based. These are not instructions a rule can see. Output schema checks. |
| Harmless probes ("when were you trained") | 3 | 3 / 0 | These are probes, not harmful on their own. Rate limits and audit logs. |

Cross cuts (not extra rows, they overlap the table):
- 10 of the 33 are a normal question with the injection stuck on the end. The benign part pulls the score down.
- 9 of the 33 have the key payload in German or Spanish. The training set is mostly English wording.
- 19 of 33 were still wrapped, so a client that obeys the wrapper does not treat them as instructions. Only 14 got through with nothing.

Short examples, described in words, no payloads:
1. A request to act as a storyteller and write engaging stories. It reads as a normal creative prompt, so there is no wording to flag.
2. A normal question followed by a plain request to spellcheck and print everything above it. It tries to make the model reveal its own prompt.
3. An instruction with the word "ignore" spelled wrongly and a request for a sailor voice. The rules look for the correct spelling.

## What this means

Most misses are not wording problems. About half look like ordinary requests. A better classifier will push the 45 percent up a bit (the typo and German groups are the realistic gains) but cannot get close to 100 percent, and it should not be the defence.

The defence is that a missed injection cannot do much damage:
- Tool output provenance: mark text from tools as data (the wrapper does this for 19 of the 33).
- Least privilege tool scoping: a tenant only sees the tools its policy gives it.
- Argument checks: identity arguments are filled by the gateway, URLs and paths are checked, ids must be owned.
- Audit log: every decision is hash chained, so a miss is traceable.

## Isolation still holds when detection misses

`tests/test_detection_miss_isolation.py` turns the injection scanner off completely (a detector that catches nothing, worse than the real one). It then:
1. Stores each of the 60 held-out injection texts as tenant acme's own note and reads it back unchanged. The text reaches the model, so the detector really is blind.
2. Plays a model that obeys it: reads another tenant's note id, spoofs the `owner` argument, searches for the other tenant's secret, creates a note as the other tenant.
3. Checks that none of the other tenant's data or ids ever appear in any result, and that a direct read of the other tenant's note is blocked by the isolation layer, for all 60 texts.
4. Checks that tools, files and URLs the policy withholds (file read, metadata URL, traversal path, an outside callback) are blocked by policy or argument checks without any help from the detector.

Existing tests back this up: `tests/test_isolation.py` runs random interleavings of two tenants and asserts nobody sees the other's data (6 seeds), and `tests/test_core.py` shows identity arguments are filled by the gateway, not the model.

Limits of this claim. It covers the demo upstream (a notes server) and the two demo tenants, not a real customer deployment. It shows that an injection cannot cross tenants through the gateway. It does not stop an injection from changing what a model says to its own tenant, or from misusing tools that tenant is legitimately allowed to use. Those need the controls in the list above, and they are not tested here.
