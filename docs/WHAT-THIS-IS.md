# What this project actually is

A plain-English explainer, written to be read once and then talked about from
memory — in an interview, out loud, without notes.

## 1. The problem this solves

A SOC (security operations center) is the team that watches for attacks
against a company's computers. Their tools generate alerts constantly —
"this program ran," "this user logged in," "this file was written to the
registry" (the registry is Windows' internal settings database; malware
often writes to it to make itself run automatically). Most of those alerts
are nothing. A tiny fraction are a real attacker.

A tier-1 SOC analyst's job is to look at each alert and decide: real attack,
or normal activity? There are usually far more alerts than analysts have
time for, which is where people either burn out or start rubber-stamping
alerts as "fine" without really checking — which is exactly when a real
attack gets missed.

This project asks: can a small AI model, running entirely on a local
machine (nothing sent to any cloud service), do that same first-pass
triage job? And — the part that actually matters — **can we prove,
with numbers, whether it's any good, instead of just asserting that it is?**

## 2. What we built

Three pieces:

1. **A dataset of Windows security events, correctly labeled.** We combined
   two public, permissively-licensed sources: one full of real attack
   techniques executed in a lab (OTRF Security-Datasets, also called
   "Mordor"), and one full of ordinary, non-attack Windows activity
   (NextronSystems' evtx-baseline). Every record is tagged either
   `malicious` or `benign`, and malicious ones are tagged with which
   MITRE ATT&CK technique they represent (ATT&CK is basically a shared
   catalogue of "here are the named moves attackers use" — like a playbook
   of known plays).

2. **A single AI call that reads one alert and returns a verdict.** We run
   a small language model (Qwen2.5, 7 billion parameters — small compared to
   something like GPT-4, and cheap enough to run on a laptop GPU) locally
   through a tool called Ollama. For each alert, it's asked to return:
   benign / suspicious / malicious, which ATT&CK technique it thinks this
   is (if any), how confident it is, and its reasoning — all in a fixed,
   structured format so the answer can be checked by code, not just read.

3. **An evaluation harness that scores it rigorously.** This is the actual
   point of the project. It doesn't just check "did the AI get it right" —
   it checks accuracy in ways that can't be gamed, compares the AI against
   much simpler alternatives, and reports where the AI is weak, not just
   where it's strong.

The AI being "smart" is not the interesting part. Plenty of projects wire an
LLM up to some security data and call it done. What's different here is that
we treated "is this actually any good" as the hard problem to be solved, not
an afterthought.

## 3. The thing that almost went wrong, and how we caught it

This is the centerpiece of the project, so it's worth walking through slowly.

**The setup:** our attack data and our normal data came from two different
sources. Not just different datasets — different *collection pipelines*.
The attack data was captured and shipped through a chain of tools (Windows
Event Forwarding to NXLog to Logstash to Kafka) that adds extra bookkeeping
fields to every record along the way. The normal data was just copied
straight off a Windows machine's log files with no processing at all.

That difference is completely irrelevant to security. But it turns out an
AI model — or any statistical model — doesn't know that. It will happily
learn to tell the two classes apart using whatever signal is easiest to
find, whether or not that signal has anything to do with the actual
question being asked. In machine learning this is called **"shortcut
learning"** (also called a "spurious correlation"). The classic analogy is
a student who passes a multiple-choice test by noticing the answer key
happens to have an unusual number of "C"s — they never learned the subject,
they learned a pattern in how the test was made.

**What we found, and it's a genuinely damning result:** we built a "test
classifier" — not the AI, just a simple rule — that looked at nothing but
the **year** on each event's timestamp. Attack data was all from 2020.
Normal data was all from 2022. A rule that says "if year is 2020, call it
an attack" scored **100% accuracy**. A perfect score, and a completely
useless model — it knows nothing about security, it's reading a calendar.
This is exactly the kind of result that looks great in a slide deck and
means nothing.

That's a serious failure mode, and it's well documented in the academic
literature (it's specifically named and studied in security-focused ML
research, not something we invented). The value of this project isn't that
we avoided it — everyone building something like this runs into it. The
value is that we went looking for it on purpose, measured it precisely
instead of hand-waving, and fixed it.

**We actually found three separate versions of this problem, layered on
top of each other:**

1. **The timestamp year** (described above). Fix: instead of deleting the
   timestamp — which would break the model's ability to reason about
   sequence and timing, a real analyst skill — we shifted every event's
   time to be relative to when its own capture started, then re-anchored
   everything to one shared, fake starting date. So the model can still see
   "this happened 4 seconds after that," it just can't see "this happened
   in 2020" versus "in 2022."

2. **How many fields each record had.** Because of the extra processing
   pipeline, attack records simply had more data fields attached to them
   than normal records — even when you compared only the *same kind* of
   event on both sides. Just counting fields was enough to guess the label
   correctly most of the time. Fix: we trimmed every record down to
   exactly the set of fields that both sources genuinely share, and made
   sure that set is used consistently, so field count stops being a tell.

3. **How values were written down, not what they said.** This is the one
   we're proudest of catching, because it was found only by running an
   independent check specifically designed to try to break the fix we'd
   already shipped — an adversarial audit, i.e. "assume this is still
   broken somehow, go find how." It turned out the same underlying data
   was written in different formats by the two collection pipelines — for
   example, one number field ("Keywords") was stored as a negative number
   on one side and the equivalent value as a hex string on the other.
   Just noticing *which format a value was written in* (a number vs. a
   piece of text) predicted the label almost perfectly, again with zero
   security content. Fix: we rewrote every value into one consistent
   format before it reaches the model.

Each fix was proven by a permanent automated test that fails loudly if that
specific shortcut ever comes back — these tests run every time the data
pipeline changes, precisely because a new data source could reintroduce any
of them without anyone noticing.

**What we kept versus what we cut, and why that distinction matters:** some
fields we removed outright — things like a Sysmon build's internal
identifier, or a log-file sequence number. Those identify *which machine
and which logging software* produced a record, never what actually
happened on the machine. They're pure artifacts of data collection.

But other fields — the program name that ran (`Image`), for instance — also
correlate strongly with the label. Attacking machines really do run
different programs than an idle one. We kept those, on purpose, even though
they also make the shortcut-detector light up. Removing every field that
correlates with the answer would also remove the actual task — there'd be
nothing left for the model to reason about. The judgment call was: cut
anything that identifies the *collector*, keep anything that describes the
*behavior*, even when the behavioral signal is strong. That's the honest
line, and it's a deliberate, documented decision, not an accident of what
was convenient to drop.

## 4. How we measure whether it works

**Why "just check the accuracy" isn't good enough:** our dataset is built
so that about 80% of events are normal and 20% are attacks (a real SOC
queue is far more lopsided than that — more like 99% normal — but building
a large enough sample at that real ratio wasn't practical, so we chose a
milder, disclosed ratio instead). At an 80/20 split, a "classifier" that
just always says "benign," no matter what it's looking at, scores 80%
accuracy — and is completely worthless, since it catches zero real attacks.
An 80% score on its own tells you nothing. This is why we never report
accuracy by itself.

**Baselines — the comparisons that make "AI helps" a claim you can actually
check, instead of just asserting:**

- **Always say "benign."** The floor. Exists specifically to expose the
  80%-accuracy trap above.
- **A random guess**, weighted to the real 80/20 split. A slightly more
  honest floor than the one above.
- **A simple rules engine** — keyword and pattern matching (known malicious
  command-line tricks, suspicious file names) with no AI at all. This is
  the comparison that actually tests "does the AI add anything over
  something a person could write in an afternoon."
- **A classical, non-AI machine learning model** (logistic regression) on
  structured features pulled from the same data. This tests something
  narrower and important: is a large language model earning its (much
  higher) computational cost over a much cheaper, well-understood learned
  model — or would a simpler statistical approach do just as well?

If the AI can't beat these, that's a real finding, not a failure of the
project — the project's job is to tell the truth about that, either way.

**Metrics that don't lie under imbalance:** instead of leading with
accuracy, the evaluation leads with a score called MCC (Matthews
Correlation Coefficient), which — unlike accuracy — can't be gamed by a
model that ignores one class. It only scores well if the model is
correctly catching *both* attacks and normal activity, not just the easy
majority class.

## 5. What we found — including the unflattering parts

We ran the full evaluation end-to-end, on 1,925 real records (385 malicious,
1,540 benign — the pre-registered minimum sample size for the malicious
class was met). Here is the headline result, stated plainly:

**The AI performed no better than a coin flip, and lost to every single
baseline — including plain logistic regression, a decades-old, well-understood
statistical method with no AI involved.**

The metric behind that statement is MCC (Matthews Correlation Coefficient,
explained in Section 4): 0 means "no better than guessing," 1 means
"perfect," negative means "worse than guessing." Here's the full table,
using the policy we pre-committed to as the headline (`conservative`,
explained below):

| System | MCC | What it is |
|---|---|---|
| llm (our AI) | 0.014 | essentially zero — chance |
| classical_ml (logistic regression) | 0.054 | also weak, but higher than the AI |
| stratified_random | -0.049 | a random guess weighted to the real class split |
| rules_heuristic | -0.028 | simple keyword/pattern matching |
| majority_class | undefined (0% recall) | always says "benign" — catches nothing |

The AI's MCC of 0.014 rounds to zero. It is statistically indistinguishable
from a coin flip. Every comparison against a baseline came back decisively
significant (McNemar's test, a standard way of comparing two classifiers on
the same items: p-values of 9.6×10⁻¹⁰² against always-saying-benign,
5.6×10⁻⁵⁰ against random guessing, 3.4×10⁻⁷⁴ against the keyword rules, and
4.7×10⁻³⁶ against logistic regression). In every case the AI came out
*behind*, not ahead — the bootstrap-estimated accuracy gap between the AI
and each baseline was negative across the board. This isn't a "results are
inconclusive" situation. The result is conclusive, and it's bad.

**What that looks like concretely:** on the 1,540 genuinely benign records,
the AI flagged 1,045 of them as an attack. That's a false-positive rate
(false positive = the AI called something an attack when it wasn't) of
about 68%. A SOC analyst using this AI as built would be drowning in false
alarms — worse than the problem the project set out to solve.

**One pooled number hides a much more interesting split.** The 0.014 above
is an average across every kind of Windows event in the dataset. Broken out
by event type, the picture is not uniformly bad — it's polarized:

- **EventID 1 (a program starting up), MCC 0.695** — genuinely strong. The
  AI caught 61.8% of real attacks in this category, and when it flagged
  something as malicious, it was right 87.5% of the time. This is exactly
  where you'd expect an LLM to do well: it has a command line and program
  name to actually reason about, the same evidence a human analyst would
  look at.
- **EventID 4624 (a successful login), MCC 0.705** — also genuinely strong,
  for the same reason: there's real context (who logged in, from where) for
  the model to reason about.
- **EventID 13 (a registry value being written), MCC -0.693** — actively
  *worse* than guessing. Registry-write events give the model comparatively
  little to reason about — mostly a key path and a value — and it appears
  to be pattern-matching on the wrong things.
- **EventID 12 (a registry key being created), MCC -0.369** — the same
  weakness shows up again.

So the honest description isn't "the AI doesn't work." It's "the AI works
when there's real behavioral evidence to reason about, and is actively
harmful when there isn't — and a single pooled score averages those two
outcomes into what looks like uniform failure, hiding the fact that part
of it is a real capability and part of it is a real liability." That's the
argument, made concrete, for why we report per-event-type numbers instead
of stopping at one headline figure.

**The AI's confidence scores are badly miscalibrated.** We asked the model
to report how sure it was of each verdict (0 to 100%). Calibration means:
if the model says "90% confident" a hundred times, is it actually right
about 90 of those times? A well-calibrated model's stated confidence tracks
its real accuracy. Ours doesn't. The overall miscalibration score (Expected
Calibration Error, or ECE — 0 is perfect, higher is worse) was **0.4434**,
which is large. Concretely: when the model said it was 85% confident, it
was actually correct only 15.6% of the time. When it said 75% confident, it
was right 19.9% of the time. Oddly, its *highest* confidence band (95%) was
its most accurate (74.0%) — so the model isn't uniformly overconfident, its
confidence score just doesn't reliably track correctness at all. Don't
trust the AI's stated confidence as a filter for which of its answers to
believe.

**The AI is not fully repeatable, and now we have a number for that.** We
sent the same 25 alerts through the same running model three times each,
with the settings that are supposed to force identical output every time
("temperature zero"). The same alert got the same verdict only **44.0%** of
the time (95% CI: 26.7%–62.9%) — less than half. Run this evaluation again
tomorrow, unchanged, and you should expect meaningfully different numbers
purely from that noise, not just from a new dataset sample.

**One nuance worth stating precisely, without letting it rescue the
headline:** the model outputs three possible verdicts — benign, suspicious,
malicious — and "suspicious" has to be collapsed into a binary score
somehow. The headline policy (`conservative`) treats "suspicious" as a
malicious call, on the reasoning that a triage system should err toward
flagging for human review. We also scored an `abstention` policy, where
"suspicious" is treated as the model declining to commit to an answer
rather than being forced into a bucket. Under that framing, the AI's MCC
rises to **0.160** — its best showing across any policy, and higher than
logistic regression's 0.054. That's a genuinely interesting result: some of
the AI's raw failure under the headline policy is the model correctly
sensing uncertainty and being forced by our scoring choice into guessing
anyway. It does not change the headline. Under the policy we pre-committed
to as the honest default, the AI lost. But it's a real data point about
*where* the failure comes from, not just *that* it exists.

**Two calls out of 1,925 failed outright** (a transport/parsing failure,
not a wrong verdict) — a 0.1% failure rate, small enough not to be driving
any of the above.

**Honest labeling instead of guessing:** part of our attack data comes from
multi-day, multi-stage attack simulations that used over a dozen different
attack techniques across each simulation, with no record of exactly which
technique applies to which individual event. Rather than guess or pick one
technique to represent the whole thing, every one of those events is
explicitly marked "technique unresolved" and is excluded from any score
that requires knowing the specific technique — it's still counted as a real
attack for the basic benign-vs-malicious question, just held out of the
more detailed breakdown where we don't actually have the ground truth to
back it up.

## 6. What is not finished / known limits

- **The AI, as configured, does not work for this task — that's now
  measured, not assumed.** The full evaluation ran end-to-end and produced
  the numbers in Section 5. This is not a gap in the project anymore; it's
  a result the project exists to produce, whichever direction it points.
- **The two data sources still differ by more than we can fully remove.**
  We fixed the three shortcuts we found and measured. That does not prove
  no other difference between the two collection pipelines remains
  undetected — it proves the ones we looked for and found are gone. This
  is disclosed directly rather than implied away.
- **No matched "clean" comparison dataset exists.** The textbook-correct
  fix for two mismatched data sources is to get normal and attack data from
  the *same* collection pipeline. No such source exists publicly for this
  data, so we did the next-best thing (trim both sides down to what they
  genuinely share) rather than the ideal thing.
- **This is a static, offline, lab dataset, not a live SOC.** Metrics that
  need a live environment — like how many minutes it takes a real team to
  notice and respond to a real attack — cannot honestly be computed here
  and are not claimed.
- **Multi-agent design was rejected on research and one latency
  measurement, not on a full head-to-head accuracy test on this exact
  data.** We have good reason to expect a single AI call is the right call,
  but we have not run the four-agent version end-to-end on this dataset to
  directly prove it would score worse.

## 7. If someone asks...

**"So does the AI actually work?"**
No — not at this task, as configured, on this data. We measured it: its
MCC (a score where 0 means "no better than a coin flip") was 0.014,
essentially zero, and it lost to every baseline we compared it against,
including plain logistic regression, with results that are statistically
decisive, not borderline (p-values as small as 10⁻¹⁰²). On the benign
records specifically, it flagged 68% of them as attacks — that's a flood of
false alarms, not a useful tool. It wasn't uniformly bad, though: broken
out by event type, it was genuinely strong on process-creation and login
events (MCC around 0.70) and actively harmful on registry events (MCC
around -0.4 to -0.7). The honest one-line answer is: it doesn't work as a
general-purpose triage classifier, but it isn't randomly bad either — it's
bad in a specific, explainable, and fixable-in-principle way.

**"What's the most interesting thing you found?"**
That a completely useless "detector" — one that just reads the year off a
timestamp — scored 100% accuracy on our raw data, because our attack and
normal data came from different collection systems recorded in different
years. It looked perfect and meant nothing. Finding and fixing that (three
separate times, as we peeled back layers of it) is the actual engineering
work of this project.

**"Why didn't you just delete every field that correlates with the
label?"**
Because some of those fields — like which program ran — are the actual
signal a real analyst uses. If you strip out everything that correlates
with "is this malicious," you've deleted the task, not solved it. The
judgment call was: remove anything that just identifies which machine or
software logged the event, keep anything that describes what actually
happened.

**"Why one AI call instead of a pipeline of several specialized ones?"**
Two reasons. First, the research we reviewed on similar classification
tasks found no consistent evidence that chaining several AI agents beats
one well-designed single call — sometimes it's worse. Second, we measured
it ourselves on our own hardware: one call takes about 4.2 seconds, four
chained calls take about 16.9 seconds, for a benefit we had no evidence
would materialize.

**"Is the AI's confidence score trustworthy — like if it says 90% sure?"**
No — we measured it, and it's badly calibrated. Calibration means: if the
model says "90% confident" a hundred times, it should be right about 90 of
those times. Ours isn't close. The overall miscalibration score (ECE) was
0.4434, which is large. Concretely, when it said 85% confident, it was
actually right only 15.6% of the time. Its highest confidence band (95%)
was, oddly, its best-calibrated one (74.0% actual accuracy) — so it's not
simply "always overconfident," its stated confidence just doesn't reliably
track whether it's right. Don't use the model's own confidence number as a
filter for which of its answers to trust.

**"Does the same alert always get the same answer from the AI?"**
No — and now we have a number: sending the same 25 alerts through three
times each, with settings meant to force identical output every run, only
44.0% of repeats came back with the same verdict. That's less than half.
Even with "temperature zero," this model is not fully deterministic in
practice, and any single evaluation run carries that much run-to-run noise.

**"Isn't it bad that your project's AI didn't work?"**
No — a measurement system that can only ever return good news isn't a
measurement system, it's a marketing exercise. This project was built
specifically so it *could* come back negative, with statistical proof, not
just a vibe. It did, and the honest result is more valuable than a flattering
one: it tells you precisely where this approach fails (registry events,
calibration, repeatability) and where it doesn't (process and login
events), instead of a single misleading "AI-powered" claim that would have
fallen apart under any real scrutiny. The engineering discipline was never
about making the AI look good — it was about being unable to lie to
ourselves about whether it actually is.

**"What would you do next if you kept working on this?"**
Chase the per-event-type split as a real lead, not a footnote — figure out
why registry events fail so badly (MCC around -0.4 to -0.7) and whether
better prompting, more context per event, or simply routing registry events
to the rules engine instead of the AI would fix it. Also worth trying: a
better-calibrated confidence signal, and rerunning determinism at a larger
sample to see if 44% holds up. The evaluation harness itself doesn't need
more work — it already produced a real, decisive, negative result. The next
work is on the AI side, not the measurement side.

**"Isn't this just a wrapper around an off-the-shelf AI model?"**
The AI call itself is genuinely simple, and that's deliberate. The real
work — and the part that took the most engineering discipline — is
everything around it: building a dataset that doesn't secretly cheat,
proving that with adversarial tests instead of trusting it, and building a
scoring system that can't be gamed into looking better than it is.
