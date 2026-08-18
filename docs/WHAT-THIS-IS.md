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

Being direct about what is and isn't finished matters more here than a
flattering summary would.

**Measured and real:**

- The three shortcuts above were measured precisely (the year-only
  classifier's 100% accuracy is a real, reproduced number from this
  project's own test suite, not an estimate) and are now blocked by
  permanent automated tests.
- We measured, on the actual hardware this runs on, that a single AI call
  per alert takes about **4.2 seconds**, while chaining four separate AI
  calls together (an "agent per task" pipeline — one step to enrich the
  alert, one to triage it, one to correlate it with other alerts, one to
  double-check the verdict) takes about **16.9 seconds** — roughly four
  times as slow, for a task where nothing in the research we reviewed
  showed four coordinated AI calls actually beating one well-prompted call
  on this kind of classification problem. So we built one solid AI call,
  not four, and can point to both the research and the measured timing as
  the reason.
- The AI's output is *not* fully repeatable. Even with settings meant to
  force determinism (a "temperature" of zero, which normally means "always
  pick the most likely next word, no randomness"), the same alert sent
  through the same running server does not always come back with the exact
  same answer — we measured this directly rather than assuming the
  determinism setting was doing its job. This matters because if you can't
  trust that a score would repeat on a re-run, you can't fully trust the
  score. We built the evaluation to measure and report this run-to-run
  agreement rate explicitly, rather than quietly assume perfect
  repeatability.

**Built, but not yet run for real:** the full scoring system — the part
that would give us an actual accuracy number, a precision/recall table, and
a measurement of how well-calibrated the AI's stated confidence is (i.e.,
when it says "I'm 90% sure," is it actually right 90% of the time?) — is
completely implemented and tested. What it has not yet done is run against
the full real dataset end-to-end and produce a results report. That's the
next concrete step, not a hidden gap: the machinery exists, the actual
numbers from a full run don't exist yet. Anyone asking "so is it actually
accurate?" gets an honest "we built the tool to answer that question
rigorously, and haven't pulled the trigger on the full run yet" — not a
made-up number.

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

- **No full evaluation run has happened yet.** The scoring, baseline
  comparison, and reporting code all exist and are tested, but we have not
  yet run the whole pipeline against the full dataset and gotten real
  accuracy/precision/recall/confidence-calibration numbers out the other
  end.
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
We don't have a final accuracy number yet — the scoring system is fully
built and tested, but the full run against the real dataset hasn't
happened. What I can say with confidence is that we built the *means* to
answer that question honestly, including comparisons against much simpler,
non-AI approaches, which is the part most similar projects skip.

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
We built the tooling to measure exactly that (it's called calibration —
checking whether "90% confident" predictions are actually right 90% of the
time), but we have not run it against real data yet. I won't claim it's
well-calibrated until we've measured it, and I also won't assume it's
badly calibrated — that's exactly the kind of thing this project is
designed to check rather than assume.

**"Does the same alert always get the same answer from the AI?"**
No, not always — even with the settings that are supposed to force
consistent output. We measured this directly rather than assuming the
"deterministic" setting worked as advertised, and we treat that
inconsistency as something to report alongside any score, not something to
paper over.

**"What would you do next if you kept working on this?"**
Run the full evaluation end-to-end and get real numbers — accuracy,
precision/recall broken out by event type, calibration, and a head-to-head
comparison against the simpler baselines with statistical significance
testing, all of which is already built and just needs to be pointed at the
real dataset.

**"Isn't this just a wrapper around an off-the-shelf AI model?"**
The AI call itself is genuinely simple, and that's deliberate. The real
work — and the part that took the most engineering discipline — is
everything around it: building a dataset that doesn't secretly cheat,
proving that with adversarial tests instead of trusting it, and building a
scoring system that can't be gamed into looking better than it is.
