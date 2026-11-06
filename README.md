# patch2vuln evaluation

`batch_patch2vuln.py` runs patch-to-advisory generation on the pairs in
`dataset/patches.csv`. Existing generated CVE records are in `patch2vuln-results`.

## Compare generated advisories with the original CVEs

`compare_advisories.py` is an independent evaluator. It reads completed
`*.cve.json` files recursively, downloads original CVE 5 records from
`https://db.gcve.eu/api/vulnerability/CVE-ID`, and writes JSON comparisons and
summary statistics to a separate directory. It does **not** run patch2vuln,
modify generated results, or require Ollama for statistical comparisons.
Python 3.10+ is sufficient; there are no third-party dependencies.

Start with a small sample:

```bash
python3 compare_advisories.py --limit 3
```

Compare everything currently available, or select particular CVEs:

```bash
python3 compare_advisories.py \
  --results-dir patch2vuln-results --output-dir advisory-comparisons

python3 compare_advisories.py --cve CVE-1999-0199 --cve CVE-1999-0731
```

The scanner takes a sorted list of files at startup. A file still being written
is reported as an error without stopping other comparisons. Rerun after generation
finishes to include new files or retry incomplete ones. Nothing in the generation
process needs to be stopped or changed.

### What is compared

| Dimension | Analysis |
| --- | --- |
| Coverage | Which CNA fields exist in both records, only the original, or only the generated record |
| Text | Title, descriptions, solutions, workarounds, exploits, and impact descriptions: language-specific token overlap, word counts, length ratio, and bag-of-words cosine similarity |
| Weaknesses and attack patterns | CWE/CAPEC set overlap, omissions, and additions |
| Products and versions | Normalized vendor/product/package identities; exact product-scoped version ranges, including bounds, status changes, and default status |
| Platform and code scope | CPEs, modules, program files |
| References and credits | URL and name/credit-type set overlap |
| CVSS | Within-version, within-scenario score delta, absolute score error, severity agreement, and individual vector metric differences |
| SSVC | Within-version, within-role, within-scenario option overlap |
| Metadata and other fields | JSON Pointer field differences covering the complete records, including timelines, dates, tags, supporting media, and GCVE extensions |

The main comparison uses CNA against CNA. Original ADP containers are retained,
and `supplementary_metrics` compares each ADP's CVSS/SSVC with the generated CNA
separately, with its source/provider labeled. ADP evidence is never silently
merged into the CNA or counted in the main aggregate scores.

CVSS 3.1 and 4.0 numeric scores are **not** directly compared. Multiple metrics
with an identical version/scenario scope are marked `ambiguous` rather than
arbitrarily selecting a score. SSVC additionally requires a matching role.
CVSS scores are compared as recorded, not recalculated or validated.

Set precision is `shared / generated`, recall is `shared / original`, F1 is
`2 * shared / (original + generated)`, and Jaccard is `shared / union`.
Precision requires both sets to be nonempty. When the original set is empty,
precision/F1/Jaccard/recall are `null`: missing reference data cannot judge an
added claim. An empty generated set with a nonempty original has zero recall,
F1, and Jaccard. Two empty sets have `exact_match: null`, not a perfect score.
Raw `added_in_generated` and `missing_from_generated` lists remain available.

Product identity strings and credit names are case-folded and whitespace-normalized.
Version range objects remain literal, including `lessThan` versus `lessThanOrEqual`;
there is no cross-ecosystem version solver or product-alias inference. URLs lose
fragments, and GitHub commit `.patch` URLs match their commit URL. Query strings
remain significant. List ordering remains visible in the full field audit even
when the set-based comparison treats it as irrelevant.

These measurements indicate **agreement with the reference**, not factual
correctness. An original CVE may be incomplete, broader than one patch, or updated
after generation. Additional detail can be correct even if absent from the CVE.
Lexical similarity is not semantic accuracy; paraphrases and different languages
need analyst review. Non-published (e.g. REJECTED) originals are reported as errors
instead of producing misleading quality scores. CVE 4 and NVD wrapper formats
are not supported; provide CVE 5 records.

### JSON outputs and repeatability

```text
advisory-comparisons/
  originals/CVE-1999-0199.json
  comparisons/CVE-1999-0199/OWNER__REPO__SHA/run_001/CVE-1999-0199.cve.comparison.json
  summary.json
```

Each fetched original is cached with its source URL, fetch timestamp, canonical
SHA-256, and full record. A cached ID, URL, or hash mismatch is an error; use
`--refresh` to fetch a clean snapshot. One fetch is reused for all runs of a CVE.
Use `--cache-dir` to share snapshots across comparison directories. The default
is to reuse cached originals, so comparisons remain reproducible even if the
live advisory changes. `--refresh` deliberately updates that baseline.

Each report has a `schema_version`, method identifier, generated-record hash,
generation provenance (model/patch/commit where available), reference provenance,
`comparison`, and separate `llm` result. Full field differences preserve original
and generated values. Multiple commits and repeated runs cannot overwrite one
another because the relative input path is retained. Outputs are written atomically.

`summary.json` includes:

- A manifest of exactly the reports selected in the current invocation.
- Counts of `compared`, `error`, and `llm_error` reports and distinct compared CVEs.
- Field coverage and agreement counts.
- Count, mean, median, minimum, and maximum for available numeric measurements.
- `cve_macro_mean`, which first averages within a CVE, then gives each CVE equal
  weight so repeated runs or multiple patches do not inflate its influence.
- The same statistics grouped by generation model under `by_model`.
- Optional semantic-review verdict counts, kept separate from statistical metrics.

Only available numeric values contribute to their stated denominator. CVSS counts
are per comparable scope, not necessarily per advisory. A filtered rerun replaces
the summary with that selection; older reports remain on disk but are not included
unless listed in the current manifest. This tool owns its output/cache directories.
Input and output trees must be separate. Use distinct output directories for
concurrent evaluations or experiments with different models/reference snapshots.

Offline reuse:

```bash
python3 compare_advisories.py --offline
```

Alternatively supply a directory of original CVE 5 files named `CVE-ID.json`:

```bash
python3 compare_advisories.py \
  --originals-dir /path/to/original-cves --offline \
  --output-dir /path/to/comparisons
```

Local originals are labeled with their file path and canonical hash; they are
never represented as having been downloaded from db.gcve.eu. `--api-base` can
point to another compatible Vulnerability-Lookup API. HTTPS uses the normal
system trust/proxy configuration. HTTP timeouts, bounded response sizes, and
limited retries handle temporary failures; a 403/404 is not retried. Every failed
record gets an error report, and the process continues. Exit codes: `0` when all
selected comparisons (and requested LLM reviews) succeed, `1` for partial/total
processing failure, `2` for invalid CLI arguments or no matching input files.

### Optional local Ollama review

Start your existing Ollama server and choose an installed model explicitly:

```bash
python3 compare_advisories.py --limit 3 \
  --ollama-model qwen3.8:27b --ollama-host http://localhost:11434
```

`OLLAMA_HOST` is also supported. This option calls Ollama's `/api/chat` with a
JSON schema, temperature/seed zero, and a prompt version stored in the report.
It does not install models or start a server. Full original/generated records are
sent to the selected endpoint, so choose the endpoint accordingly.

The review addresses description, affected products/versions, weaknesses,
severity, remediation, references, credits, and overall agreement. Verdicts
distinguish `supported`, `contradicted`, `not_in_reference`, `omitted`, and
`uncertain`. The prompt treats advisory contents as untrusted evidence and asks
for verbatim evidence. Evidence excerpts are checked against the supplied records;
`*_evidence_verified: false` marks a quote that could not be found. Findings are
model opinions, including those with matching quotes. Verdict counts do not
filter unverified evidence; inspect the per-report evidence flags before using
semantic findings in downstream statistics.

Malformed or incomplete model JSON is an LLM error. Statistical results are
preserved even if the optional review fails. The process then exits `1` so a failed
review cannot pass unnoticed. `--llm-timeout` defaults to 300 seconds;
`--llm-max-chars` defaults to 120,000 characters. Oversized records are rejected
for LLM review rather than silently truncated; adjust this limit and your model's
context capacity together. A deterministic request does not guarantee identical
model output across hardware or Ollama/model versions.

## Tests

```bash
python3 -B -m unittest discover -s tests -v
```

Tests cover comparisons, missing reference fields, language handling, scoped
versions and severity, caching and retries, structured Ollama responses, and
offline CLI processing of multiple runs and failures. HTTP/model responses in
unit tests are mocked; they do not establish live endpoint or inference access.
