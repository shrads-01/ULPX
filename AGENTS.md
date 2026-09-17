\# ULPX — Agent Development Rules



\## Mission



ULPX (Universal Lossless Security Telemetry Intelligence Framework) processes heterogeneous security and network telemetry while preserving original evidence.



The system should eventually support:



\* lossless evidence preservation

\* event framing

\* format detection

\* parsing

\* semantic normalization

\* unknown-format inference

\* provenance

\* integrity verification

\* versioned reprocessing

\* entity resolution

\* drift detection

\* OCSF/ECS output

\* Parquet/OpenSearch output

\* air-gapped operation



Build the project incrementally. Do not attempt to implement the entire framework at once.



\## Core Rules



\### 1. Never lose original evidence



Original input must never be silently modified or discarded.



The system must preserve enough information to recover the original input byte-for-byte.



Never replace raw evidence with normalized data.



\### 2. Separate framing and parsing



Do not assume that one line always equals one event.



Framing determines event boundaries.



Parsing interprets an already-framed event.



These must remain separate components.



\### 3. ULPX-IR is the canonical internal representation



ULPX-IR is the internal source of truth.



OCSF and ECS are output projections.



Do not make OCSF or ECS the internal canonical representation.



\### 4. Represent uncertainty explicitly



Never turn an uncertain inference into a fact.



Use states such as:



\* KNOWN

\* PROBABLE

\* UNKNOWN

\* QUARANTINED

\* REJECTED



Track confidence separately for:



\* format detection

\* extraction

\* semantic mapping

\* overall interpretation



When evidence is insufficient, prefer UNKNOWN over a confidently incorrect result.



\### 5. Unknown formats



Unknown input formats must not silently become known formats.



The inference system may suggest:



\* structure

\* fields

\* parsers

\* semantic mappings



Suggestions must remain distinguishable from validated interpretations.



\### 6. AI is advisory



AI/ML may suggest parsers and mappings.



AI must never:



\* modify original evidence

\* modify evidence hashes

\* bypass validation

\* bypass security controls

\* silently modify historical interpretations

\* automatically promote an unvalidated parser



AI-generated suggestions must go through validation before becoming trusted.



\### 7. Version everything that affects interpretation



Parser versions and interpretation versions must be explicit.



Reprocessing must create a new interpretation without modifying the original evidence.



Historical interpretations must remain reproducible.



\### 8. Provenance



Normalized fields should eventually be traceable to their source evidence.



Provenance should identify, where practical:



\* source event

\* byte/character location

\* parser

\* parser version

\* transformation

\* semantic mapping



\## Security Rules



Telemetry is attacker-controlled input.



Design defensively against:



\* malformed input

\* oversized events

\* oversized fields

\* deeply nested structures

\* parser crashes

\* excessive recursion

\* catastrophic regular expressions

\* resource exhaustion

\* invalid encodings

\* invalid Unicode

\* maliciously crafted records



Where appropriate, enforce limits on:



\* event size

\* field size

\* nesting depth

\* number of fields

\* parser execution time

\* memory consumption



Prefer safe failure over uncontrolled resource consumption.



\## Rust Rules



Use stable Rust.



Prefer:



\* clear types

\* explicit error handling

\* small modules

\* deterministic behavior

\* well-tested APIs

\* minimal dependencies



Avoid unsafe Rust unless it is necessary.



Run these before completing a phase:



```text

cargo fmt --check

cargo clippy --all-targets --all-features -- -D warnings

cargo test --workspace

```



\## Development Rules



Work in explicit phases.



Do not skip ahead unless instructed.



Every phase should:



1\. Have a clear purpose.

2\. Compile successfully.

3\. Include appropriate tests.

4\. Handle important error cases.

5\. Avoid unnecessary dependencies.

6\. Update documentation when architecture changes.

7\. Preserve offline compatibility where possible.



Do not create fake implementations merely to make tests pass.



Do not add large placeholder systems for future features.



\## Intended Architecture



The overall system should eventually follow this conceptual pipeline:



raw input

→ ingestion

→ lossless evidence

→ framing

→ format detection

→ parsing or unknown-format inference

→ ULPX-IR

→ semantic normalization

→ provenance/integrity

→ storage/export



Possible output projections include:



\* OCSF

\* ECS

\* Parquet

\* OpenSearch-compatible records



\## Parser Lifecycle



Parsers should eventually follow a controlled lifecycle:



candidate

→ validated

→ approved

→ versioned

→ deployed



An AI-generated parser must not automatically become trusted.



Parser validation should eventually include:



\* syntax tests

\* semantic tests

\* golden tests

\* negative tests

\* malformed-input tests

\* mutation tests

\* security/resource tests

\* performance tests



\## Testing



Tests are part of the implementation.



Use appropriate:



\* unit tests

\* integration tests

\* golden fixtures

\* malformed-input tests

\* security tests

\* property-based tests where useful

\* parser regression tests

\* performance benchmarks

\* offline/air-gap tests



Never remove a regression test simply to make the build pass.



\## Performance



Do not make unsupported performance claims.



Measure performance when relevant.



Future benchmarks should measure things such as:



\* ingestion throughput

\* parsing throughput

\* normalization throughput

\* storage throughput

\* memory usage

\* latency



\## Quality



Prefer a smaller correct implementation over a larger unreliable implementation.



Do not add technologies merely because they sound impressive.



Every major dependency must have a clear architectural reason.



Keep the system understandable, testable, maintainable, and suitable for air-gapped deployment.



\## Planned Phases



1\. Repository foundation

2\. Core event model

3\. Lossless evidence storage

4\. Universal framing

5\. Parser runtime

6\. ULPX-IR

7\. Semantic mapping

8\. Unknown-format inference

9\. ParserLab

10\. Provenance

11\. Integrity

12\. Versioned reprocessing

13\. Entity resolution

14\. Drift detection

15\. Storage/infrastructure

16\. User interface

17\. Air-gapped deployment

18\. Benchmarking

19\. SIH demonstration and documentation



When instructed to work on a specific phase, implement only that phase unless explicitly told otherwise.



