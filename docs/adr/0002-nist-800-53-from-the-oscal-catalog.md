# ADR-0002: Resolve NIST SP 800-53 identifiers against NIST's OSCAL catalog

- **Status:** proposed
- **Date:** 2026-10-30
- **Deciders:** repository owner (pending review)

## Context

The spec makes NIST SP 800-53 Rev 5 the join key for every control and now
says identifiers "must exist in the OSCAL catalog, not be cited from memory".
Until now, the tool accepted any string as an 800-53 identifier. The Athena
fixture's identifiers were written by hand in display form (`AC-3`). All of
them happen to exist, but nothing checked that, and a withdrawn control such
as AC-3(1) would have passed.

NIST publishes the catalog in OSCAL JSON in `usnistgov/oscal-content`. The
current release is 5.2.0, last modified 2026-10-22: 1,196 controls and
enhancements, 182 of them withdrawn, in a file of about 10 MB.

## Decision

1. **The catalog is a new source**, fetched only from
   `https://raw.githubusercontent.com/usnistgov/oscal-content/` (host and path
   allowlisted, checked again after redirects) with the same size cap and
   timeout as the service reference.
2. **Pin an index, not the catalog.** `onboard catalog` reduces the OSCAL file
   to each control's catalog id, label, title and withdrawn status, plus the
   catalog's version, last-modified date, source URL, retrieval time and the
   SHA-256 of the source file. The pinned index is
   `catalogs/nist-sp-800-53-rev5.json` (about 144 KB) and is reviewed like
   code. Refreshing it is a deliberate PR that shows the diff.
3. **Catalog form only.** Control records cite 800-53 by catalog id (`ac-3`,
   `ac-2.1`) with `catalog_version`. Findings with display-form or missing
   versions are refused, and every candidate needs at least one 800-53
   reference.
4. **Select fails closed.** Before selecting anything, Select resolves every
   800-53 reference on every candidate, in or out of the requested tier. A
   reference fails when it isn't in the catalog, is withdrawn, or names another
   catalog version. Resolved references carry the catalog's label and title,
   and `selection.json` records which catalog was used.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| Pinned index from the OSCAL catalog (chosen) | Small, reviewable, offline tests; the source hash ties it back to NIST's file | A refresh step to remember |
| Commit the full OSCAL catalog | Nothing derived | 10 MB in the repository, mostly prose the tool doesn't use |
| Fetch the catalog on every run | Always current | Network in every run; versions drift between runs; tests can't be offline |
| Hand-maintained list of identifiers | Simple | "From memory" by another name: exactly what the spec forbids |

## Consequences

- A typo or a withdrawn control now stops a run with a message naming the
  control and the identifier.
- When NIST releases a new catalog version, every finding's `catalog_version`
  must move with the index, and identifiers withdrawn in the new release will
  fail. That's intended: the change is visible and reviewed.
- The tool now reaches a second host. The threat model covers it.
- Mapping *correctness* is still not verified. The catalog proves an
  identifier exists, not that it fits the control; that is the verification
  pass's job.
