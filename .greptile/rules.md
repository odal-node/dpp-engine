# Review rules

This repository keeps its review rules in one file, `.coderabbit.yaml`, and this
review is given that file as context. A rule copied into a second file has two homes,
and one of them goes stale, so the rules are not restated here. Apply them as written:

- **`reviews.path_instructions`:** apply each entry to the changed files its `path`
  glob matches. `**` covers every file.
- **`reviews.pre_merge_checks.custom_checks`:** treat each entry as a check on the
  whole pull request: its diff and its description.
  - A failed `mode: error` check is a blocking finding.
  - A failed `mode: warning` check is a non-blocking one.
  - Each finding names the line that fails and gives the fix the check describes.
- **`knowledge_base.code_guidelines`:** the documents it names are the standards.
  The instructions say what to flag, and the documents say what to do.

The paths in `reviews.path_filters` are generated or resolved files. They are left
out of this review too, through `ignorePatterns` in `.greptile/config.json`. The rest
of `.coderabbit.yaml` (`profile`, `auto_review`, `review_status`, `tools`, `language`)
governs when and how that tool runs. It has nothing to say about this review.

What CI already decides is not what this review is for. Formatting, clippy, the test
tiers, the guard scripts and the doc build are gates, and a gate that passes needs no
second opinion.

This file, and every file in `.greptile/`, is published with the repository. The
publication boundary in `.coderabbit.yaml` binds them too.
