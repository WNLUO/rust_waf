---
name: thesis-update-skill
description: Use when continuing work on the Rust WAF thesis in this repository. Read the current thesis HTML, the thesis update log, then map code changes to thesis sections, tables, diagrams, screenshots, and wording updates without rewriting unrelated parts.
---

# Thesis Update Skill

This is a project-local workflow file for maintaining the thesis under `paper/`.

## Scope

Use this when the user asks to:

- continue editing the thesis
- sync thesis content with code changes
- refresh tables, diagrams, screenshots, test results, or wording
- prepare a cleaner final HTML thesis version

## Files To Read First

Always start with:

1. `paper/rust_waf_thesis.html`
2. `paper/论文更新日志.md`
3. `/Users/wnluo/Downloads/05  论文正文格式模板（参考）（不少于4000字，建议查重率不低于5%不超过25%）.docx`

Then read only the code files related to the user's latest change.
If formatting matters in the request, also read:

4. `paper/thesis-update-skill/references/template_requirements.md`

## Thesis Template Requirements

When updating the thesis, keep these template-derived requirements in mind:

1. The paper should remain in a standard undergraduate thesis structure.
2. The main body should target at least 5000 Chinese characters to stay on the safe side.
3. Keep these major sections unless the user explicitly changes them:
   - cover information
   - table of contents
   - Chinese abstract
   - English abstract
   - main chapters
   - references
   - appendix
   - integrity statement
   - acknowledgements
4. The introduction should cover background, significance, content, methods, and research status.
5. The conclusion should summarize results, value, limitations, and future work.
6. References should generally stay in the range required by the template:
   - usually 15 to 30 entries
   - should include some foreign-language references
7. Do not remove formal thesis elements just because the user is currently focused on code changes.
8. If the user updates the project substantially, re-check whether the abstract, Chapter 4, Chapter 5, figures, and conclusion still match the code.
9. If the user asks about formatting, prioritize the extracted style table in `references/template_requirements.md` instead of guessing.

## School Q&A Constraints

From the supplied Q&A PDF, keep these process constraints in mind when helping with the thesis:

1. The thesis title should stay consistent across all submission stages unless the user explicitly confirms an approved title change.
2. For this school context, the student normally needs all of the following to qualify for defense:
   - AI detection copy ratio below 45%
   - text copy ratio and internal mutual-check below 25%
   - advisor review score at least 60
   - peer review score at least 60
3. If the final manuscript changes a lot after a passed draft, warn that AI detection may need to be redone.
4. If only minor wording changes are made, preserve the passed version as much as possible unless the user explicitly wants a larger rewrite.
5. Avoid unnecessary large-scale rewrites close to final submission, because that can increase AI risk and make the checked version diverge from the final version.

These are not just formatting notes; they should influence how aggressively the thesis is revised.

## What Is Already Captured

The current thesis already tries to reflect:

- title and design-and-implementation orientation
- Chinese/English abstracts
- six-chapter main structure
- references, appendix, integrity statement, acknowledgements
- code-aligned system architecture, implementation details, testing, and UI screenshots

## What To Watch For

Pay extra attention to these possible mismatches:

- chapter titles drifting away from the school template style
- claims exceeding the real implementation
- test numbers becoming stale after code changes
- screenshots no longer matching the current UI
- references count or composition falling outside the expected range
- revisions becoming so large that they may affect AI/checking risk
- the thesis title drifting away from the already fixed submission title

## Update Workflow

1. Identify what changed in the program.
2. Map the change to thesis sections.
3. Prefer local edits over broad rewrites.
4. Preserve the existing title unless the user explicitly changes it.
5. Keep chapter structure stable unless the user asks for a restructure.
6. If UI changed, refresh screenshots only for affected pages.
7. If backend behavior changed, check whether these sections need updates:
   - abstract
   - Chapter 3 overall design
   - Chapter 4 implementation details
   - Chapter 5 testing and analysis
8. If tests or build results changed, update the exact statements in the thesis.
9. If a code feature was removed, remove or tone down the matching thesis claim.
10. Do not claim capabilities that the code does not actually implement.
11. If formatting is being refined, preserve the template-derived style baseline:
   - A4-like page setup
   - Chinese body text close to `宋体` 12 pt
   - blackface major headings
   - cover labels in `黑体`
   - cover values leaning toward `楷体_GB2312`

## Editing Rules

- Prefer editing the existing `paper/rust_waf_thesis.html` file.
- Keep the paper “design and implementation” oriented.
- Keep tables, diagrams, and screenshots aligned with the actual codebase.
- Avoid turning the paper into an AI/security theory survey disconnected from the project.
- When uncertain, describe the implementation conservatively.
- When formatting is uncertain, prefer “closer to extracted template evidence” over visual improvisation.

## Screenshot Rules

When screenshots are needed:

1. Run the backend and frontend locally.
2. Capture only the pages relevant to the changed feature.
3. Replace only the affected figure blocks in the thesis.
4. If exporting to single-file HTML, embed images directly.

## Good Prompt For Next Time

The user can say:

`先看 paper/论文更新日志.md 和 paper/thesis-update-skill/SKILL.md，然后根据这次代码改动继续修改 paper/rust_waf_thesis.html。`

## Log Maintenance

After each meaningful thesis update, append a short entry to:

- `paper/论文更新日志.md`

The log should record:

- what changed in the code
- which thesis sections were updated
- whether screenshots were refreshed
- whether claims/tests/metrics changed
