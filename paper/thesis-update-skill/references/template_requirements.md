# Template And Submission Requirements

This file summarizes the most useful constraints extracted from the school's template and Q&A materials.

## 1. Structural Requirements

Keep these sections in the thesis unless the user explicitly changes school requirements:

1. cover page
2. table of contents
3. Chinese abstract
4. English abstract
5. main body chapters
6. references
7. appendix
8. integrity statement
9. acknowledgements

The current project thesis already follows this overall structure.

## 2. Body Length

The template filename mentions 4000+, but the template body explicitly says:

- main body should not be less than 5000 Chinese characters

So future edits should continue targeting 5000+ for safety.

## 3. Reference Requirements

The template states that references should generally:

- not exceed 30
- not be fewer than 15
- include some foreign-language references

When editing references, preserve this range when practical.

## 4. Q&A Constraints From PDF

Useful constraints extracted from:

- `/Users/wnluo/Downloads/10  本科生论文常见问题问答.pdf`

Key points:

1. Thesis title should be consistent across all stages.
2. Defense qualification normally requires:
   - AI detection ratio < 45%
   - text copy ratio and internal mutual-check < 25%
   - advisor score >= 60
   - peer review score >= 60
3. School free detection counts are limited:
   - AI detection: 1 free time
   - copy-ratio detection: 2 free times
4. If the final version changes substantially after a passed draft, it may need to be re-checked.
5. If only minor changes are made, it is safer to preserve the already checked version as much as possible.

## 5. Format Clues Extracted From The DOCX Template

These were extracted from the provided DOCX XML and should be treated as strong hints.

### Page Setup

- page size: A4
- top margin: 1440 twips = 2.54 cm
- bottom margin: 1440 twips = 2.54 cm
- left margin: 1803 twips ≈ 3.18 cm
- right margin: 1803 twips ≈ 3.18 cm
- header distance: 851 twips ≈ 1.50 cm
- footer distance: 992 twips ≈ 1.75 cm

### Default Fonts

- Western text default: `Times New Roman`
- East Asian text default: `宋体`

### Page And Grid Settings

- A4 page detected from document XML
- top margin: `1440` twips = `2.54 cm`
- bottom margin: `1440` twips = `2.54 cm`
- left margin: `1803` twips ≈ `3.18 cm`
- right margin: `1803` twips ≈ `3.18 cm`
- header distance: `851` twips ≈ `1.50 cm`
- footer distance: `992` twips ≈ `1.75 cm`
- document grid line pitch: `312`

These values are strong template signals and should be treated as the target layout baseline.

### Fonts Seen In The Template

- `黑体`
- `宋体`
- `楷体_GB2312`
- `Times New Roman`

### Sizes Seen In The Template XML

The following OOXML half-point sizes appear in the template:

- `21` = 10.5 pt
- `24` = 12 pt
- `28` = 14 pt
- `30` = 15 pt
- `32` = 16 pt
- `36` = 18 pt
- `44` = 22 pt
- `52` = 26 pt

This strongly suggests the template uses a mix of:

- small-four / five-size body text ranges
- larger blackface / title text for section headers and cover text

## 6. Practical Style Table From Template

The following table is a working reference distilled from `word/document.xml` and `word/styles.xml`.
Use it as a near-template style guide when adjusting thesis presentation.

| Element | Observed font | Observed size | Other clues |
|---|---|---:|---|
| Cover thesis name at top (`贵州师范大学本科毕业论文`) | `黑体` | `52` half-points = `26 pt` | centered |
| Cover label `题目` | `黑体` | `30` = `15 pt` | left block indentation used |
| Cover main title value | `方正小标宋简体` | `30` = `15 pt` | follows `题目：` |
| Cover subtitle line (`——...`) | `楷体_GB2312` | `28` = `14 pt` | centered |
| Cover metadata labels (`学院/专业/年级/姓名/指导教师`) | `黑体` | `30` = `15 pt` | label/value mixed line |
| Cover metadata values | `楷体_GB2312` | `30` = `15 pt` | used for filled-in content |
| Directory title (`目录`) | `黑体` | `32` = `16 pt` | centered |
| TOC level 1 items | mixed, visually bold | inherited from TOC style | right tab with dot leader at position `8505` |
| Chapter title (`1 绪论/引言`) | `黑体` | visually around `14-16 pt` in TOC and body | major heading |
| Section title (`1.1 ...`) | `楷体`/`楷体_GB2312` clues appear in TOC | around `12 pt` | secondary heading |
| Body paragraphs | `宋体` + western `Times New Roman` | `24` = `12 pt` | first-line indent, exact line spacing often `400` |
| Figure caption | `黑体` | around `10.5-12 pt` | centered, e.g. `图3-1 ...` |
| Table caption | `黑体` | around `12 pt` | centered, e.g. `表3.1 ...` |
| Reference heading | `黑体` | around `16 pt` in TOC signal | standalone section |
| Integrity statement / acknowledgements headings | `黑体` | around `15 pt` in TOC signal | standalone section |

Notes:

1. Some style IDs in `styles.xml` are generic Word/WPS built-ins and do not perfectly reflect the visible final formatting.
2. The `document.xml` runs are more trustworthy than style names for visible cover/title details.
3. When in doubt, preserve the current thesis HTML structure and only move closer to these extracted style signals rather than inventing a new style system.

## 7. Observed Cover Clues

From the document XML:

- cover labels such as `学院`, `专业`, `年级`, `指导教师` use `黑体`
- filled values often use `楷体_GB2312`
- the cover page includes right-aligned fields for thesis code and student number

## 8. Body Layout Clues

These recurring layout details also appeared in the template:

- many body paragraphs use `w:spacing w:line="400" w:lineRule="exact"`
- some title/TOC blocks use centered alignment
- body paragraphs often use first-line indentation:
  - examples like `w:firstLine="480"` or larger cover indentation values
- TOC uses automatic fields rather than manual numbering
- the template explicitly expects chapter-level page separation

These should guide future formatting-sensitive updates.

## 9. Practical Editing Guidance

When continuing to update the thesis:

1. Prefer local section edits over broad rewrites.
2. If the user is close to submission, avoid changing abstract and conclusion more than necessary.
3. If code changes are major, update:
   - abstract
   - Chapter 3
   - Chapter 4
   - Chapter 5
   - screenshots
4. If code changes are minor, only patch the affected subsection and keep the rest stable.
5. Be conservative with claims to help reduce mismatch and checking risk.
