/**
 * Say which rows of the IETF table in the standards register no longer match the
 * RFC Editor's index.
 *
 * Every row records the status its specification had when somebody last read it,
 * and the gate in `crates/dpp-node/tests/standard_citations.rs` can prove only
 * that the cell is filled in and dated, not that it is still true. A specification
 * can be updated, obsoleted or reclassified without a commit here, and a row that
 * has gone stale reads exactly like one that has not. This compares each row with
 * `rfc-index.xml`, which the RFC Editor publishes with every RFC's current status
 * and what updates or obsoletes it, and names the rows that differ.
 *
 * Per RFC row it checks that:
 *
 *   status    the row begins with the status the index gives (Proposed Standard,
 *             Internet Standard, Informational, ...);
 *   updaters  every RFC the index lists as updating or obsoleting this one is
 *             named in the row. The row is prose, so this asks that the number
 *             appear, not where;
 *   claims    every RFC the row says updates or obsoletes it ("updated by RFC N")
 *             is one the index lists;
 *   exists    the RFC is in the index at all.
 *
 * Per Internet-Draft row it checks whether the draft has since been published as
 * an RFC. It cannot say whether the revision cited is still the current one: the
 * index lists published RFCs only.
 *
 * It never edits the register. The `Read` date records a person reading a source,
 * and a script that moved it would turn "somebody checked" into "a job ran". W3C,
 * GS1, IDTA and ETSI rows are not checked here either, because no equally plain
 * feed exists for them; the release-time re-read covers those.
 *
 * Exit status: 0 when every row matches, 1 when any differs, 2 when the check
 * could not run (the index could not be fetched or read, or it parsed to
 * something that cannot be the index). A check that cannot run must not read as
 * one that passed.
 *
 *   node standards_status.mjs                   fetch the index and compare
 *   node standards_status.mjs --index FILE      compare against a saved copy
 *   node standards_status.mjs --register FILE   read the table from another file
 *   node standards_status.mjs --self-test       prove the comparison on fixtures
 *
 * Needs Node 18+. Run it through `just standards-status`.
 */
import { readFileSync, appendFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const REGISTER = "docs/architecture/STANDARDS.md";
const INDEX_URL = "https://www.rfc-editor.org/rfc/rfc-index.xml";
// The index lists far more than this. Fewer means the parse matched nothing and
// every row would "differ" or, worse, none would.
const MIN_ENTRIES = 5000;

// How a status is spelled in the index, and how the register spells it.
const STATUSES = [
  "Internet Standard",
  "Draft Standard",
  "Proposed Standard",
  "Best Current Practice",
  "Informational",
  "Experimental",
  "Historic",
];

const rfcNumbers = (text) => [...text.matchAll(/RFC\s*0*(\d+)/gi)].map((m) => Number(m[1]));

/** Read the index into the RFCs it lists and the drafts they came from. */
export function parseIndex(xml) {
  const rfcs = new Map();
  const drafts = new Map();
  for (const [, body] of xml.matchAll(/<rfc-entry>([\s\S]*?)<\/rfc-entry>/g)) {
    const id = /<doc-id>RFC0*(\d+)<\/doc-id>/.exec(body);
    if (!id) continue;
    const number = Number(id[1]);
    // The two blocks are written out as literals, not built from a tag name, so
    // that no pattern here is made of a variable.
    const numbersIn = (m) => new Set(m ? rfcNumbers(m[1].replace(/<doc-id>RFC/g, "RFC ")) : []);
    const status = /<current-status>([^<]*)<\/current-status>/.exec(body)?.[1] ?? "";
    rfcs.set(number, {
      status: status.trim().toLowerCase(),
      updatedBy: numbersIn(/<updated-by>([\s\S]*?)<\/updated-by>/.exec(body)),
      obsoletedBy: numbersIn(/<obsoleted-by>([\s\S]*?)<\/obsoleted-by>/.exec(body)),
    });
    const draft = /<draft>([^<]*)<\/draft>/.exec(body)?.[1]?.trim();
    // `draft-ietf-name-NN` becomes `draft-ietf-name`, the part that survives a
    // revision. A draft that went through several RFCs maps to the last.
    if (draft) drafts.set(draft.replace(/-\d{2}$/, ""), number);
  }
  if (rfcs.size < MIN_ENTRIES) {
    throw new Error(`the index parsed to ${rfcs.size} RFCs; expected more than ${MIN_ENTRIES}`);
  }
  return { rfcs, drafts };
}

/** Read the rows of the register's IETF table. */
export function parseRegister(markdown) {
  const section = /^## IETF\s*$([\s\S]*?)(?=^## |$(?![\s\S]))/m.exec(markdown)?.[1];
  if (!section) throw new Error("no `## IETF` section in the register");
  const rows = [];
  for (const line of section.split("\n")) {
    if (!line.startsWith("|")) continue;
    const cells = line.split("|").slice(1, -1).map((c) => c.trim());
    const spec = cells[0]?.replace(/`/g, "");
    if (!spec || spec === "Spec" || /^-+$/.test(spec)) continue;
    rows.push({ spec, status: cells[2] ?? "" });
  }
  if (rows.length === 0) throw new Error("the register's IETF table has no rows");
  return rows;
}

/** Compare the rows with the index; returns one sentence per difference. */
export function compare(rows, { rfcs, drafts }) {
  const findings = [];
  for (const { spec, status } of rows) {
    const cell = status.replace(/\*/g, "");
    const rfc = /^RFC\s*0*(\d+)$/.exec(spec);
    if (rfc) {
      const entry = rfcs.get(Number(rfc[1]));
      if (!entry) {
        findings.push(`${spec}: not in the RFC Editor's index`);
        continue;
      }
      const stated = STATUSES.find((s) => cell.toLowerCase().startsWith(s.toLowerCase()));
      if (!stated) {
        findings.push(`${spec}: the status cell does not begin with a status the index uses`);
      } else if (stated.toLowerCase() !== entry.status) {
        findings.push(`${spec}: the row says ${stated}, the index says ${entry.status}`);
      }
      const named = new Set(rfcNumbers(cell));
      for (const [kind, set] of [["updated", entry.updatedBy], ["obsoleted", entry.obsoletedBy]]) {
        for (const n of set) {
          if (!named.has(n)) findings.push(`${spec}: ${kind} by RFC ${n} in the index, and the row does not say so`);
        }
      }
      for (const [, kind, list] of cell.matchAll(/\b(updated|obsoleted) by((?:[\s,]*(?:and\s+)?RFC\s*\d+)+)/gi)) {
        const set = kind.toLowerCase() === "updated" ? entry.updatedBy : entry.obsoletedBy;
        for (const n of rfcNumbers(list)) {
          if (!set.has(n)) findings.push(`${spec}: the row says ${kind.toLowerCase()} by RFC ${n}, and the index does not`);
        }
      }
    } else if (/^draft-/.test(spec)) {
      const published = drafts.get(spec.replace(/-\d{2}$/, ""));
      if (published) findings.push(`${spec}: published as RFC ${published}`);
    } else {
      findings.push(`${spec}: not an RFC or a draft this check can read`);
    }
  }
  return findings;
}

function selfTest() {
  // Entries in the shape the index uses, filler to clear the sanity floor, and a
  // register that has each kind of difference once and one row that is right.
  const entry = (n, status, extra = "") =>
    `<rfc-entry><doc-id>RFC${String(n).padStart(4, "0")}</doc-id><current-status>${status}</current-status>${extra}</rfc-entry>`;
  const filler = Array.from({ length: MIN_ENTRIES }, (_, i) => entry(100000 + i, "INFORMATIONAL")).join("");
  const xml =
    `<rfc-index>${filler}` +
    entry(1111, "PROPOSED STANDARD", "<updated-by><doc-id>RFC2222</doc-id><doc-id>RFC2223</doc-id></updated-by>") +
    entry(3333, "INFORMATIONAL", "<obsoleted-by><doc-id>RFC4444</doc-id></obsoleted-by>") +
    entry(5555, "BEST CURRENT PRACTICE", "<draft>draft-ietf-foo-bar-07</draft>") +
    entry(6666, "INTERNET STANDARD") +
    `</rfc-index>`;
  const row = (spec, status) => `| ${spec} | Title | ${status} | 2026-01-01 | code | Unit tests | No |`;
  const register = [
    "## IETF", "", "| Spec | Title | Status as read | Read | Implemented in | Evidence | Conformance claimed |", "|---|---|---|---|---|---|---|",
    row("RFC 1111", "Proposed Standard; updated by RFC 2222, RFC 2223"), // right
    row("RFC 6666", "Internet Standard. Nothing updates or obsoletes it"), // right
    row("RFC 3333", "Proposed Standard"), // wrong status, and misses the obsoleter
    row("RFC 5555", "Best Current Practice; **updated by RFC 9999**"), // claims an updater the index lacks
    row("RFC 7777", "Informational"), // not in the index
    row("`draft-ietf-foo-bar-06`", "Internet-Draft; revision 6 is current"), // since published
    row("`draft-ietf-no-such-01`", "Internet-Draft"), // right
    "", "## Other specifications", "", row("W3C Thing", "Recommendation"),
  ].join("\n");
  const got = compare(parseRegister(register), parseIndex(xml)).sort();
  const want = [
    "RFC 3333: obsoleted by RFC 4444 in the index, and the row does not say so",
    "RFC 3333: the row says Proposed Standard, the index says informational",
    "RFC 5555: the row says updated by RFC 9999, and the index does not",
    "RFC 7777: not in the RFC Editor's index",
    "draft-ietf-foo-bar-06: published as RFC 5555",
  ].sort();
  const failures = [];
  for (const w of want) if (!got.includes(w)) failures.push(`missed: ${w}`);
  for (const g of got) if (!want.includes(g)) failures.push(`unexpected: ${g}`);
  // The rows that are right must produce nothing, and a table cut off at the next
  // section must not read the "Other specifications" row.
  if (got.some((g) => g.startsWith("RFC 1111") || g.startsWith("RFC 6666") || g.startsWith("W3C"))) {
    failures.push("a correct row, or a row outside the IETF table, was reported");
  }
  let guarded = false;
  try {
    parseIndex("<rfc-index></rfc-index>");
  } catch {
    guarded = true;
  }
  if (!guarded) failures.push("an index with no entries was accepted");
  if (failures.length) {
    console.error(`SELF-TEST FAILED:\n  ${failures.join("\n  ")}`);
    return 1;
  }
  console.log(`self-test passed: ${want.length} differences found, correct rows and the sanity floor held.`);
  return 0;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--self-test")) return selfTest();
  let xml;
  try {
    const at = args.indexOf("--index");
    xml = at >= 0
      ? readFileSync(args[at + 1], "utf8")
      : await (await fetch(INDEX_URL, { signal: AbortSignal.timeout(90_000) })).text();
  } catch (e) {
    console.error(`could not read the index: ${e.message}`);
    return 2;
  }
  let rows, index;
  try {
    const register = args.indexOf("--register");
    rows = parseRegister(readFileSync(register >= 0 ? args[register + 1] : REGISTER, "utf8"));
    index = parseIndex(xml);
  } catch (e) {
    console.error(`could not run the check: ${e.message}`);
    return 2;
  }
  const findings = compare(rows, index);
  const report = findings.length
    ? `${findings.length} difference(s) between the register and the RFC Editor's index:\n\n${findings.map((f) => `- ${f}`).join("\n")}\n\nRe-read each source, then update the row and its \`Read\` date together.`
    : `All ${rows.length} IETF rows match the RFC Editor's index (${index.rfcs.size} RFCs read).`;
  console.log(report);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### Standards register\n\n${report}\n`);
  return findings.length ? 1 : 0;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main());
}
