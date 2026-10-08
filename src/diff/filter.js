// dotnet-codereview-framework — src/diff/filter.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Partition correlated findings into what the diff mode reports and what it withholds.
 *
 * HONESTY — WHAT --diff CANNOT SEE: a taint finding is reported at its SINK. If a change
 * introduces a taint SOURCE in file A and the sink is in unchanged file B, this filter sees the
 * finding only if the producing tool emitted A as an additionalLocation (--diff-context then
 * catches it). Tools that emit a single location give us nothing to correlate, so such a finding
 * WILL be missed by --diff and is only caught by a full review. --diff is therefore a fast PR
 * gate, not a replacement for the scheduled full scan.
 *
 * Bucket semantics (disjoint; the three counts always sum to findings.length):
 *   'primary'  — the finding's own location file is in the changed set. Always in `inDiff`.
 *   'context'  — the primary file is unchanged, but at least one additionalLocations[].file is
 *                in the changed set. Returned in `contextual` unless opts.context is true, in
 *                which case it moves into `inDiff` (reported AND gating).
 *   'outside'  — neither. Always in `outOfDiff`, never reported in diff mode.
 *
 * Every returned finding is the SAME object with a `diffRelation` property added; input order
 * is preserved within each bucket; `changedSet` is never mutated.
 */

const { normalisePath } = require('./changed-files');

const DIFF_RELATION = Object.freeze({
  PRIMARY: 'primary',
  CONTEXT: 'context',
  OUTSIDE: 'outside'
});

/**
 * @param {Array<object>} findings canonical findings (correlate() output shape)
 * @param {Set<string>} changedSet normalised repo-relative paths (see changed-files.js)
 * @param {{context?: boolean}} opts context: also pull 'context' findings into inDiff
 * @returns {{inDiff: Array, contextual: Array, outOfDiff: Array}}
 */
function partitionFindings(findings, changedSet, opts = {}) {
  const includeContext = opts.context === true;
  const inDiff = [];
  const contextual = [];
  const outOfDiff = [];

  for (const f of findings) {
    const loc = f.location || {};
    let relation;
    if (changedSet.has(normalisePath(loc.file))) {
      relation = DIFF_RELATION.PRIMARY;
    } else if ((loc.additionalLocations || [])
      .some(l => changedSet.has(normalisePath(l && l.file)))) {
      relation = DIFF_RELATION.CONTEXT;
    } else {
      relation = DIFF_RELATION.OUTSIDE;
    }

    f.diffRelation = relation; // the same object, annotated — never a copy

    if (relation === DIFF_RELATION.PRIMARY) {
      inDiff.push(f);
    } else if (relation === DIFF_RELATION.CONTEXT) {
      if (includeContext) inDiff.push(f); else contextual.push(f);
    } else {
      outOfDiff.push(f);
    }
  }

  return { inDiff, contextual, outOfDiff };
}

module.exports = { partitionFindings, DIFF_RELATION };
