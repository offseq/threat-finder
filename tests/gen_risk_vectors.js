// Regenerate from the Radar repo: node tests/gen_risk_vectors.js <radar>/server/utils/riskScore.js > tests/risk_vectors.json
const { computeRiskScore } = require(process.argv[2]);
const sevs = [['critical', null], ['high', null], ['medium', null], ['low', null], [null, 9.5], [null, 7.2], [null, 4.1], [null, 0.5], [null, null]];
const epss = [null, 0.1, 0.42, 0.5, 0.97, 1];
const mats = [null, 'WEAPONIZED', 'PUBLIC_EXPLOIT_REMOTE', 'PUBLIC_EXPLOIT', 'POC_HIGH', 'POC_LOW'];
const exps = ['public', 'private', 'loopback', 'none'];
let seed = 7;
const rnd = n => { seed = (seed * 1103515245 + 12345) % 2147483648; return Math.floor(seed / 65536) % n; };
const out = [];
for (let i = 0; i < 200; i++) {
  const [severity, cvssScore] = sevs[rnd(sevs.length)];
  const kev = rnd(3) === 0;
  const input = {
    severity, cvssScore, epss: epss[rnd(epss.length)], kev, kevOverdue: kev && rnd(2) === 0,
    exploitMaturity: mats[rnd(mats.length)], exploitedOutsideKev: rnd(4) === 0, exposure: exps[rnd(exps.length)],
    confirmed: rnd(4) !== 0, eol: rnd(2) === 0
  };
  const r = computeRiskScore(input);
  out.push({ ...input, score: r.score, decision: r.decision, reason: r.reason || null });
}
// eol + exploited only by the threat's own flag (neither KEV nor EUVD/Mirage) never escalates; unconfirmed never does.
for (const [kev, outside, confirmed] of [[false, false, true], [true, false, false], [false, true, false], [true, false, true], [false, true, true]]) {
  const input = { severity: 'low', cvssScore: null, epss: null, kev, kevOverdue: false, exploitMaturity: null, exploitedOutsideKev: outside, exposure: 'none', confirmed, eol: true };
  const r = computeRiskScore(input);
  out.push({ ...input, score: r.score, decision: r.decision, reason: r.reason || null });
}
process.stdout.write(JSON.stringify(out, null, 0).replace(/\},\{/g, '},\n{') + '\n');
