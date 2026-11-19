'use strict';

// Dashboard health score (0-100). The old formula subtracted absolute
// counts (100 - 15C - 8H - 3M - L), so any repo with 7+ criticals sat
// at 0 forever and the number carried no information. This scores the
// severity MIX instead: 100 when nothing is open, 0 when everything
// open is critical, and proportional in between.
function computeHealthScore({ critical = 0, high = 0, medium = 0, low = 0 } = {}) {
  const total = critical + high + medium + low;
  if (total === 0) return 100;
  const weighted = critical * 15 + high * 8 + medium * 3 + low;
  return Math.max(0, Math.round(100 * (1 - weighted / (15 * total))));
}

module.exports = { computeHealthScore };
