const MAX_SUGGESTIONS = 3;

function editDistance(a: string, b: string): number {
  let previous = Array.from({ length: b.length + 1 }, (_, index) => index);
  for (let i = 1; i <= a.length; i++) {
    const current = [i];
    for (let j = 1; j <= b.length; j++) {
      const substitution = (previous[j - 1] ?? 0) + (a[i - 1] === b[j - 1] ? 0 : 1);
      current.push(Math.min(substitution, (previous[j] ?? 0) + 1, (current[j - 1] ?? 0) + 1));
    }
    previous = current;
  }
  return previous[b.length] ?? 0;
}

/** Closest names to a misspelt `input`: a prefix/substring hit or an edit distance of at most
 *  a third of the longer word (min 2). Closest first, capped so the envelope stays short. */
export function didYouMean(input: string, candidates: string[]): string[] {
  return rank(input, candidates).slice(0, MAX_SUGGESTIONS);
}

/** For a small closed set (a group's actions, the groups themselves): the close matches first,
 *  then every remaining name, so a wild guess still gets the complete list of valid choices. */
export function didYouMeanOrAll(input: string, candidates: string[]): string[] {
  const close = rank(input, candidates).slice(0, MAX_SUGGESTIONS);
  return [...close, ...candidates.filter((name) => !close.includes(name))];
}

function rank(input: string, candidates: string[]): string[] {
  const needle = input.toLowerCase();
  const scored: Array<{ name: string; score: number }> = [];
  for (const name of new Set(candidates)) {
    const hay = name.toLowerCase();
    if (hay === needle) {
      continue;
    }
    const distance = editDistance(needle, hay);
    const limit = Math.max(2, Math.floor(Math.max(needle.length, hay.length) / 3));
    const contained = needle.length >= 2 && (hay.includes(needle) || needle.includes(hay));
    if (contained || distance <= limit) {
      scored.push({ name, score: contained ? Math.min(distance, 1) : distance });
    }
  }
  return scored
    .sort((x, y) => x.score - y.score || x.name.localeCompare(y.name))
    .map((entry) => entry.name);
}
