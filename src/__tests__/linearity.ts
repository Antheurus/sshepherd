import { expect } from 'bun:test';

/** Growth per doubling of the input a linear scan stays under on a loaded machine; a quadratic
 *  one grows about 4x, so the check fails it without an absolute time bound that load can break. */
const MAX_RATIO_PER_DOUBLING = 3;
/** A run this slow on the largest input is a hang, whatever the ratios say. */
const HANG_CEILING_MS = 10_000;
/** Each size is timed this many times and the fastest kept: load only ever adds time. */
const RUNS_PER_SIZE = 3;
/** A linearity test runs its target 22 times (a warm-up, then three sizes three times each), so its
 *  test timeout sits above the hang ceiling rather than at bun's 5 s default. */
export const LINEARITY_TEST_TIMEOUT_MS = 60_000;

/** A deliberately quadratic stand-in for the scrubber, run instead of it when
 *  `SSHEPHERD_LINEARITY_PROOF=quadratic`, to prove each linearity test still fails one. */
function quadraticStandIn(input: string): void {
  let sum = 0;
  for (let i = 0; i < input.length; i += 16) {
    for (let j = i; j < input.length; j += 16) {
      sum += input.charCodeAt(j);
    }
  }
  if (sum < 0) {
    throw new Error('unreachable');
  }
}

function fastestMs(run: (input: string) => void, input: string): number {
  let fastest = Number.POSITIVE_INFINITY;
  for (let attempt = 0; attempt < RUNS_PER_SIZE; attempt += 1) {
    const started = performance.now();
    run(input);
    fastest = Math.min(fastest, performance.now() - started);
  }
  return fastest;
}

/** Times `run` over `make(n)`, `make(2n)` and `make(4n)` and asserts each doubling grows the time
 *  by at most `MAX_RATIO_PER_DOUBLING`, and the largest stays under `HANG_CEILING_MS`. */
export function expectLinear(
  make: (chars: number) => string,
  baseChars: number,
  run: (input: string) => void,
): void {
  const target = process.env.SSHEPHERD_LINEARITY_PROOF === 'quadratic' ? quadraticStandIn : run;
  const inputs = [1, 2, 4].map((scale) => make(baseChars * scale));
  target(inputs[0] ?? '');
  const times = inputs.map((input) => fastestMs(target, input));
  const [small = 0, middle = 0, large = 0] = times;
  const ratios = [middle / small, large / middle];
  const report = {
    kb: inputs.map((input) => Math.round(input.length / 1_024)),
    ms: times.map((ms) => Math.round(ms * 10) / 10),
    ratios: ratios.map((ratio) => Math.round(ratio * 100) / 100),
  };
  expect({
    linear: ratios.every((ratio) => ratio <= MAX_RATIO_PER_DOUBLING),
    hung: large > HANG_CEILING_MS,
    report,
  }).toEqual({ linear: true, hung: false, report });
}
