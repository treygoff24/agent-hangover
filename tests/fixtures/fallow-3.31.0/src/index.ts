import { used } from './lib';
export function complexOne(a: number, b: number, c: number): number {
  let r = 0;
  if (a > 1) { if (b > 2) { for (let i = 0; i < a; i++) { if (i % 2) { r += i; } else if (i % 3) { r -= i; } else { r *= 2; } } } else { r = c > 3 ? 1 : c > 2 ? 2 : c > 1 ? 3 : 4; } }
  switch (b) { case 1: r += 1; break; case 2: r += 2; break; case 3: r += 3; break; case 4: r += 4; break; case 5: r += 5; break; default: r = 0; }
  while (r > 100 && a > 0 && b > 0 || c > 5) { r -= 10; if (r < 0) { break; } }
  return r + used();
}
