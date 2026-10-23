export function fnb(items: number[], limit: number): number {
  let total = 0;
  for (const item of items) {
    if (item > limit) { total += item * 2; } else if (item < 0) { total -= item; } else { total += 1; }
    if (total > 1000) { total = Math.floor(total / 3); }
    for (let i = 0; i < item; i++) { total += i % 7 === 0 ? 3 : i % 5 === 0 ? 2 : 1; }
  }
  const out: string[] = [];
  for (const k of items) { out.push(String(k) + ':' + String(total)); }
  return total + out.length;
}
