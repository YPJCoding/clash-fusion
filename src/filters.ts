import type { ClashProxy } from "./proxy-parser";

export function dedupeByEndpoint(proxies: ClashProxy[]): ClashProxy[] {
  const seen = new Set<string>();
  return proxies.filter((p) => {
    const key = `${p.server}:${p.port}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function sortByName(proxies: ClashProxy[]): ClashProxy[] {
  return [...proxies].sort((a, b) => a.name.localeCompare(b.name, "zh"));
}

export function excludeByName(proxies: ClashProxy[], pattern: RegExp): ClashProxy[] {
  return proxies.filter((p) => !pattern.test(p.name));
}
