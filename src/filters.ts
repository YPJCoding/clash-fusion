import type { ClashProxy } from "./proxy-parser";

export function dedupeByEndpoint(proxies: ClashProxy[]): ClashProxy[] {
  const seen = new Set<string>();
  return proxies.filter((p) => {
    const key = buildDedupeKey(p);
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

function buildDedupeKey(p: ClashProxy): string {
  const wsOpts = p["ws-opts"] as Record<string, unknown> | undefined;
  const wsHeaders = wsOpts?.headers as Record<string, unknown> | undefined;
  const grpcOpts = p["grpc-opts"] as Record<string, unknown> | undefined;
  const realityOpts = p["reality-opts"] as Record<string, unknown> | undefined;

  return [
    p.type,
    p.server,
    p.port,
    p.cipher,
    p.uuid,
    p.password,
    p.username,
    p.network,
    p.sni,
    p.servername,
    p.flow,
    wsOpts?.path,
    wsHeaders?.Host,
    grpcOpts?.["grpc-service-name"],
    realityOpts?.["public-key"],
    realityOpts?.["short-id"],
  ].map((value) => String(value ?? "")).join("|");
}
