import { parse as parseYaml } from "yaml";

export interface ClashProxy {
  name: string;
  type: string;
  server: string;
  port: number;
  [key: string]: unknown;
}

export function parseSubscriptionContent(raw: string): ClashProxy[] {
  const text = raw.trim();
  if (!text) return [];

  // Try base64 decode (common for subscription content in URI format)
  let decoded = text;
  try {
    const buf = atob(text);
    if (buf.length > 0 && /^(ss|vmess|vless|trojan|hysteria2?|hy2|tuic|anytls|wireguard|socks5|http)/m.test(buf)) {
      decoded = buf;
    }
  } catch { /* not base64 */ }

  // Clash YAML format (starts with mixed-port or has proxies: section)
  if (/^\s*(mixed-port:|allow-lan:|mode:|proxies:)/m.test(decoded)) {
    try {
      const parsed = parseYaml(decoded) as { proxies?: ClashProxy[] };
      if (Array.isArray(parsed?.proxies)) {
        return parsed.proxies.filter((p: unknown) => p && typeof p === "object" && "name" in (p as object));
      }
    } catch { /* not YAML */ }
  }

  // JSON format (Clash JSON or proxy array)
  if (/^\s*[\[{]/.test(decoded)) {
    try {
      const parsed = JSON.parse(decoded);
      const proxies = Array.isArray(parsed) ? parsed : parsed.proxies || [];
      return proxies.filter((p: unknown) => p && typeof p === "object" && "name" in (p as object));
    } catch { /* not JSON */ }
  }

  // Parse line-by-line proxy URIs
  return decoded
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#") && !line.startsWith(";"))
    .map(parseProxyLine)
    .filter((p): p is ClashProxy => p !== null);
}

function parseProxyLine(line: string): ClashProxy | null {
  try {
    const decoded = decodeURIComponent(line);
    if (decoded.startsWith("ss://")) return parseSs(decoded);
    if (decoded.startsWith("vmess://")) return parseVmess(decoded);
    if (decoded.startsWith("vless://")) return parseVless(decoded);
    if (decoded.startsWith("trojan://")) return parseTrojan(decoded);
    if (/^hysteria2?:\/\//i.test(decoded)) return parseHysteria2(decoded);
    if (/^hy2:\/\//i.test(decoded)) return parseHysteria2(decoded);
    if (decoded.startsWith("tuic://")) return parseTuic(decoded);
    if (decoded.startsWith("anytls://")) return parseAnyTls(decoded);
    if (decoded.startsWith("http://") || decoded.startsWith("https://")) return parseHttp(decoded);
    if (decoded.startsWith("socks5://")) return parseSocks5(decoded);
    return null;
  } catch {
    return null;
  }
}

function parseUrl(url: string): { protocol: string; userinfo: string; host: string; port: number; params: URLSearchParams; hash: string } {
  const u = new URL(url);
  return {
    protocol: u.protocol.replace(":", ""),
    userinfo: decodeURIComponent(u.username || ""),
    host: u.hostname,
    port: Number(u.port) || 443,
    params: u.searchParams,
    hash: decodeURIComponent(u.hash.replace(/^#/, "")),
  };
}

function parseSs(url: string): ClashProxy {
  // ss://base64(method:password)@host:port#name
  // ss://base64(method:password@host:port)#name
  const rest = url.slice(5);
  const hashIdx = rest.lastIndexOf("#");
  const encoded = hashIdx >= 0 ? rest.slice(0, hashIdx) : rest;
  const nameRaw = hashIdx >= 0 ? rest.slice(hashIdx + 1) : "";

  let decoded = encoded;
  try { decoded = atob(decoded.replace(/@.*/, "")); } catch { /* keep as-is */ }

  const atIdx = decoded.lastIndexOf("@");
  const userinfo = atIdx >= 0 ? decoded.slice(0, atIdx) : "";
  const [method = "aes-256-gcm", ...passwordParts] = userinfo.split(":");
  const password = passwordParts.join(":");

  const hostPart = atIdx >= 0 ? decoded.slice(atIdx + 1) : "";
  const [server = "127.0.0.1", portStr = "8388"] = hostPart.split(":");
  const port = Number(portStr) || 8388;

  let name = decodeURIComponent(nameRaw);
  if (!name && atIdx < 0) name = `${method}:${server}:${port}`;

  return { name, type: "ss", server, port, cipher: method, password };
}

function parseVmess(url: string): ClashProxy | null {
  const raw = url.slice(8);
  let json: Record<string, unknown>;
  try {
    json = JSON.parse(atob(raw));
  } catch {
    return null;
  }
  const port = Number(json.port) || 443;
  const name = String(json.ps || json.remarks || "");
  const proxy: ClashProxy = {
    name,
    type: "vmess",
    server: String(json.add || ""),
    port,
    uuid: String(json.id || ""),
    alterId: Number(json.aid ?? 0),
    cipher: String(json.scy || "auto"),
    udp: true,
  };
  const net = String(json.net || "tcp");
  if (net !== "tcp") {
    proxy.network = net;
    proxy["ws-opts"] = json.host || json.path ? { path: json.path ? String(json.path) : "/" } : undefined;
    if (json.host) (proxy["ws-opts"] as Record<string, unknown>)!["headers"] = { Host: String(json.host) };
  }
  if (json.tls === "tls") proxy.tls = true;
  if (json.sni) proxy.servername = String(json.sni);
  return proxy;
}

function parseVless(url: string): ClashProxy {
  const u = parseUrl(url);
  const name = u.hash || `${u.host}:${u.port}`;
  const proxy: ClashProxy = { name, type: "vless", server: u.host, port: u.port, uuid: u.userinfo, udp: true };

  const flow = u.params.get("flow");
  if (flow) proxy.flow = flow;

  const type = u.params.get("type") || "tcp";
  if (type !== "tcp") {
    proxy.network = type;
    if (type === "grpc") {
      proxy["grpc-opts"] = { "grpc-service-name": u.params.get("serviceName") || "" };
    }
    if (type === "ws") {
      const path = u.params.get("path") || "/";
      const host = u.params.get("host") || "";
      proxy["ws-opts"] = { path };
      if (host) (proxy["ws-opts"] as Record<string, unknown>).headers = { Host: host };
    }
  }

  const security = u.params.get("security") || "none";
  if (security !== "none") proxy.tls = true;
  const sni = u.params.get("sni");
  if (sni) proxy.servername = sni;
  const fp = u.params.get("fp");
  if (fp) proxy["client-fingerprint"] = fp;

  return proxy;
}

function parseTrojan(url: string): ClashProxy {
  const u = parseUrl(url);
  const name = u.hash || `${u.host}:${u.port}`;
  const proxy: ClashProxy = {
    name,
    type: "trojan",
    server: u.host,
    port: u.port,
    password: u.userinfo,
    udp: true,
  };

  const type = u.params.get("type") || "tcp";
  if (type !== "tcp") {
    const sni = u.params.get("sni") || u.host;
    proxy.network = type;
    proxy.sni = sni;
    if (type === "ws") {
      const path = u.params.get("path") || "/";
      const host = u.params.get("host") || "";
      proxy["ws-opts"] = { path, headers: { Host: host } };
    }
  }

  const security = u.params.get("security") || "none";
  if (security !== "none") proxy.tls = true;
  const sni2 = u.params.get("sni");
  if (sni2) proxy.sni = sni2;
  const fp = u.params.get("fp");
  if (fp) proxy["client-fingerprint"] = fp;
  if (u.params.get("allowInsecure") === "1") proxy["skip-cert-verify"] = true;

  return proxy;
}

function parseHysteria2(url: string): ClashProxy {
  const u = parseUrl(url);
  const name = u.hash || `${u.host}:${u.port}`;
  const proxy: ClashProxy = {
    name,
    type: "hysteria2",
    server: u.host,
    port: u.port,
    password: u.userinfo,
    "skip-cert-verify": u.params.get("insecure") === "1" || u.params.get("allowInsecure") === "1",
    up: Number(u.params.get("upmbps")) ? `${u.params.get("upmbps")} Mbps` : undefined,
    down: Number(u.params.get("downmbps")) ? `${u.params.get("downmbps")} Mbps` : undefined,
  };
  const sni = u.params.get("sni") || u.host;
  if (sni) proxy.sni = sni;
  const fp = u.params.get("pinSHA256");
  if (fp) proxy.fingerprint = fp;
  return proxy;
}

function parseTuic(url: string): ClashProxy {
  const u = parseUrl(url);
  const name = u.hash || `${u.host}:${u.port}`;
  return {
    name,
    type: "tuic",
    server: u.host,
    port: u.port,
    uuid: u.userinfo,
    password: u.params.get("password") || "",
    udp: true,
    "skip-cert-verify": u.params.get("allowInsecure") === "1",
    sni: u.params.get("sni") || u.host,
    "congestion-controller": u.params.get("congestion_control") || "bbr",
    "alpn": u.params.get("alpn") ? [u.params.get("alpn")!] : ["h3"],
  };
}

function parseAnyTls(url: string): ClashProxy {
  const u = parseUrl(url);
  const name = u.hash || `${u.host}:${u.port}`;
  return {
    name,
    type: "anytls",
    server: u.host,
    port: u.port,
    password: u.userinfo,
    udp: true,
    "skip-cert-verify": true,
    sni: u.params.get("sni") || u.host,
    alpn: u.params.get("alpn") ? [u.params.get("alpn")!] : undefined,
  };
}

function parseHttp(url: string): ClashProxy {
  const u = parseUrl(url);
  const name = u.hash || `${u.host}:${u.port}`;
  return { name, type: u.protocol, server: u.host, port: u.port, username: u.userinfo, tls: u.protocol === "https" };
}

function parseSocks5(url: string): ClashProxy {
  const u = parseUrl(url);
  const name = u.hash || `${u.host}:${u.port}`;
  return { name, type: "socks5", server: u.host, port: u.port, username: u.userinfo };
}
