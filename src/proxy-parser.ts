import { parse as parseYaml } from "yaml";

export interface ClashProxy {
  name: string;
  type: string;
  server: string;
  port: number;
  [key: string]: unknown;
}

interface ParsedUrl {
  protocol: string;
  username: string;
  password: string;
  userinfo: string;
  host: string;
  port: number;
  params: URLSearchParams;
  hash: string;
}

export function parseSubscriptionContent(raw: string): ClashProxy[] {
  const text = raw.trim();
  if (!text) return [];

  // Try base64 decode (common for subscription content in URI format)
  let decoded = text;
  const base64Decoded = decodeBase64Flexible(text);
  if (base64Decoded && /^(ss|vmess|vless|trojan|hysteria2?|hy2|tuic|anytls|wireguard|socks5|http)/im.test(base64Decoded.trim())) {
    decoded = base64Decoded;
  }

  // Clash YAML format (starts with mixed-port or has proxies: section)
  if (/^\s*(mixed-port:|allow-lan:|mode:|proxies:)/m.test(decoded)) {
    try {
      const parsed = parseYaml(decoded) as { proxies?: ClashProxy[] };
      if (Array.isArray(parsed?.proxies)) {
        return parsed.proxies.filter(isProxyLike);
      }
    } catch { /* not YAML */ }
  }

  // JSON format (Clash JSON or proxy array)
  if (/^\s*[\[{]/.test(decoded)) {
    try {
      const parsed = JSON.parse(decoded);
      const proxies = Array.isArray(parsed) ? parsed : parsed.proxies || [];
      return proxies.filter(isProxyLike);
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

function isProxyLike(p: unknown): p is ClashProxy {
  return !!p && typeof p === "object" && "name" in p && "type" in p && "server" in p && "port" in p;
}

function parseProxyLine(line: string): ClashProxy | null {
  try {
    const lower = line.toLowerCase();
    if (lower.startsWith("ss://")) return parseSs(line);
    if (lower.startsWith("vmess://")) return parseVmess(line);
    if (lower.startsWith("vless://")) return parseVless(line);
    if (lower.startsWith("trojan://")) return parseTrojan(line);
    if (/^hysteria2?:\/\//i.test(line)) return parseHysteria2(line);
    if (/^hy2:\/\//i.test(line)) return parseHysteria2(line);
    if (lower.startsWith("tuic://")) return parseTuic(line);
    if (lower.startsWith("anytls://")) return parseAnyTls(line);
    if (lower.startsWith("http://") || lower.startsWith("https://")) return parseHttp(line);
    if (lower.startsWith("socks5://")) return parseSocks5(line);
    return null;
  } catch {
    return null;
  }
}

function parseUrl(url: string): ParsedUrl {
  const u = new URL(url);
  const protocol = u.protocol.replace(":", "").toLowerCase();
  const username = safeDecodeURIComponent(u.username || "");
  const password = safeDecodeURIComponent(u.password || "");
  return {
    protocol,
    username,
    password,
    userinfo: password ? `${username}:${password}` : username,
    host: u.hostname,
    port: Number(u.port) || defaultPort(protocol),
    params: u.searchParams,
    hash: safeDecodeURIComponent(u.hash.replace(/^#/, "")),
  };
}

function defaultPort(protocol: string): number {
  if (protocol === "http") return 80;
  if (protocol === "socks5") return 1080;
  return 443;
}

function parseSs(url: string): ClashProxy | null {
  // Supported formats:
  // ss://base64(method:password)@host:port#name
  // ss://base64(method:password@host:port)#name
  // ss://method:password@host:port#name
  const rest = url.slice(5);
  const hashIdx = rest.indexOf("#");
  const withoutHash = hashIdx >= 0 ? rest.slice(0, hashIdx) : rest;
  const nameRaw = hashIdx >= 0 ? rest.slice(hashIdx + 1) : "";
  const queryIdx = withoutHash.indexOf("?");
  const main = queryIdx >= 0 ? withoutHash.slice(0, queryIdx) : withoutHash;
  const params = new URLSearchParams(queryIdx >= 0 ? withoutHash.slice(queryIdx + 1) : "");

  let method = "";
  let password = "";
  let server = "";
  let port = 8388;

  const atIdx = main.lastIndexOf("@");
  if (atIdx >= 0) {
    const userPart = main.slice(0, atIdx);
    const hostPart = main.slice(atIdx + 1);
    const decodedUser = decodeBase64Flexible(userPart) || safeDecodeURIComponent(userPart);
    [method, password] = splitOnce(decodedUser, ":");
    ({ host: server, port } = parseHostPort(hostPart, 8388));
  } else {
    const decoded = decodeBase64Flexible(main) || safeDecodeURIComponent(main);
    const decodedAtIdx = decoded.lastIndexOf("@");
    if (decodedAtIdx >= 0) {
      const userPart = decoded.slice(0, decodedAtIdx);
      const hostPart = decoded.slice(decodedAtIdx + 1);
      [method, password] = splitOnce(userPart, ":");
      ({ host: server, port } = parseHostPort(hostPart, 8388));
    }
  }

  if (!method || !server || !password) return null;

  const proxy: ClashProxy = {
    name: safeDecodeURIComponent(nameRaw) || `${server}:${port}`,
    type: "ss",
    server,
    port,
    cipher: method,
    password,
  };

  const plugin = params.get("plugin");
  if (plugin) proxy.plugin = plugin;

  return proxy;
}

function parseVmess(url: string): ClashProxy | null {
  const raw = url.slice(8);
  let json: Record<string, unknown>;
  try {
    const decoded = decodeBase64Flexible(raw);
    if (!decoded) return null;
    json = JSON.parse(decoded);
  } catch {
    return null;
  }

  const port = Number(json.port) || 443;
  const name = String(json.ps || json.remarks || `${json.add || ""}:${port}`);
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

  const net = String(json.net || "tcp").toLowerCase();
  if (net !== "tcp") proxy.network = net;

  if (net === "ws") {
    const path = json.path ? String(json.path) : "/";
    const host = json.host ? String(json.host) : "";
    proxy["ws-opts"] = { path };
    if (host) (proxy["ws-opts"] as Record<string, unknown>).headers = { Host: host };
  } else if (net === "grpc") {
    proxy["grpc-opts"] = { "grpc-service-name": json.path ? String(json.path) : "" };
  }

  if (json.tls === "tls" || json.tls === true) proxy.tls = true;
  if (json.sni) proxy.servername = String(json.sni);
  return proxy;
}

function parseVless(url: string): ClashProxy {
  const u = parseUrl(url);
  const name = u.hash || `${u.host}:${u.port}`;
  const proxy: ClashProxy = { name, type: "vless", server: u.host, port: u.port, uuid: u.username, udp: true };

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
  if (u.params.get("allowInsecure") === "1" || u.params.get("insecure") === "1") proxy["skip-cert-verify"] = true;

  if (security === "reality") {
    const publicKey = u.params.get("pbk");
    const shortId = u.params.get("sid");
    if (publicKey || shortId) {
      proxy["reality-opts"] = {
        ...(publicKey ? { "public-key": publicKey } : {}),
        ...(shortId ? { "short-id": shortId } : {}),
      };
    }
  }

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
    proxy.network = type;
    if (type === "ws") {
      const path = u.params.get("path") || "/";
      const host = u.params.get("host") || "";
      proxy["ws-opts"] = { path };
      if (host) (proxy["ws-opts"] as Record<string, unknown>).headers = { Host: host };
    }
    if (type === "grpc") {
      proxy["grpc-opts"] = { "grpc-service-name": u.params.get("serviceName") || "" };
    }
  }

  const security = u.params.get("security") || "none";
  if (security !== "none") proxy.tls = true;
  const sni = u.params.get("sni");
  if (sni) proxy.sni = sni;
  const fp = u.params.get("fp");
  if (fp) proxy["client-fingerprint"] = fp;
  if (u.params.get("allowInsecure") === "1" || u.params.get("insecure") === "1") proxy["skip-cert-verify"] = true;

  return proxy;
}

function parseHysteria2(url: string): ClashProxy {
  const u = parseUrl(url.replace(/^hy2:\/\//i, "hysteria2://"));
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
  const password = u.password || u.params.get("password") || "";
  const alpn = u.params.get("alpn");
  return {
    name,
    type: "tuic",
    server: u.host,
    port: u.port,
    uuid: u.username,
    password,
    udp: true,
    "skip-cert-verify": u.params.get("allowInsecure") === "1" || u.params.get("insecure") === "1",
    sni: u.params.get("sni") || u.host,
    "congestion-controller": u.params.get("congestion_control") || "bbr",
    alpn: alpn ? alpn.split(",").map((item) => item.trim()).filter(Boolean) : ["h3"],
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
    "skip-cert-verify": u.params.get("allowInsecure") === "1" || u.params.get("insecure") === "1",
    sni: u.params.get("sni") || u.host,
    alpn: u.params.get("alpn") ? [u.params.get("alpn")!] : undefined,
  };
}

function parseHttp(url: string): ClashProxy {
  const u = parseUrl(url);
  const name = u.hash || `${u.host}:${u.port}`;
  return {
    name,
    type: "http",
    server: u.host,
    port: u.port,
    username: u.username || undefined,
    password: u.password || undefined,
    tls: u.protocol === "https" || undefined,
  };
}

function parseSocks5(url: string): ClashProxy {
  const u = parseUrl(url);
  const name = u.hash || `${u.host}:${u.port}`;
  return {
    name,
    type: "socks5",
    server: u.host,
    port: u.port,
    username: u.username || undefined,
    password: u.password || undefined,
  };
}

function decodeBase64Flexible(value: string): string | null {
  const normalized = value.trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!normalized) return null;
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

function safeDecodeURIComponent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function splitOnce(value: string, separator: string): [string, string] {
  const idx = value.indexOf(separator);
  if (idx < 0) return [value, ""];
  return [value.slice(0, idx), value.slice(idx + separator.length)];
}

function parseHostPort(value: string, defaultPortValue: number): { host: string; port: number } {
  const decoded = safeDecodeURIComponent(value);
  if (decoded.startsWith("[")) {
    const end = decoded.indexOf("]");
    if (end >= 0) {
      const host = decoded.slice(1, end);
      const rest = decoded.slice(end + 1);
      return { host, port: rest.startsWith(":") ? Number(rest.slice(1)) || defaultPortValue : defaultPortValue };
    }
  }

  const idx = decoded.lastIndexOf(":");
  if (idx > 0 && decoded.indexOf(":") === idx) {
    return { host: decoded.slice(0, idx), port: Number(decoded.slice(idx + 1)) || defaultPortValue };
  }

  return { host: decoded, port: defaultPortValue };
}
