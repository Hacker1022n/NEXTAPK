import { getStore } from "@netlify/blobs";
import { createHmac, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
export const config = { path: "/api/*" };
const db = () => getStore({ name: "db", consistency: "strong" });
const fs = () => getStore({ name: "files", consistency: "strong" });
const J = (d, s = 200, h = {}) => new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store", ...h } });
const SECRET = process.env.SESSION_SECRET || "";
const MAX = (+process.env.MAX_APK_MB || 20) * 1048576;
const sign = (v) => createHmac("sha256", SECRET).update(v).digest("base64url");
const eq = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const authed = (req) => { const c = (req.headers.get("cookie") || "").match(/nx=(\d+)\.([\w-]+)/); return !!(SECRET && c && eq(c[2], sign(c[1])) && +c[1] > Date.now()); };
const slugify = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60);
const clean = (s, n = 200) => String(s ?? "").replace(/[<>]/g, "").trim().slice(0, n);
const pub = (a) => ({ ...a, versions: a.versions.map(({ ver, vc, size, changelog, date }) => ({ ver, vc, size, changelog, date })) });
const sniff = (b) => (b[0] === 0x89 && b[1] === 0x50 ? "image/png" : b[0] === 0xff && b[1] === 0xd8 ? "image/jpeg" : b[0] === 0x52 && b[1] === 0x49 ? "image/webp" : null);

export default async (req) => {
  const u = new URL(req.url), p = u.pathname.replace(/^\/api\/?/, "").split("/"), m = req.method, d = db();
  const list = async () => (await d.get("apps", { type: "json" })) || [];
  const save = (a) => d.setJSON("apps", a);
  const admin = authed(req);

  if (m !== "GET" && (req.headers.get("x-nx") !== "1" || (req.headers.get("origin") && new URL(req.headers.get("origin")).host !== u.host))) return J({ error: "Blocked request" }, 403);

  if (p[0] === "login" && m === "POST") {
    const ip = req.headers.get("x-nf-client-connection-ip") || "x", k = "rl:" + ip, r = (await d.get(k, { type: "json" })) || { n: 0, t: Date.now() };
    if (Date.now() - r.t > 9e5) { r.n = 0; r.t = Date.now(); }
    if (r.n >= 5) return J({ error: "Too many attempts. Try again in 15 minutes." }, 429);
    const { email, password } = await req.json().catch(() => ({}));
    const [salt, hash] = (process.env.ADMIN_PASSWORD_HASH || ":").split(":");
    let ok = false;
    try { ok = !!SECRET && email === process.env.ADMIN_EMAIL && eq(scryptSync(String(password), salt, 64).toString("hex"), hash); } catch {}
    if (!ok) { r.n++; await d.setJSON(k, r); return J({ error: "Invalid email or password" }, 401); }
    await d.delete(k);
    const exp = Date.now() + 2 * 36e5;
    return J({ ok: true }, 200, { "set-cookie": `nx=${exp}.${sign(String(exp))}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=7200` });
  }
  if (p[0] === "logout") return J({ ok: true }, 200, { "set-cookie": "nx=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0" });
  if (p[0] === "me") return J({ admin });

  if (p[0] === "apps" && m === "GET") {
    let a = await list();
    const now = Date.now();
    if (p[1]) { const x = a.find((v) => v.slug === p[1]); return x && (x.status === "published" || admin) ? J(pub(x)) : J({ error: "Not found" }, 404); }
    if (!(admin && u.searchParams.get("all"))) a = a.filter((v) => v.status === "published" && (!v.publishAt || v.publishAt <= now));
    const q = (u.searchParams.get("q") || "").toLowerCase(), c = u.searchParams.get("cat"), s = u.searchParams.get("sort") || "latest";
    if (q) a = a.filter((v) => [v.name, v.dev, v.pkg, v.cat, v.desc].some((f) => (f || "").toLowerCase().includes(q)));
    if (c) a = a.filter((v) => v.cat === c);
    const by = { latest: (x, y) => y.created - x.created, downloads: (x, y) => y.dl - x.dl, rating: (x, y) => y.rating - x.rating, name: (x, y) => x.name.localeCompare(y.name), updated: (x, y) => y.updated - x.updated };
    a.sort(by[s] || by.latest);
    const page = Math.max(1, +u.searchParams.get("page") || 1);
    return J({ total: a.length, items: a.slice((page - 1) * 24, page * 24).map(pub) });
  }

  if (p[0] === "file" && m === "GET") {
    const r = await fs().getWithMetadata(p[1], { type: "arrayBuffer" });
    if (!r || !r.metadata?.icon) return J({ error: "Not found" }, 404);
    return new Response(r.data, { headers: { "content-type": r.metadata.type, "cache-control": "public, max-age=31536000, immutable", "x-content-type-options": "nosniff" } });
  }

  if (p[0] === "download" && m === "GET") {
    const a = await list(), x = a.find((v) => v.slug === p[1]);
    if (!x || (x.status !== "published" && !admin)) return J({ error: "Not found" }, 404);
    if (x.demo) return J({ error: "This is a sample listing with no file" }, 404);
    const v = x.versions.find((q) => q.ver === u.searchParams.get("v")) || x.versions[0];
    const stream = await fs().get(v.file, { type: "stream" });
    if (!stream) return J({ error: "File missing" }, 404);
    const ck = `dl_${x.slug}`, seen = (req.headers.get("cookie") || "").includes(ck + "=1");
    if (!seen) { x.dl++; await save(a); const day = new Date().toISOString().slice(0, 10), st = (await d.get("stats", { type: "json" })) || {}; st[day] = (st[day] || 0) + 1; await d.setJSON("stats", st); }
    return new Response(stream, { headers: { "content-type": "application/vnd.android.package-archive", "content-disposition": `attachment; filename="${x.slug}-${v.ver.replace(/[^\w.-]/g, "")}.apk"`, "x-content-type-options": "nosniff", "set-cookie": `${ck}=1; Path=/; Max-Age=3600; SameSite=Lax` } });
  }

  if (p[0] !== "admin") return J({ error: "Not found" }, 404);
  if (!admin) return J({ error: "Unauthorized" }, 401);

  if (p[1] === "stats") { const a = await list(), st = (await d.get("stats", { type: "json" })) || {}; const days = (n) => Object.entries(st).filter(([k]) => Date.now() - Date.parse(k) < n * 864e5).reduce((s, [, v]) => s + v, 0); return J({ apps: a.length, total: a.reduce((s, v) => s + v.dl, 0), today: st[new Date().toISOString().slice(0, 10)] || 0, week: days(7), month: days(30), top: [...a].sort((x, y) => y.dl - x.dl).slice(0, 5).map((v) => ({ name: v.name, dl: v.dl })) }); }


  if (p[1] === "demo") {
    const a = await list();
    if (m === "DELETE") { await save(a.filter((v) => !v.demo)); return J({ ok: true }); }
    const S = [["Pixel Racer","Games","Nova Studio","Fast arcade racing with 40 tracks and weekly challenges.",4.7,18400],["Focus Timer","Productivity","Nova Studio","Pomodoro timer with task lists and daily focus stats.",4.8,9200],["SnapEdit","Photography","Lumen Labs","Crop, filter and retouch photos with one-tap presets.",4.6,15300],["Wave Player","Music & Audio","Lumen Labs","Lightweight offline music player with an equalizer.",4.5,12100],["QuickNotes","Tools","Nova Studio","Fast notes with checklists, tags and home-screen widgets.",4.4,7600],["FitTrack","Health & Fitness","Pulse Apps","Log workouts, steps and water intake with weekly charts.",4.6,6800],["Budgetly","Finance","Pulse Apps","Track spending and split bills with simple monthly reports.",4.3,5400],["LearnLingo","Education","Nova Studio","Bite-size vocabulary lessons with spaced repetition.",4.9,21000]];
    const now = Date.now(), add = S.filter(([n]) => !a.some((v) => v.slug === slugify(n))).map(([name, cat, dev, desc, rating, dl], i) => ({ slug: slugify(name), name, cat, dev, desc, rating, rc: Math.round(dl / 9), dl, pkg: "com.sample." + slugify(name).replace(/-/g, ""), ver: "1." + (i + 1) + ".0", vc: i + 1, size: 8e6 + i * 2e6, minSdk: 24, targetSdk: 34, icon: null, status: "published", featured: i < 3, demo: true, created: now - i * 864e5, updated: now - i * 432e5, versions: [{ ver: "1." + (i + 1) + ".0", vc: i + 1, size: 8e6 + i * 2e6, changelog: "Sample listing.", date: now - i * 864e5, file: null }] }));
    await save([...a, ...add]); return J({ added: add.length });
  }

  if (p[1] === "chunk" && m === "POST") {
    const id = u.searchParams.get("id") || "", i = +u.searchParams.get("i");
    if (!/^[\w-]{36}$/.test(id) || !(i >= 0 && i < 64)) return J({ error: "Bad chunk" }, 400);
    const buf = await req.arrayBuffer();
    if (buf.byteLength > 5e6) return J({ error: "Chunk too large" }, 413);
    await fs().set(`up/${id}/${i}`, buf); return J({ ok: true });
  }

  if (p[1] === "apps" && m === "POST") {
    const b = await req.json().catch(() => null); if (!b) return J({ error: "Invalid JSON" }, 400);
    const name = clean(b.name, 80), pkg = clean(b.pkg, 150), ver = clean(b.ver, 30);
    if (!name || !/^[a-zA-Z][\w]*(\.[a-zA-Z][\w]*)+$/.test(pkg) || !ver || !/^[\w-]{36}$/.test(b.uploadId || "")) return J({ error: "Name, valid package name (com.example.app), version and APK are required" }, 400);
    const f = fs(), parts = [];
    for (let i = 0; i < +b.chunks; i++) { const c = await f.get(`up/${b.uploadId}/${i}`, { type: "arrayBuffer" }); if (!c) return J({ error: "Upload incomplete" }, 400); parts.push(Buffer.from(c)); }
    const apk = Buffer.concat(parts);
    for (let i = 0; i < +b.chunks; i++) await f.delete(`up/${b.uploadId}/${i}`);
    if (apk.length > MAX) return J({ error: `APK exceeds ${MAX / 1048576} MB limit` }, 413);
    if (apk.readUInt32LE(0) !== 0x04034b50 || !apk.includes("AndroidManifest.xml")) return J({ error: "Not a valid APK file" }, 400);
    const fid = randomUUID(); await f.set(fid, apk);
    let icon = null;
    const im = /^data:image\/\w+;base64,(.+)$/.exec(b.icon || "");
    if (im) { const ib = Buffer.from(im[1], "base64"), t = sniff(ib); if (t && ib.length < 1e6) { icon = randomUUID(); await f.set(icon, ib, { metadata: { icon: true, type: t } }); } }
    const a = await list(), now = Date.now();
    let x = a.find((v) => v.pkg === pkg);
    const rel = { ver, vc: +b.vc || 0, size: apk.length, changelog: clean(b.changelog, 2000), date: now, file: fid };
    if (x) { if (x.versions.some((v) => v.ver === ver)) return J({ error: "That version already exists" }, 409); x.versions.unshift(rel); x.updated = now; if (icon) x.icon = "/api/file/" + icon; }
    else { let slug = slugify(name) || "app"; while (a.some((v) => v.slug === slug)) slug += "-" + Math.random().toString(36).slice(2, 5); x = { slug, pkg, dl: 0, rating: 0, created: now, updated: now, versions: [rel], icon: icon && "/api/file/" + icon }; a.push(x); }
    Object.assign(x, { name, dev: clean(b.dev, 80), cat: clean(b.cat, 40) || "Other", desc: clean(b.desc, 8000), minSdk: +b.minSdk || null, targetSdk: +b.targetSdk || null, ver, vc: rel.vc, size: apk.length, status: b.status === "published" ? "published" : "draft", featured: !!b.featured });
    await save(a); return J(pub(x), 201);
  }

  if (p[1] === "apps" && p[2]) {
    const a = await list(), x = a.find((v) => v.slug === p[2]); if (!x) return J({ error: "Not found" }, 404);
    if (m === "DELETE") { for (const v of x.versions) if (v.file) await fs().delete(v.file); await save(a.filter((v) => v !== x)); return J({ ok: true }); }
    if (m === "PATCH") { const b = await req.json(); if (b.status) x.status = b.status === "published" ? "published" : "draft"; if ("featured" in b) x.featured = !!b.featured; if (b.desc != null) x.desc = clean(b.desc, 8000); x.updated = Date.now(); await save(a); return J(pub(x)); }
  }
  return J({ error: "Not found" }, 404);
};
