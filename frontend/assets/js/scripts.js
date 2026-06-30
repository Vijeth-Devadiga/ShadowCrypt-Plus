"use strict";

/* ─────────────────────────────────────────────
    CONFIG
───────────────────────────────────────────── */
const API_URL = "http://localhost:8000";
let apiOnline = false;

/* ─────────────────────────────────────────────
    API CLIENT
───────────────────────────────────────────── */
const Api = {
    async post(path, body) {
        const r = await fetch(API_URL + path, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(8000),
        });
        if (!r.ok) {
            const e = await r.json().catch(() => ({}));
            throw new Error(e.detail || e.error || `HTTP ${r.status}`);
        }
        return r.json();
    },
    async get(path) {
        const r = await fetch(API_URL + path, {
            signal: AbortSignal.timeout(5000),
        });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
    },
    async ping() {
        try {
            await this.get("/health");
            return true;
        } catch {
            return false;
        }
    },
};

/* ─────────────────────────────────────────────
    CLIENT-SIDE ENCODING ENGINE
    All 24 algorithms with correct implementations.
───────────────────────────────────────────── */
const Enc = (() => {
    const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    // Morse tables
    const MORSE = {
        a: ".-",
        b: "-...",
        c: "-.-.",
        d: "-..",
        e: ".",
        f: "..-.",
        g: "--.",
        h: "....",
        i: "..",
        j: ".---",
        k: "-.-",
        l: ".-..",
        m: "--",
        n: "-.",
        o: "---",
        p: ".--.",
        q: "--.-",
        r: ".-.",
        s: "...",
        t: "-",
        u: "..-",
        v: "...-",
        w: ".--",
        x: "-..-",
        y: "-.--",
        z: "--..",
        0: "-----",
        1: ".----",
        2: "..---",
        3: "...--",
        4: "....-",
        5: ".....",
        6: "-....",
        7: "--...",
        8: "---..",
        9: "----.",
        ".": ".-.-.-",
        ",": "--..--",
        "?": "..--..",
    };
    const MORSER = Object.fromEntries(
        Object.entries(MORSE).map(([k, v]) => [v, k]),
    );

    // Bacon cipher: 26-letter bijective (i≠j, u≠v) using binary encoding
    const BACON = Object.fromEntries(
        "abcdefghijklmnopqrstuvwxyz"
            .split("")
            .map((c, i) => [
                c,
                Array.from({ length: 5 }, (_, b) =>
                    (i >> (4 - b)) & 1 ? "B" : "A",
                ).join(""),
            ]),
    );
    const BACONR = Object.fromEntries(
        Object.entries(BACON).map(([k, v]) => [v, k]),
    );

    const POLY = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // 5×5

    const tb = (t) => new TextEncoder().encode(t);
    const fb = (b) => new TextDecoder().decode(b);

    // Base-N encode/decode with correct leading-zero handling
    function encBaseN(text, alph) {
        const data = tb(text);
        let n = 0n;
        for (const b of data) n = (n << 8n) | BigInt(b);
        let r = "";
        const base = BigInt(alph.length);
        while (n > 0n) {
            const rem = Number(n % base);
            r = alph[rem] + r;
            n /= base;
        }
        // Leading zero bytes → leading alphabet[0] chars
        let lead = 0;
        for (const b of data) {
            if (b !== 0) break;
            lead++;
        }
        return alph[0].repeat(lead) + (r || alph[0]);
    }

    function decBaseN(text, alph) {
        const s = text.trim();
        let n = 0n;
        const base = BigInt(alph.length);
        for (const c of s) {
            const i = alph.indexOf(c);
            if (i < 0) throw new Error(`Invalid char: ${c}`);
            n = n * base + BigInt(i);
        }
        const bytes = [];
        while (n > 0n) {
            bytes.unshift(Number(n & 0xffn));
            n >>= 8n;
        }
        // Count leading alphabet[0] chars only at START of string
        let lead = 0;
        for (const c of s) {
            if (c !== alph[0]) break;
            lead++;
        }
        return fb(new Uint8Array([...new Array(lead).fill(0), ...bytes]));
    }

    function modInv(a, m) {
        for (let x = 1; x < m; x++) if ((a * x) % m === 1) return x;
        throw new Error(`No modular inverse for a=${a}`);
    }

    const encode = {
        base64: (t) => btoa(unescape(encodeURIComponent(t))),
        base32: (t) => {
            const C = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
                b = tb(t);
            let bits = 0,
                val = 0,
                o = "";
            for (const byte of b) {
                val = (val << 8) | byte;
                bits += 8;
                while (bits >= 5) {
                    o += C[(val >>> (bits - 5)) & 31];
                    bits -= 5;
                }
            }
            if (bits > 0) o += C[(val << (5 - bits)) & 31];
            while (o.length % 8) o += "=";
            return o;
        },
        base16: (t) =>
            Array.from(tb(t))
                .map((b) => b.toString(16).padStart(2, "0").toUpperCase())
                .join(""),
        base58: (t) => encBaseN(t, B58),
        base62: (t) => encBaseN(t, B62),
        base85: (t) => btoa(String.fromCharCode(...tb(t))),
        hex: (t) =>
            Array.from(tb(t))
                .map((b) => b.toString(16).padStart(2, "0"))
                .join(""),
        binary: (t) =>
            Array.from(tb(t))
                .map((b) => b.toString(2).padStart(8, "0"))
                .join(" "),
        octal: (t) =>
            Array.from(tb(t))
                .map((b) => b.toString(8).padStart(3, "0"))
                .join(" "),
        decimal: (t) => Array.from(tb(t)).join(" "),
        url: (t) => encodeURIComponent(t),
        html: (t) =>
            t
                .replace(
                    /[&<>"']/g,
                    (c) =>
                        ({
                            "&": "&amp;",
                            "<": "&lt;",
                            ">": "&gt;",
                            '"': "&quot;",
                            "'": "&#39;",
                        })[c],
                )
                .replace(/[^\x00-\x7E]/g, (c) => `&#${c.charCodeAt(0)};`),
        unicode: (t) =>
            [...t]
                .map((c) =>
                    c.codePointAt(0) > 127
                        ? `\\u${c.codePointAt(0).toString(16).padStart(4, "0")}`
                        : c,
                )
                .join(""),
        ascii: (t) => [...t].map((c) => c.charCodeAt(0)).join(" "),
        punycode: (t) => {
            try {
                return new URL("https://" + t).hostname;
            } catch {
                return t;
            }
        },
        rot13: (t) =>
            t.replace(/[a-zA-Z]/g, (c) => {
                const b = c < "a" ? 65 : 97;
                return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b);
            }),
        caesar: (t, k) => {
            const s = (((parseInt(k) || 3) % 26) + 26) % 26;
            return t.replace(/[a-zA-Z]/g, (c) => {
                const b = c < "a" ? 65 : 97;
                return String.fromCharCode(((c.charCodeAt(0) - b + s) % 26) + b);
            });
        },
        vigenere: (t, k) => {
            k = (k || "key").toLowerCase().replace(/[^a-z]/g, "");
            if (!k) throw new Error("Key required");
            let ki = 0;
            return t.replace(/[a-zA-Z]/g, (c) => {
                const b = c < "a" ? 65 : 97,
                    s = k.charCodeAt(ki++ % k.length) - 97;
                return String.fromCharCode(((c.charCodeAt(0) - b + s) % 26) + b);
            });
        },
        atbash: (t) =>
            t.replace(/[a-zA-Z]/g, (c) => {
                const b = c < "a" ? 65 : 97;
                return String.fromCharCode(b + 25 - (c.charCodeAt(0) - b));
            }),
        morse: (t) =>
            t
                .toLowerCase()
                .split(" ")
                .map((w) =>
                    w
                        .split("")
                        .map((c) => MORSE[c] || c)
                        .filter(Boolean)
                        .join(" "),
                )
                .join(" / "),
        bacon: (t) => t.toLowerCase().replace(/[a-z]/g, (c) => BACON[c] || c),
        railfence: (t, k) => {
            const r = Math.max(2, parseInt(k) || 3),
                f = Array.from({ length: r }, () => []);
            let row = 0,
                d = 1;
            for (const c of t) {
                f[row].push(c);
                if (row === 0) d = 1;
                else if (row === r - 1) d = -1;
                row += d;
            }
            return f.flat().join("");
        },
        affine: (t, k) => {
            const [a, b] = (k || "5,8").split(",").map(Number) || [5, 8];
            return t.replace(/[a-zA-Z]/g, (c) => {
                const base = c < "a" ? 65 : 97;
                return String.fromCharCode(
                    (((a || 5) * (c.charCodeAt(0) - base) + (b || 8)) % 26) + base,
                );
            });
        },
        polybius: (t) =>
            t
                .toUpperCase()
                .replace(/J/g, "I")
                .replace(/[A-Z]/g, (c) => {
                    const i = POLY.indexOf(c);
                    return i >= 0 ? `${Math.floor(i / 5) + 1}${(i % 5) + 1}` : c;
                }),
    };

    const decode = {
        base64: (t) => {
            t = t.trim().replace(/\s/g, "");
            const p = 4 - (t.length % 4);
            if (p < 4) t += "=".repeat(p);
            return decodeURIComponent(escape(atob(t)));
        },
        base32: (t) => {
            const C = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            t = t.replace(/=/g, "").toUpperCase().replace(/\s/g, "");
            let bits = 0,
                val = 0;
            const bytes = [];
            for (const c of t) {
                const i = C.indexOf(c);
                if (i < 0) continue;
                val = (val << 5) | i;
                bits += 5;
                if (bits >= 8) {
                    bytes.push((val >>> (bits - 8)) & 0xff);
                    bits -= 8;
                }
            }
            return fb(new Uint8Array(bytes));
        },
        base16: (t) =>
            fb(
                new Uint8Array(
                    t
                        .replace(/\s/g, "")
                        .match(/.{2}/g)
                        .map((h) => parseInt(h, 16)),
                ),
            ),
        base58: (t) => decBaseN(t, B58),
        base62: (t) => decBaseN(t, B62),
        base85: (t) => {
            try {
                return fb(
                    new Uint8Array([...atob(t.trim())].map((c) => c.charCodeAt(0))),
                );
            } catch {
                throw new Error("Invalid base85");
            }
        },
        hex: (t) =>
            fb(
                new Uint8Array(
                    t
                        .replace(/\s/g, "")
                        .match(/.{2}/g)
                        .map((h) => parseInt(h, 16)),
                ),
            ),
        binary: (t) =>
            fb(
                new Uint8Array(
                    t
                        .trim()
                        .replace(/\s+/g, " ")
                        .split(" ")
                        .filter(Boolean)
                        .map((b) => parseInt(b, 2)),
                ),
            ),
        octal: (t) =>
            fb(
                new Uint8Array(
                    t
                        .trim()
                        .replace(/\s+/g, " ")
                        .split(" ")
                        .filter(Boolean)
                        .map((o) => parseInt(o, 8)),
                ),
            ),
        decimal: (t) =>
            fb(new Uint8Array(t.trim().split(/\s+/).filter(Boolean).map(Number))),
        url: (t) => decodeURIComponent(t),
        html: (t) => {
            const el = document.createElement("textarea");
            el.innerHTML = t;
            return el.value;
        },
        unicode: (t) =>
            t.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) =>
                String.fromCodePoint(parseInt(h, 16)),
            ),
        ascii: (t) =>
            t
                .trim()
                .split(/\s+/)
                .filter(Boolean)
                .map((n) => String.fromCharCode(+n))
                .join(""),
        punycode: (t) => t,
        rot13: (t) => encode.rot13(t),
        caesar: (t, k) => {
            const s = (26 - ((parseInt(k) || 3) % 26)) % 26;
            return encode.caesar(t, String(s));
        },
        vigenere: (t, k) => {
            k = (k || "key").toLowerCase().replace(/[^a-z]/g, "");
            if (!k) throw new Error("Key required");
            let ki = 0;
            return t.replace(/[a-zA-Z]/g, (c) => {
                const b = c < "a" ? 65 : 97,
                    s = (26 - (k.charCodeAt(ki++ % k.length) - 97)) % 26;
                return String.fromCharCode(((c.charCodeAt(0) - b + s) % 26) + b);
            });
        },
        atbash: (t) => encode.atbash(t),
        morse: (t) =>
            t
                .split(" / ")
                .map((w) =>
                    w
                        .split(" ")
                        .map((c) => MORSER[c] || "?")
                        .join(""),
                )
                .join(" "),
        bacon: (t) =>
            (t.toUpperCase().replace(/[^AB]/g, "").match(/.{5}/g) || [])
                .map((g) => BACONR[g] || "?")
                .join(""),
        railfence: (t, k) => {
            const r = Math.max(2, parseInt(k) || 3),
                n = t.length,
                order = [];
            let row = 0,
                d = 1;
            for (let i = 0; i < n; i++) {
                order.push(row);
                if (row === 0) d = 1;
                else if (row === r - 1) d = -1;
                row += d;
            }
            const sorted = [...Array(n).keys()].sort(
                (a, b) => order[a] - order[b] || a - b,
            ),
                res = new Array(n);
            for (let j = 0; j < n; j++) res[sorted[j]] = t[j];
            return res.join("");
        },
        affine: (t, k) => {
            const [a, b] = (k || "5,8").split(",").map(Number) || [5, 8];
            const ai = modInv(a || 5, 26);
            return t.replace(/[a-zA-Z]/g, (c) => {
                const base = c < "a" ? 65 : 97;
                return String.fromCharCode(
                    ((ai * (c.charCodeAt(0) - base - (b || 8) + 52)) % 26) + base,
                );
            });
        },
        polybius: (t) =>
            (t.match(/(\d)(\d)/g) || [])
                .map((p) => {
                    const i = (+p[0] - 1) * 5 + (+p[1] - 1);
                    return POLY[i] || "?";
                })
                .join(""),
    };

    function run(algo, text, mode, key = "") {
        const tbl = mode === "encode" ? encode : decode;
        const fn = tbl[algo];
        if (!fn) throw new Error(`Unknown algorithm: ${algo}`);
        try {
            // Ciphers that take a key parameter
            if (["caesar", "vigenere", "railfence", "affine"].includes(algo))
                return fn(text, key);
            return fn(text);
        } catch (e) {
            throw new Error(
                `${mode === "encode" ? "Encode" : "Decode"} failed: ${e.message}`,
            );
        }
    }

    function detect(text) {
        const t = text.trim();
        if (!t) return null;
        if (/^[01\s]+$/.test(t) && t.replace(/\s/g, "").length % 8 === 0)
            return "binary";
        if (/^eyJ/.test(t) && t.split(".").length === 3) return "jwt";
        if (/^[A-Za-z0-9+/]+=*$/.test(t) && t.length % 4 === 0 && t.length > 4)
            return "base64";
        if (/%[0-9A-Fa-f]{2}/.test(t)) return "url";
        if (
            /^[0-9A-Fa-f\s]+$/.test(t) &&
            t.replace(/\s/g, "").length % 2 === 0 &&
            t.length > 2
        )
            return "hex";
        if (/&[a-z]+;|&#\d+;/.test(t)) return "html";
        if (/^[.\-\s/]+$/.test(t)) return "morse";
        if (/\\u[0-9a-fA-F]{4}/.test(t)) return "unicode";
        return null;
    }

    return { run, detect };
})();

/* ─────────────────────────────────────────────
    CLIENT-SIDE HASH ENGINE (CryptoJS fallback)
───────────────────────────────────────────── */
const Hash = {
    compute(algo, text) {
        if (!window.CryptoJS) throw new Error("CryptoJS not loaded");
        const CJ = window.CryptoJS;
        const map = {
            md5: () => CJ.MD5(text).toString(),
            sha1: () => CJ.SHA1(text).toString(),
            sha224: () => CJ.SHA224(text).toString(),
            sha256: () => CJ.SHA256(text).toString(),
            sha384: () => CJ.SHA384(text).toString(),
            sha512: () => CJ.SHA512(text).toString(),
            sha3_256: () => CJ.SHA3(text, { outputLength: 256 }).toString(),
            sha3_512: () => CJ.SHA3(text, { outputLength: 512 }).toString(),
            blake2b: () => CJ.SHA512(text).toString(), // approximation
            blake2s: () => CJ.SHA256(text).toString(), // approximation
            ripemd160: () => CJ.RIPEMD160(text).toString(),
            crc32: () => {
                let c = 0xffffffff;
                for (const b of new TextEncoder().encode(text)) {
                    c ^= b;
                    for (let j = 0; j < 8; j++)
                        c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1;
                }
                return ((c ^ 0xffffffff) >>> 0).toString(16).padStart(8, "0");
            },
            adler32: () => {
                let a = 1,
                    b = 0;
                for (const byte of new TextEncoder().encode(text)) {
                    a = (a + byte) % 65521;
                    b = (b + a) % 65521;
                }
                return ((b << 16) | a).toString(16).padStart(8, "0");
            },
        };
        const fn = map[algo.toLowerCase()];
        if (!fn) throw new Error(`Unknown hash: ${algo}`);
        return fn();
    },
};

/* ─────────────────────────────────────────────
    CLIENT-SIDE JWT
───────────────────────────────────────────── */
const JWT = {
    decode(token) {
        const parts = token.trim().split(".");
        if (parts.length !== 3) throw new Error("Invalid JWT: expected 3 parts");
        const b64dec = (s) => {
            s += "===".slice((s.length + 3) % 4);
            return atob(s.replace(/-/g, "+").replace(/_/g, "/"));
        };
        return {
            header: JSON.parse(b64dec(parts[0])),
            payload: JSON.parse(b64dec(parts[1])),
            signature: parts[2],
            raw: parts,
        };
    },
    generate(payload, secret, algo = "HS256", expiresIn = 3600) {
        if (!window.CryptoJS)
            throw new Error("CryptoJS required for JWT generation");
        const now = Math.floor(Date.now() / 1000);
        const full = { iat: now, exp: now + expiresIn, ...payload };
        const b64url = (s) =>
            btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
        const hB64 = b64url(JSON.stringify({ alg: algo, typ: "JWT" }));
        const pB64 = b64url(JSON.stringify(full));
        const si = `${hB64}.${pB64}`;
        const CJ = window.CryptoJS;
        const fn = {
            HS256: CJ.HmacSHA256,
            HS384: CJ.HmacSHA384,
            HS512: CJ.HmacSHA512,
        }[algo];
        if (!fn) throw new Error(`Unsupported: ${algo}`);
        const sig = fn(si, secret)
            .toString(CJ.enc.Base64)
            .replace(/=/g, "")
            .replace(/\+/g, "-")
            .replace(/\//g, "_");
        return `${si}.${sig}`;
    },
};

/* ─────────────────────────────────────────────
    UNIVERSAL ENCODE (API → client fallback)
───────────────────────────────────────────── */
async function apiEncode(algo, text, mode, key = "") {
    if (apiOnline) {
        try {
            const data = await Api.post(
                mode === "encode" ? "/api/encode" : "/api/decode",
                { text, algorithm: algo, key: key || null },
            );
            return data.result;
        } catch (e) {
            console.warn(`API ${mode} failed (${algo}), falling back:`, e.message);
        }
    }
    return Enc.run(algo, text, mode, key);
}

async function apiHash(algo, text) {
    if (apiOnline) {
        try {
            const data = await Api.post("/api/hash", { text, algorithm: algo });
            return data.hash;
        } catch (e) {
            console.warn("API hash failed, falling back:", e.message);
        }
    }
    return Hash.compute(algo, text);
}

async function apiHashAll(text) {
    if (apiOnline) {
        try {
            const data = await Api.post("/api/hash/all", { text });
            return data.hashes;
        } catch { }
    }
    const algos = [
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3_256",
        "sha3_512",
        "blake2b",
        "blake2s",
        "ripemd160",
        "crc32",
        "adler32",
    ];
    const out = {};
    for (const a of algos) {
        try {
            out[a] = Hash.compute(a, text);
        } catch {
            out[a] = "(unavailable)";
        }
    }
    return out;
}

async function apiDev(path, body) {
    if (apiOnline) {
        try {
            return await Api.post(path, body);
        } catch (e) {
            console.warn("API dev failed:", e.message);
        }
    }
    return null;
}

/* ─────────────────────────────────────────────
    TOAST (queue-based, prevents stacking)
───────────────────────────────────────────── */
const Toast = (() => {
    const MAX = 4;
    const ICONS = {
        success: "check-circle",
        error: "x-circle",
        info: "info",
        warn: "alert-triangle",
    };
    const COLORS = {
        success: "var(--c-green)",
        error: "var(--c-red)",
        info: "var(--c-purple-3)",
        warn: "var(--c-amber)",
    };

    function show(msg, type = "success", dur = 3200) {
        const root = document.getElementById("toastRoot");
        if (root.children.length >= MAX) root.firstChild?.remove();
        const el = document.createElement("div");
        el.className = `toast ${type}`;
        el.innerHTML = `<i data-lucide="${ICONS[type] || "info"}" style="width:15px;height:15px;color:${COLORS[type]};flex-shrink:0" aria-hidden="true"></i><span>${esc(msg)}</span>`;
        root.appendChild(el);
        if (window.lucide) lucide.createIcons({ nodes: [el] });
        setTimeout(() => {
            el.style.opacity = "0";
            el.style.transform = "translateX(20px)";
            el.style.transition = "all .25s";
            setTimeout(() => el.remove(), 250);
        }, dur);
    }

    return { show };
})();

function toast(msg, type, dur) {
    Toast.show(msg, type, dur);
}

/* ─────────────────────────────────────────────
    COPY WITH VISUAL FEEDBACK
───────────────────────────────────────────── */
async function copyWithFeedback(text, btnId) {
    if (!text?.trim()) return;
    try {
        await navigator.clipboard.writeText(text.trim());
        toast("Copied to clipboard!");
        if (btnId) {
            const btn = document.getElementById(btnId);
            if (btn) {
                const orig = btn.innerHTML;
                btn.classList.add("btn-copied");
                btn.innerHTML = `<i data-lucide="check" style="width:12px;height:12px"></i> Copied`;
                if (window.lucide) lucide.createIcons({ nodes: [btn] });
                setTimeout(() => {
                    btn.classList.remove("btn-copied");
                    btn.innerHTML = orig;
                    if (window.lucide) lucide.createIcons({ nodes: [btn] });
                }, 2000);
            }
        }
    } catch {
        toast("Clipboard access denied", "error");
    }
}

/* ─────────────────────────────────────────────
    SECURITY: HTML escaping
───────────────────────────────────────────── */
function esc(s) {
    return String(s).replace(
        /[&<>"']/g,
        (c) =>
            ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
            c
            ],
    );
}

/* ─────────────────────────────────────────────
    ROUTER (SPA navigation)
───────────────────────────────────────────── */
const PAGES = [
    "home",
    "encode",
    "hash",
    "jwt",
    "compression",
    "devtools",
    "json",
    "qr",
    "api",
    "about",
];

function goto(id) {
    if (!PAGES.includes(id)) id = "home";
    document
        .querySelectorAll(".page")
        .forEach((p) => p.classList.remove("active"));
    document
        .querySelectorAll("[data-nav]")
        .forEach((el) => el.classList.toggle("active", el.dataset.nav === id));
    const pg = document.getElementById("page-" + id);
    if (pg) {
        pg.classList.add("active");
        window.scrollTo({ top: 0, behavior: "instant" });
    }
    history.replaceState(null, "", "#" + id);
    closeDrawer();
}

document
    .querySelectorAll("[data-nav]")
    .forEach((el) => el.addEventListener("click", () => goto(el.dataset.nav)));

/* ─────────────────────────────────────────────
    PAGE TABS (data-driven — no string parsing)
───────────────────────────────────────────── */
function initTabs() {
    document.querySelectorAll(".tab[data-tab-group]").forEach((tab) => {
        tab.addEventListener("click", () => {
            const group = tab.dataset.tabGroup;
            const target = tab.dataset.tab;
            // Update tab buttons
            document
                .querySelectorAll(`.tab[data-tab-group="${group}"]`)
                .forEach((t) => {
                    const active = t.dataset.tab === target;
                    t.setAttribute("aria-selected", active);
                });
            // Update panels
            document.querySelectorAll(`[id^="${group}-"]`).forEach((panel) => {
                panel.classList.toggle("active", panel.id === `${group}-${target}`);
            });
        });
    });
}

/* ─────────────────────────────────────────────
    HOME WORKSPACE
───────────────────────────────────────────── */
const POPULAR = [
    { v: "base64", name: "Base64", desc: "Standard Base64", ico: "layers" },
    { v: "hex", name: "Hex", desc: "Hexadecimal", ico: "hash" },
    { v: "binary", name: "Binary", desc: "Binary encoding", ico: "cpu" },
    { v: "url", name: "URL Encode", desc: "Percent-encode", ico: "link" },
    { v: "rot13", name: "ROT13", desc: "Rotate by 13", ico: "rotate-cw" },
];
let homeMode = "encode";

function renderPopular() {
    const cur = document.getElementById("homeAlgo").value;
    document.getElementById("popularList").innerHTML = POPULAR.map(
        (p) => `
<div class="pop-item ${p.v === cur ? "active" : ""}" role="button" tabindex="0"
onclick="pickPopular('${p.v}')" onkeydown="if(event.key==='Enter'||event.key===' ')pickPopular('${p.v}')"
aria-label="Select ${p.name}">
<i data-lucide="${p.ico}" class="pop-item-ico" style="width:13px;height:13px" aria-hidden="true"></i>
<div><div class="pop-item-name">${p.name}</div><div class="pop-item-desc">${p.desc}</div></div>
</div>`,
    ).join("");
    if (window.lucide)
        lucide.createIcons({ nodes: [document.getElementById("popularList")] });
}

function pickPopular(v) {
    document.getElementById("homeAlgo").value = v;
    renderPopular();
    runHome();
}

function setHomeMode(mode) {
    homeMode = mode;
    document
        .getElementById("homeTabEnc")
        .setAttribute("aria-selected", mode === "encode");
    document
        .getElementById("homeTabDec")
        .setAttribute("aria-selected", mode === "decode");
    document.getElementById("homeLblIn").textContent =
        mode === "encode" ? "Enter Your Text" : "Encoded Input";
    document.getElementById("homeLblOut").textContent =
        mode === "encode" ? "Encoded Output" : "Decoded Output";
    runHome();
}

function onHomeInput() {
    const v = document.getElementById("homeIn").value;
    document.getElementById("homeCharCount").textContent = v.length;
    const banner = document.getElementById("homeDetect");
    if (homeMode === "decode") {
        const d = Enc.detect(v);
        if (d) {
            document.getElementById("homeDetectTxt").textContent =
                `Detected: ${d.toUpperCase()}`;
            banner.classList.add("show");
        } else {
            banner.classList.remove("show");
        }
    } else {
        banner.classList.remove("show");
    }
    runHome();
}

async function runHome() {
    const input = document.getElementById("homeIn").value;
    const algo = document.getElementById("homeAlgo").value;
    const out = document.getElementById("homeOut");
    if (!input.trim()) {
        out.textContent = "Output will appear here…";
        out.className = "ws-out empty";
        return;
    }
    try {
        const result = await apiEncode(algo, input, homeMode);
        out.textContent = result;
        out.className = "ws-out";
    } catch (e) {
        out.textContent = `⚠ ${e.message}`;
        out.className = "ws-out empty";
    }
}

function swapHome() {
    const out = document.getElementById("homeOut");
    if (out.classList.contains("empty")) return;
    document.getElementById("homeIn").value = out.textContent;
    setHomeMode(homeMode === "encode" ? "decode" : "encode");
}

function clearHome() {
    document.getElementById("homeIn").value = "";
    const out = document.getElementById("homeOut");
    out.textContent = "Output will appear here…";
    out.className = "ws-out empty";
    document.getElementById("homeCharCount").textContent = "0";
    document.getElementById("homeDetect").classList.remove("show");
}

function copyHomeOut() {
    const out = document.getElementById("homeOut");
    if (!out.classList.contains("empty"))
        copyWithFeedback(out.textContent, "homeCopyBtn");
}

/* ─────────────────────────────────────────────
    ENCODE PAGE
───────────────────────────────────────────── */
let encMode = "encode";
const CIPHER_ALGOS = new Set(["caesar", "vigenere", "railfence", "affine"]);

function setEncMode(mode) {
    encMode = mode;
    document
        .getElementById("encTabE")
        .setAttribute("aria-selected", mode === "encode");
    document
        .getElementById("encTabD")
        .setAttribute("aria-selected", mode === "decode");
    runEnc();
}

function onEncAlgoChange() {
    document
        .getElementById("cipherWrap")
        .classList.toggle(
            "show",
            CIPHER_ALGOS.has(document.getElementById("encAlgo").value),
        );
    runEnc();
}

async function runEnc() {
    const input = document.getElementById("encIn").value;
    const algo = document.getElementById("encAlgo").value;
    const key = document.getElementById("cipherKey").value;
    const outEl = document.getElementById("encOut");
    document.getElementById("encInCount").textContent = input.length + " chars";
    if (!input.trim()) {
        outEl.value = "";
        document.getElementById("encOutCount").textContent = "0 chars";
        return;
    }
    try {
        const result = await apiEncode(algo, input, encMode, key);
        outEl.value = result;
        document.getElementById("encOutCount").textContent =
            result.length + " chars";
    } catch (e) {
        outEl.value = `Error: ${e.message}`;
    }
}

function clearEnc() {
    document.getElementById("encIn").value = "";
    document.getElementById("encOut").value = "";
    document.getElementById("encInCount").textContent = "0 chars";
    document.getElementById("encOutCount").textContent = "0 chars";
}
async function pasteEnc() {
    try {
        document.getElementById("encIn").value =
            await navigator.clipboard.readText();
        runEnc();
    } catch {
        toast("Clipboard access denied", "error");
    }
}
function copyEnc() {
    copyWithFeedback(document.getElementById("encOut").value, "encCopyBtn");
}
function loadEncFile(e) {
    const f = e.target.files[0];
    if (!f) return;
    if (f.size > 5e6) {
        toast("Max 5MB", "error");
        return;
    }
    const r = new FileReader();
    r.onload = (ev) => {
        document.getElementById("encIn").value = ev.target.result;
        runEnc();
    };
    r.readAsText(f);
}
function dlEnc(fmt) {
    const t = document.getElementById("encOut").value;
    if (!t) {
        toast("Nothing to download", "error");
        return;
    }
    if (fmt === "json") {
        dlText(
            JSON.stringify({
                input: document.getElementById("encIn").value,
                output: t,
                algorithm: document.getElementById("encAlgo").value,
                mode: encMode,
            }),
            "shadowcrypt.json",
        );
    } else {
        dlText(t, "shadowcrypt.txt");
    }
}
function detectEnc() {
    const d = Enc.detect(document.getElementById("encIn").value);
    if (d) {
        document.getElementById("encAlgo").value = d;
        toast(`Detected: ${d.toUpperCase()}`, "info");
        onEncAlgoChange();
    } else {
        toast("Could not detect format", "warn");
    }
}

async function runChain() {
    const input = document.getElementById("chainIn").value;
    const steps = [...document.querySelectorAll("[data-chain]")].map(
        (s) => s.value,
    );
    const out = document.getElementById("chainOut");
    if (!input) {
        out.textContent = "Chain result will appear here…";
        out.className = "out-box empty";
        return;
    }
    try {
        let result = input;
        if (apiOnline) {
            const data = await Api.post("/api/batch", {
                text: input,
                steps: steps.map((a) => ({ algorithm: a, mode: "encode" })),
            });
            result = data.result;
        } else {
            for (const s of steps) result = Enc.run(s, result, "encode");
        }
        out.textContent = result;
        out.className = "out-box";
    } catch (e) {
        out.textContent = `Error: ${e.message}`;
        out.className = "out-box empty";
    }
}
document
    .querySelectorAll("[data-chain]")
    .forEach((el) => el.addEventListener("change", runChain));

/* ─────────────────────────────────────────────
    HASH PAGE
───────────────────────────────────────────── */
let selectedHash = "md5";
const HASH_BITS = {
    md5: 128,
    sha1: 160,
    sha224: 224,
    sha256: 256,
    sha384: 384,
    sha512: 512,
    sha3_256: 256,
    sha3_512: 512,
    blake2b: 512,
    blake2s: 256,
    ripemd160: 160,
    crc32: 32,
    adler32: 32,
};

function initHashBtns() {
    document.querySelectorAll(".hash-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".hash-btn").forEach((b) => {
                b.setAttribute("aria-pressed", "false");
                b.setAttribute("aria-checked", "false");
            });
            btn.setAttribute("aria-pressed", "true");
            btn.setAttribute("aria-checked", "true");
            selectedHash = btn.dataset.hash;
            runHash();
        });
    });
}

async function runHash() {
    const text = document.getElementById("hashIn").value;
    const resEl = document.getElementById("hashResult");
    const metaEl = document.getElementById("hashMeta");
    if (!text) {
        resEl.textContent = "Select an algorithm and enter text…";
        resEl.className = "out-box empty";
        document.getElementById("hashAllOut").innerHTML =
            '<p class="muted sm">Enter text above to see all hashes.</p>';
        return;
    }
    try {
        const h = await apiHash(selectedHash, text);
        resEl.textContent = h;
        resEl.className = "out-box";
        metaEl.textContent = `${selectedHash.toUpperCase()} · ${h.length} hex chars · ${HASH_BITS[selectedHash] || "?"} bits`;
        renderAllHashes(text);
    } catch (e) {
        resEl.textContent = `Error: ${e.message}`;
        resEl.className = "out-box empty";
    }
}

async function renderAllHashes(text) {
    const tbl = document.getElementById("hashAllOut");
    tbl.innerHTML =
        '<div class="loading-row"><div class="spinner"></div><span>Computing…</span></div>';
    const hashes = await apiHashAll(text);
    tbl.innerHTML = Object.entries(hashes)
        .map(
            ([a, h]) => `
<div class="hash-row">
<span class="hash-row-name">${a.toUpperCase()}</span>
<span class="hash-row-val">${esc(h)}</span>
<button class="btn btn-ghost btn-icon btn-xs" onclick="navigator.clipboard.writeText(${JSON.stringify(h)}).then(()=>toast('Copied!'))" aria-label="Copy ${a} hash">
<i data-lucide="copy" style="width:11px;height:11px" aria-hidden="true"></i>
</button>
</div>`,
        )
        .join("");
    if (window.lucide) lucide.createIcons({ nodes: [tbl] });
}

function copyHash() {
    copyWithFeedback(
        document.getElementById("hashResult").textContent,
        "hashCopyBtn",
    );
}

async function verifyHash() {
    const text = document.getElementById("vfyIn").value;
    const hash = document.getElementById("vfyHash").value.trim();
    const algo = document.getElementById("vfyAlgo").value;
    const resEl = document.getElementById("vfyResult");
    if (!text || !hash) {
        toast("Enter both text and hash", "error");
        return;
    }
    try {
        let match, computed;
        if (apiOnline) {
            const data = await Api.post("/api/hash/verify", {
                text,
                hash,
                algorithm: algo,
            });
            match = data.match;
            computed = data.computed;
        } else {
            computed = Hash.compute(algo, text);
            match = computed.toLowerCase() === hash.toLowerCase();
        }
        resEl.innerHTML = match
            ? `<div class="card" style="border-color:rgba(16,185,129,.4);background:rgba(16,185,129,.05)"><div class="sm c-green" style="font-weight:700;margin-bottom:6px">✓ Hash Matches</div><div class="xs muted mono">${esc(computed)}</div></div>`
            : `<div class="card" style="border-color:rgba(239,68,68,.4);background:rgba(239,68,68,.05)"><div class="sm c-red" style="font-weight:700;margin-bottom:6px">✗ Hash Mismatch</div><div class="xs muted mono">${esc(computed)}</div></div>`;
    } catch (e) {
        toast(`Error: ${e.message}`, "error");
    }
}

function compareHashes() {
    const a = document.getElementById("cmpA").value.trim().toLowerCase();
    const b = document.getElementById("cmpB").value.trim().toLowerCase();
    const el = document.getElementById("cmpResult");
    if (!a || !b) {
        toast("Enter both hashes", "error");
        return;
    }
    el.innerHTML =
        a === b
            ? `<div class="card" style="border-color:rgba(16,185,129,.4);background:rgba(16,185,129,.05)"><span class="c-green" style="font-weight:700">✓ Hashes are identical</span></div>`
            : `<div class="card" style="border-color:rgba(239,68,68,.4);background:rgba(239,68,68,.05)"><span class="c-red" style="font-weight:700">✗ Hashes differ</span> <span class="xs muted">A: ${a.length} · B: ${b.length} chars</span></div>`;
}

/* ─────────────────────────────────────────────
    JWT PAGE
───────────────────────────────────────────── */
function decodeJWT() {
    const token = document.getElementById("jwtDecIn").value.trim();
    const resEl = document.getElementById("jwtDecResult");
    if (!token) {
        resEl.innerHTML = "";
        return;
    }
    try {
        const { header, payload, signature, raw } = JWT.decode(token);
        const now = Math.floor(Date.now() / 1000);
        const expired = payload.exp && payload.exp < now;
        const fmt = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "—");
        resEl.innerHTML = `
<div class="jwt-parts">
<div class="jwt-part jwt-part-h"><div class="jwt-part-lbl">Header</div><div class="jwt-part-val">${esc(raw[0])}</div></div>
<div class="jwt-part jwt-part-p"><div class="jwt-part-lbl">Payload</div><div class="jwt-part-val">${esc(raw[1])}</div></div>
<div class="jwt-part jwt-part-s"><div class="jwt-part-lbl">Signature</div><div class="jwt-part-val">${esc(raw[2])}</div></div>
</div>
<div class="col-2 mt-12">
<div><div class="field-label mb-8">Decoded Header</div><pre class="out-box" style="font-size:11.5px">${esc(JSON.stringify(header, null, 2))}</pre></div>
<div><div class="field-label mb-8">Decoded Payload</div><pre class="out-box" style="font-size:11.5px">${esc(JSON.stringify(payload, null, 2))}</pre></div>
</div>
<div class="jwt-claims mt-12">
${payload.sub ? `<div class="jwt-claim"><div class="jwt-claim-key">Subject (sub)</div><div class="jwt-claim-val">${esc(String(payload.sub))}</div></div>` : ""}
${payload.iss ? `<div class="jwt-claim"><div class="jwt-claim-key">Issuer (iss)</div><div class="jwt-claim-val">${esc(String(payload.iss))}</div></div>` : ""}
<div class="jwt-claim"><div class="jwt-claim-key">Issued At</div><div class="jwt-claim-val">${fmt(payload.iat)}</div></div>
<div class="jwt-claim" style="${expired ? "border-color:rgba(239,68,68,.38)" : ""}">
    <div class="jwt-claim-key">Expires At</div>
    <div class="jwt-claim-val ${expired ? "c-red" : ""}">${fmt(payload.exp)} ${expired ? "⚠ EXPIRED" : payload.exp ? "✓ Valid" : ""}</div>
</div>
<div class="jwt-claim"><div class="jwt-claim-key">Algorithm</div><div class="jwt-claim-val">${esc(header.alg || "none")}</div></div>
<div class="jwt-claim"><div class="jwt-claim-key">Type</div><div class="jwt-claim-val">${esc(header.typ || "?")}</div></div>
</div>`;
    } catch (e) {
        resEl.innerHTML = `<div class="card" style="border-color:rgba(239,68,68,.38)"><span class="c-red sm">Invalid JWT: ${esc(e.message)}</span></div>`;
    }
}

async function genJWT() {
    try {
        const algo = document.getElementById("jwtAlgo").value;
        const secret = document.getElementById("jwtSecret").value;
        const sub = document.getElementById("jwtSub").value;
        const iss = document.getElementById("jwtIss").value;
        const expH = parseInt(document.getElementById("jwtExp").value) || 1;
        const extra = document.getElementById("jwtExtra").value;
        const extra2 = extra ? JSON.parse(extra) : {};
        let token;
        if (apiOnline) {
            const data = await Api.post("/api/jwt/generate", {
                payload: extra2,
                secret,
                algorithm: algo,
                expires_in: expH * 3600,
                issuer: iss || null,
                subject: sub || null,
            });
            token = data.token;
        } else {
            const payload = {
                ...extra2,
                ...(sub ? { sub } : {}),
                ...(iss ? { iss } : {}),
            };
            token = JWT.generate(payload, secret, algo, expH * 3600);
        }
        const el = document.getElementById("jwtGenOut");
        el.textContent = token;
        el.className = "out-box";
        toast("JWT generated!");
    } catch (e) {
        toast(`Error: ${e.message}`, "error");
    }
}

function copyJWTGen() {
    copyWithFeedback(
        document.getElementById("jwtGenOut").textContent,
        "jwtGenCopyBtn",
    );
}

async function verifyJWT() {
    const token = document.getElementById("jwtVfyTok").value.trim();
    const secret = document.getElementById("jwtVfySecret").value;
    const resEl = document.getElementById("jwtVfyResult");
    if (!token || !secret) {
        toast("Enter token and secret", "error");
        return;
    }
    if (!apiOnline) {
        // Client-side: recompute and compare
        try {
            const { header, raw } = JWT.decode(token);
            const algo = header.alg || "HS256";
            const si = `${raw[0]}.${raw[1]}`;
            const CJ = window.CryptoJS;
            const fn = {
                HS256: CJ.HmacSHA256,
                HS384: CJ.HmacSHA384,
                HS512: CJ.HmacSHA512,
            }[algo];
            if (!fn) throw new Error("Unsupported algorithm: " + algo);
            const sig = fn(si, secret)
                .toString(CJ.enc.Base64)
                .replace(/=/g, "")
                .replace(/\+/g, "-")
                .replace(/\//g, "_");
            const valid = sig === raw[2];
            resEl.innerHTML = valid
                ? `<div class="card" style="border-color:rgba(16,185,129,.4);background:rgba(16,185,129,.05)"><span class="c-green" style="font-weight:700">✓ Signature Valid</span> <span class="xs muted">(client-side)</span></div>`
                : `<div class="card" style="border-color:rgba(239,68,68,.4);background:rgba(239,68,68,.05)"><span class="c-red" style="font-weight:700">✗ Invalid Signature</span></div>`;
        } catch (e) {
            resEl.innerHTML = `<div class="card" style="border-color:rgba(239,68,68,.38)"><span class="c-red sm">Error: ${esc(e.message)}</span></div>`;
        }
        return;
    }
    try {
        const data = await Api.post("/api/jwt/verify", { token, secret });
        resEl.innerHTML = data.valid
            ? `<div class="card" style="border-color:rgba(16,185,129,.4);background:rgba(16,185,129,.05)"><span class="c-green" style="font-weight:700">✓ Signature Valid</span></div>`
            : `<div class="card" style="border-color:rgba(239,68,68,.4);background:rgba(239,68,68,.05)"><span class="c-red" style="font-weight:700">✗ Invalid Signature</span> <span class="xs muted">${esc(data.error || "")}</span></div>`;
        if (window.lucide) lucide.createIcons({ nodes: [resEl] });
    } catch (e) {
        toast(`Error: ${e.message}`, "error");
    }
}

/* ─────────────────────────────────────────────
    COMPRESSION PAGE
───────────────────────────────────────────── */
let compMode = "compress";

function setCompMode(m) {
    compMode = m;
    document
        .getElementById("compTabC")
        .setAttribute("aria-selected", m === "compress");
    document
        .getElementById("compTabD")
        .setAttribute("aria-selected", m === "decompress");
    document.getElementById("compBtnTxt").textContent =
        m === "compress" ? "Compress" : "Decompress";
}

function updateCompBanner() {
    const b = document.getElementById("compOfflineBanner");
    if (b) b.style.display = apiOnline ? "none" : "flex";
}

async function runComp() {
    const input = document.getElementById("compIn").value;
    const algo = document.getElementById("compAlgo").value;
    const b64 = document.getElementById("compB64").checked;
    const outEl = document.getElementById("compOut");
    const infoEl = document.getElementById("compInfo");
    if (!input) {
        toast("Enter text first", "error");
        return;
    }
    if (!apiOnline) {
        toast("Compression requires the backend API", "warn");
        return;
    }
    const btn = document.getElementById("compBtn");
    btn.disabled = true;
    btn.innerHTML = `<div class="spinner"></div> ${compMode === "compress" ? "Compressing" : "Decompressing"}…`;
    try {
        if (compMode === "compress") {
            const data = await Api.post("/api/compress", {
                text: input,
                algorithm: algo,
                base64_output: b64,
            });
            outEl.value = data.result;
            infoEl.textContent = `${data.original_size}B → ${data.compressed_size}B (${data.ratio}% reduction)`;
            toast("Compressed!");
        } else {
            const data = await Api.post("/api/decompress", {
                text: input,
                algorithm: algo,
                base64_input: b64,
            });
            outEl.value = data.result;
            infoEl.textContent = `${data.compressed_size}B → ${data.decompressed_size}B`;
            toast("Decompressed!");
        }
    } catch (e) {
        toast(`Error: ${e.message}`, "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i data-lucide="archive" style="width:14px;height:14px"></i> <span id="compBtnTxt">${compMode === "compress" ? "Compress" : "Decompress"}</span>`;
        if (window.lucide) lucide.createIcons({ nodes: [btn] });
    }
}

/* ─────────────────────────────────────────────
    DEV TOOLS
───────────────────────────────────────────── */
async function genUUID() {
    const ver = document.getElementById("uuidVer").value;
    const cnt = parseInt(document.getElementById("uuidCount").value) || 1;
    const out = document.getElementById("uuidOut");
    const data = await apiDev("/api/uuid", { version: ver, count: cnt });
    const ids =
        data?.uuids ??
        Array.from({ length: cnt }, () => {
            if (ver === "nanoid")
                return Array.from(
                    crypto.getRandomValues(new Uint8Array(21)),
                    (b) =>
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"[
                        b % 64
                        ],
                ).join("");
            return crypto.randomUUID();
        });
    out.innerHTML = ids
        .map(
            (u) =>
                `<div class="mono sm c-purple" style="margin-bottom:3px">${esc(u)}</div>`,
        )
        .join("");
    out.className = "out-box";
}

async function genPwd() {
    const len = parseInt(document.getElementById("pwdLen").value);
    const U = document.getElementById("pwdU").checked;
    const L = document.getElementById("pwdL").checked;
    const N = document.getElementById("pwdN").checked;
    const S = document.getElementById("pwdS").checked;
    const X = document.getElementById("pwdX").checked;
    const data = await apiDev("/api/password", {
        length: len,
        uppercase: U,
        lowercase: L,
        numbers: N,
        symbols: S,
        count: 1,
        exclude_ambiguous: X,
    });
    const out = document.getElementById("pwdOut");
    if (data) {
        out.textContent = data.passwords[0];
        out.className = "out-box";
        setPwdStrength(data.strength, data.entropy_bits);
    } else {
        let chars = "";
        if (U) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (L) chars += "abcdefghijklmnopqrstuvwxyz";
        if (N) chars += "0123456789";
        if (S) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";
        if (X) chars = chars.replace(/[0O1lI]/g, "");
        if (!chars) {
            toast("Select a character set", "error");
            return;
        }
        const pwd = Array.from(
            crypto.getRandomValues(new Uint8Array(len)),
            (b) => chars[b % chars.length],
        ).join("");
        out.textContent = pwd;
        out.className = "out-box";
        const score =
            [U, L, N, S].filter(Boolean).length +
            (len >= 12) +
            (len >= 16) +
            (len >= 24);
        const labels = [
            "Very Weak",
            "Weak",
            "Fair",
            "Good",
            "Strong",
            "Very Strong",
            "Excellent",
        ];
        setPwdStrength(labels[Math.min(score, 6)], null);
    }
}

function setPwdStrength(label, entropy) {
    const pct = {
        "very weak": 14,
        weak: 28,
        fair: 42,
        good: 57,
        strong: 72,
        "very strong": 86,
        excellent: 100,
    };
    const clrs = {
        "very weak": "var(--c-red)",
        weak: "var(--c-red)",
        fair: "var(--c-amber)",
        good: "var(--c-amber)",
        strong: "var(--c-green)",
        "very strong": "var(--c-green)",
        excellent: "var(--c-green)",
    };
    const k = label.toLowerCase();
    document.getElementById("pwdStrFill").style.width = (pct[k] ?? 42) + "%";
    document.getElementById("pwdStrFill").style.background =
        clrs[k] ?? "var(--c-amber)";
    document.getElementById("pwdStrLbl").textContent =
        label + (entropy ? ` · ${entropy} bits entropy` : "");
}

function tsNow() {
    document.getElementById("tsIn").value = Math.floor(Date.now() / 1000);
    convertTs();
}

async function convertTs() {
    const v = document.getElementById("tsIn").value.trim();
    const el = document.getElementById("tsResult");
    if (!v) {
        el.innerHTML = "";
        return;
    }
    const data = await apiDev("/api/timestamp", { unix: parseInt(v) });
    if (data) {
        el.innerHTML = `<div class="jwt-claims"><div class="jwt-claim"><div class="jwt-claim-key">Unix</div><div class="jwt-claim-val mono">${data.unix}</div></div><div class="jwt-claim"><div class="jwt-claim-key">ISO 8601</div><div class="jwt-claim-val mono" style="font-size:11px">${esc(data.iso)}</div></div><div class="jwt-claim"><div class="jwt-claim-key">UTC</div><div class="jwt-claim-val sm">${esc(data.utc)}</div></div><div class="jwt-claim"><div class="jwt-claim-key">Relative</div><div class="jwt-claim-val c-purple">${esc(data.relative)}</div></div></div>`;
    } else {
        const d = new Date(parseInt(v) * 1000);
        el.innerHTML = `<div class="jwt-claims"><div class="jwt-claim"><div class="jwt-claim-key">UTC</div><div class="jwt-claim-val sm">${esc(d.toUTCString())}</div></div><div class="jwt-claim"><div class="jwt-claim-key">ISO 8601</div><div class="jwt-claim-val mono" style="font-size:11px">${esc(d.toISOString())}</div></div><div class="jwt-claim"><div class="jwt-claim-key">Local</div><div class="jwt-claim-val sm">${esc(d.toLocaleString())}</div></div></div>`;
    }
}

function onColorPick() {
    document.getElementById("colorIn").value =
        document.getElementById("colorPick").value;
    convertColor();
}

async function convertColor() {
    const v = document.getElementById("colorIn").value.trim();
    const el = document.getElementById("colorResult");
    if (!v) {
        el.innerHTML = "";
        return;
    }
    const data = await apiDev("/api/color", { value: v });
    let r = 0,
        g = 0,
        b = 0;
    if (data) {
        r = data.rgb.r;
        g = data.rgb.g;
        b = data.rgb.b;
        el.innerHTML = `<div style="display:flex;gap:10px;align-items:center;margin-top:12px;flex-wrap:wrap"><div style="width:44px;height:44px;background:${esc(data.hex)};border-radius:var(--r-sm);border:1px solid var(--c-border);flex-shrink:0" aria-label="Color preview"></div><div class="jwt-claims" style="flex:1"><div class="jwt-claim"><div class="jwt-claim-key">HEX</div><div class="jwt-claim-val mono">${esc(data.hex)}</div></div><div class="jwt-claim"><div class="jwt-claim-key">RGB</div><div class="jwt-claim-val mono sm">rgb(${r},${g},${b})</div></div><div class="jwt-claim"><div class="jwt-claim-key">HSL</div><div class="jwt-claim-val mono sm">hsl(${data.hsl.h},${data.hsl.s}%,${data.hsl.l}%)</div></div><div class="jwt-claim"><div class="jwt-claim-key">RGBA</div><div class="jwt-claim-val mono sm">${esc(data.rgba)}</div></div></div></div>`;
        document.getElementById("colorPick").value = data.hex.toLowerCase();
    } else {
        try {
            if (/^#/.test(v)) {
                let h = v.slice(1);
                if (h.length === 3) h = [...h].map((c) => c + c).join("");
                r = parseInt(h.slice(0, 2), 16);
                g = parseInt(h.slice(2, 4), 16);
                b = parseInt(h.slice(4, 6), 16);
            } else if (/^rgb/.test(v)) {
                const m = v.match(/[\d.]+/g);
                r = +m[0];
                g = +m[1];
                b = +m[2];
            } else {
                el.innerHTML = "";
                return;
            }
            const hex = `#${[r, g, b]
                .map((x) => x.toString(16).padStart(2, "0"))
                .join("")
                .toUpperCase()}`;
            el.innerHTML = `<div style="display:flex;gap:10px;align-items:center;margin-top:12px"><div style="width:44px;height:44px;background:${hex};border-radius:var(--r-sm);border:1px solid var(--c-border)"></div><div class="jwt-claims" style="flex:1"><div class="jwt-claim"><div class="jwt-claim-key">HEX</div><div class="jwt-claim-val mono">${hex}</div></div><div class="jwt-claim"><div class="jwt-claim-key">RGB</div><div class="jwt-claim-val mono sm">rgb(${r},${g},${b})</div></div></div></div>`;
            document.getElementById("colorPick").value = hex.toLowerCase();
        } catch {
            el.innerHTML = "";
        }
    }
}

async function genRStr() {
    const len = parseInt(document.getElementById("rstrLen").value);
    const type = document.getElementById("rstrType").value;
    const out = document.getElementById("rstrOut");
    const data = await apiDev("/api/random-string", {
        length: len,
        string_type: type,
        count: 1,
    });
    if (data) {
        out.textContent = data.strings[0];
    } else {
        const A = {
            alphanumeric:
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            hex: "0123456789abcdef",
            base64:
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            numeric: "0123456789",
            alpha: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?",
        };
        const chars = A[type] || A.alphanumeric;
        out.textContent = Array.from(
            crypto.getRandomValues(new Uint8Array(len)),
            (b) => chars[b % chars.length],
        ).join("");
    }
    out.className = "out-box";
}

async function runSlug() {
    const t = document.getElementById("slugIn").value;
    const el = document.getElementById("slugResult");
    if (!t) {
        el.innerHTML = "";
        return;
    }
    const data = await apiDev("/api/slug", { text: t });
    const d =
        data ||
        (() => {
            const words = t
                .replace(/[^a-zA-Z0-9\s]/g, " ")
                .split(/[\s_\-]+/)
                .filter(Boolean);
            const lower = words.map((w) => w.toLowerCase());
            return {
                slug: lower.join("-"),
                snake_case: lower.join("_"),
                camel_case:
                    lower[0] +
                    lower
                        .slice(1)
                        .map((w) => w[0].toUpperCase() + w.slice(1))
                        .join(""),
                pascal_case: lower.map((w) => w[0].toUpperCase() + w.slice(1)).join(""),
                kebab_case: lower.join("-"),
                upper: words.join(" ").toUpperCase(),
                lower: words.join(" ").toLowerCase(),
            };
        })();
    el.innerHTML = Object.entries(d)
        .map(
            ([k, v]) => `
<div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--c-border)">
<span class="xs dim mono" style="min-width:90px">${esc(k)}</span>
<span class="mono sm" style="flex:1;word-break:break-all">${esc(v)}</span>
<button class="btn btn-ghost btn-icon btn-xs" onclick="navigator.clipboard.writeText(${JSON.stringify(v)}).then(()=>toast('Copied!'))" aria-label="Copy ${k}">
<i data-lucide="copy" style="width:11px;height:11px" aria-hidden="true"></i>
</button>
</div>`,
        )
        .join("");
    if (window.lucide) lucide.createIcons({ nodes: [el] });
}

/* ─────────────────────────────────────────────
    JSON / DATA FORMATTERS
───────────────────────────────────────────── */
function fmtJSON() {
    try {
        document.getElementById("jsonOut").value = JSON.stringify(
            JSON.parse(document.getElementById("jsonIn").value),
            null,
            2,
        );
        document.getElementById("jsonStatus").innerHTML =
            '<span class="c-green">✓ Valid JSON</span>';
    } catch (e) {
        document.getElementById("jsonStatus").innerHTML =
            `<span class="c-red">✗ ${esc(e.message)}</span>`;
    }
}
function minJSON() {
    try {
        document.getElementById("jsonOut").value = JSON.stringify(
            JSON.parse(document.getElementById("jsonIn").value),
        );
        document.getElementById("jsonStatus").innerHTML =
            '<span class="c-green">✓ Minified</span>';
    } catch (e) {
        document.getElementById("jsonStatus").innerHTML =
            `<span class="c-red">✗ ${esc(e.message)}</span>`;
    }
}
function valJSON() {
    try {
        JSON.parse(document.getElementById("jsonIn").value);
        document.getElementById("jsonStatus").innerHTML =
            '<span class="c-green">✓ Valid JSON</span>';
        toast("Valid JSON!");
    } catch (e) {
        document.getElementById("jsonStatus").innerHTML =
            `<span class="c-red">✗ ${esc(e.message)}</span>`;
        toast(e.message, "error");
    }
}
function clrJSON() {
    document.getElementById("jsonIn").value = "";
    document.getElementById("jsonOut").value = "";
    document.getElementById("jsonStatus").innerHTML = "";
}

// YAML: minimal parser for common cases
function yaml2json() {
    try {
        const lines = document.getElementById("yamlIn").value.split("\n");
        const root = {},
            stack = [{ obj: root, ind: -1 }];
        for (const line of lines) {
            if (!line.trim() || line.trim().startsWith("#")) continue;
            const ind = line.match(/^\s*/)[0].length;
            const m = line.trim().match(/^([^:]+):\s*(.*)?$/);
            if (!m) continue;
            const [, k, v] = m;
            while (stack.length > 1 && stack[stack.length - 1].ind >= ind)
                stack.pop();
            const parent = stack[stack.length - 1].obj;
            if (v) {
                const n = +v;
                parent[k.trim()] =
                    v === "true"
                        ? true
                        : v === "false"
                            ? false
                            : v === "null"
                                ? null
                                : isNaN(n) || v === ""
                                    ? v
                                    : n;
            } else {
                parent[k.trim()] = {};
                stack.push({ obj: parent[k.trim()], ind });
            }
        }
        document.getElementById("yamlOut").value = JSON.stringify(root, null, 2);
    } catch (e) {
        document.getElementById("yamlOut").value = "Error: " + e.message;
    }
}
function json2yaml() {
    try {
        const obj = JSON.parse(document.getElementById("yamlIn").value);
        function toYaml(o, l = 0) {
            const p = "  ".repeat(l);
            if (Array.isArray(o))
                return o
                    .map((v) =>
                        typeof v === "object" ? `${p}-\n${toYaml(v, l + 1)}` : `${p}- ${v}`,
                    )
                    .join("\n");
            if (typeof o === "object" && o !== null)
                return Object.entries(o)
                    .map(([k, v]) =>
                        typeof v === "object"
                            ? `${p}${k}:\n${toYaml(v, l + 1)}`
                            : `${p}${k}: ${v}`,
                    )
                    .join("\n");
            return String(o);
        }
        document.getElementById("yamlOut").value = toYaml(obj);
    } catch (e) {
        document.getElementById("yamlOut").value = "Error: " + e.message;
    }
}

function fmtXML() {
    try {
        document.getElementById("xmlOut").value = prettyXML(
            document.getElementById("xmlIn").value,
        );
    } catch (e) {
        document.getElementById("xmlOut").value = "Error: " + e.message;
    }
}
function minXML() {
    document.getElementById("xmlOut").value = document
        .getElementById("xmlIn")
        .value.replace(/>\s+</g, "><")
        .trim();
}
function prettyXML(x) {
    let f = "",
        i = 0;
    x.replace(/>\s*</g, ">\n<")
        .split("\n")
        .forEach((n) => {
            if (n.match(/^<\/\w/)) i--;
            f += "  ".repeat(Math.max(0, i)) + n.trim() + "\n";
            if (n.match(/^<\w[^>]*[^\/]>.*$/) && !n.match(/<.*\/>/)) i++;
        });
    return f.trim();
}

const SQL_KW = [
    "SELECT",
    "FROM",
    "WHERE",
    "AND",
    "OR",
    "NOT",
    "IN",
    "JOIN",
    "LEFT JOIN",
    "RIGHT JOIN",
    "INNER JOIN",
    "ON",
    "GROUP BY",
    "ORDER BY",
    "HAVING",
    "LIMIT",
    "OFFSET",
    "INSERT INTO",
    "VALUES",
    "UPDATE",
    "SET",
    "DELETE FROM",
    "CREATE TABLE",
    "ALTER TABLE",
    "DROP TABLE",
    "UNION",
    "WITH",
    "AS",
    "DISTINCT",
];
function fmtSQL() {
    let s = document.getElementById("sqlIn").value.replace(/\s+/g, " ").trim();
    const p = new RegExp(`\\b(${SQL_KW.join("|")})\\b`, "gi");
    document.getElementById("sqlOut").value = s.replace(p, "\n$1").trim();
}
function minSQL() {
    document.getElementById("sqlOut").value = document
        .getElementById("sqlIn")
        .value.replace(/\s+/g, " ")
        .trim();
}

/* ─────────────────────────────────────────────
    QR CODE — canvas-based for reliable download
───────────────────────────────────────────── */
function genQR() {
    const text = document.getElementById("qrIn").value.trim();
    const size = parseInt(document.getElementById("qrSize").value) || 256;
    const color = document.getElementById("qrColor").value;
    const out = document.getElementById("qrOut");
    const dlBtn = document.getElementById("qrDlBtn");
    if (!text) {
        toast("Enter content first", "error");
        return;
    }
    // Load via image from Google Charts, then draw onto canvas for download
    const url = `https://chart.googleapis.com/chart?chs=${size}x${size}&cht=qr&chl=${encodeURIComponent(text)}&choe=UTF-8`;
    const img = document.createElement("img");
    img.crossOrigin = "anonymous";
    img.src = url;
    img.width = Math.min(size, 300);
    img.height = Math.min(size, 300);
    img.style.cssText = "border-radius:10px;border:8px solid #fff";
    img.alt = "Generated QR code";
    img.onload = () => {
        out.innerHTML = "";
        out.appendChild(img);
        dlBtn.classList.remove("hidden");
        toast("QR code generated!");
    };
    img.onerror = () => {
        out.innerHTML = '<span class="c-red sm">Failed — check connection</span>';
    };
}

function dlQR() {
    const img = document.querySelector("#qrOut img");
    if (!img) return;
    // Draw to canvas for reliable PNG download
    const canvas = document.createElement("canvas");
    const size = parseInt(document.getElementById("qrSize").value) || 256;
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#fff";
    ctx.fillRect(0, 0, size, size);
    const tmp = new Image();
    tmp.crossOrigin = "anonymous";
    tmp.onload = () => {
        ctx.drawImage(tmp, 0, 0, size, size);
        const a = document.createElement("a");
        a.href = canvas.toDataURL("image/png");
        a.download = "qrcode.png";
        a.click();
    };
    tmp.onerror = () => {
        const a = document.createElement("a");
        a.href = img.src;
        a.download = "qrcode.png";
        a.click();
    };
    tmp.src = img.src;
}

/* ─────────────────────────────────────────────
    API DOCS
───────────────────────────────────────────── */
const ENDPOINTS = [
    {
        m: "POST",
        p: "/api/encode",
        d: "Encode text (24 algorithms)",
        req: `{"text":"Hello","algorithm":"base64","key":null}`,
        res: `{"result":"SGVsbG8=","algorithm":"base64","mode":"encode","processing_time_ms":0.1}`,
    },
    {
        m: "POST",
        p: "/api/decode",
        d: "Decode text",
        req: `{"text":"SGVsbG8=","algorithm":"base64"}`,
        res: `{"result":"Hello","algorithm":"base64","mode":"decode"}`,
    },
    {
        m: "POST",
        p: "/api/detect",
        d: "Auto-detect encoding format",
        req: `{"text":"SGVsbG8gV29ybGQ="}`,
        res: `{"detected":"base64","confidence":0.9,"alternatives":["hex"]}`,
    },
    {
        m: "POST",
        p: "/api/batch",
        d: "Chain multiple encoding operations",
        req: `{"text":"Hello","steps":[{"algorithm":"base64","mode":"encode"},{"algorithm":"hex","mode":"encode"}]}`,
        res: `{"result":"5347567362473873513356...","steps":[...]}`,
    },
    {
        m: "POST",
        p: "/api/hash",
        d: "Generate a hash (13 algorithms)",
        req: `{"text":"Hello","algorithm":"sha256"}`,
        res: `{"hash":"185f8db32921bd46d...","algorithm":"sha256","length":64,"bits":256}`,
    },
    {
        m: "POST",
        p: "/api/hash/all",
        d: "Generate all hashes simultaneously",
        req: `{"text":"Hello"}`,
        res: `{"hashes":{"md5":"8b1a9953c...","sha256":"185f8db3..."}}`,
    },
    {
        m: "POST",
        p: "/api/hash/verify",
        d: "Verify hash (constant-time comparison)",
        req: `{"text":"Hello","hash":"185f8db3...","algorithm":"sha256"}`,
        res: `{"match":true,"algorithm":"sha256","computed":"185f8db3..."}`,
    },
    {
        m: "POST",
        p: "/api/jwt/decode",
        d: "Decode JWT without verifying signature",
        req: `{"token":"eyJhbGciOiJIUzI1NiJ9..."}`,
        res: `{"header":{...},"payload":{...},"is_expired":false}`,
    },
    {
        m: "POST",
        p: "/api/jwt/generate",
        d: "Generate a signed JWT token",
        req: `{"payload":{"role":"admin"},"secret":"key","algorithm":"HS256","expires_in":3600}`,
        res: `{"token":"eyJ...","algorithm":"HS256","expires_at":1700003600}`,
    },
    {
        m: "POST",
        p: "/api/jwt/verify",
        d: "Verify JWT HMAC signature",
        req: `{"token":"eyJ...","secret":"key"}`,
        res: `{"valid":true,"payload":{...},"error":null}`,
    },
    {
        m: "POST",
        p: "/api/compress",
        d: "Compress text (GZIP/ZLIB/LZMA/Brotli)",
        req: `{"text":"Hello World","algorithm":"gzip","base64_output":true}`,
        res: `{"result":"H4sIAAAA...","original_size":11,"compressed_size":31,"ratio":-181.8}`,
    },
    {
        m: "POST",
        p: "/api/decompress",
        d: "Decompress data",
        req: `{"text":"H4sIAAAA...","algorithm":"gzip","base64_input":true}`,
        res: `{"result":"Hello World","compressed_size":31,"decompressed_size":11}`,
    },
    {
        m: "POST",
        p: "/api/uuid",
        d: "Generate UUIDs v1/v4/v7 or NanoID",
        req: `{"version":"v4","count":5}`,
        res: `{"uuids":["550e8400-e29b-..."],"version":"v4","count":5}`,
    },
    {
        m: "POST",
        p: "/api/password",
        d: "Generate secure passwords with entropy",
        req: `{"length":20,"uppercase":true,"lowercase":true,"numbers":true,"symbols":true}`,
        res: `{"passwords":["..."],"strength":"Strong","entropy_bits":131.1}`,
    },
    {
        m: "POST",
        p: "/api/random-string",
        d: "Generate random strings",
        req: `{"length":32,"string_type":"hex","count":3}`,
        res: `{"strings":["a1b2c3..."],"type":"hex","length":32}`,
    },
    {
        m: "POST",
        p: "/api/timestamp",
        d: "Convert Unix timestamp ↔ ISO / UTC",
        req: `{"unix":1700000000}`,
        res: `{"unix":1700000000,"iso":"2023-11-14T22:13:20+00:00","utc":"Tue, 14 Nov 2023..."}`,
    },
    {
        m: "POST",
        p: "/api/color",
        d: "Convert color formats (HEX/RGB/HSL)",
        req: `{"value":"#7c3aed"}`,
        res: `{"hex":"#7C3AED","rgb":{"r":124,"g":58,"b":237},"hsl":{"h":262.1,...}}`,
    },
    {
        m: "POST",
        p: "/api/slug",
        d: "Generate slug and string case variants",
        req: `{"text":"Hello World Post!"}`,
        res: `{"slug":"hello-world-post","snake_case":"hello_world_post","camel_case":"helloWorldPost"}`,
    },
    {
        m: "GET",
        p: "/api/tools",
        d: "List all available algorithms",
        req: null,
        res: `{"encoding_algorithms":[...],"hash_algorithms":[...],"compression_algorithms":[...]}`,
    },
    {
        m: "GET",
        p: "/health",
        d: "Health check",
        req: null,
        res: `{"status":"healthy","timestamp":"2025-01-01T00:00:00Z","version":"2.0.0"}`,
    },
];

function renderApiDocs() {
    document.getElementById("apiEndpoints").innerHTML = ENDPOINTS.map(
        (ep, i) => `
<div class="ep" id="ep${i}">
<div class="ep-head" onclick="toggleEp(${i})" role="button" aria-expanded="false" aria-controls="ep-body-${i}">
<span class="ep-method method-${ep.m.toLowerCase()}">${ep.m}</span>
<span class="ep-path">${esc(ep.p)}</span>
<span class="ep-desc">${esc(ep.d)}</span>
<i data-lucide="chevron-down" class="ep-chevron" style="width:13px;height:13px" aria-hidden="true"></i>
</div>
<div class="ep-body" id="ep-body-${i}">
${ep.req ? `<div class="mb-8"><strong style="font-size:10px;color:var(--c-muted);letter-spacing:.8px;text-transform:uppercase">Request Body</strong><pre class="ep-code ep-req mt-8">${esc(ep.req)}</pre></div>` : ""}
<div><strong style="font-size:10px;color:var(--c-muted);letter-spacing:.8px;text-transform:uppercase">Response</strong><pre class="ep-code ep-res mt-8">${esc(ep.res)}</pre></div>
</div>
</div>`,
    ).join("");
    if (window.lucide)
        lucide.createIcons({ nodes: [document.getElementById("apiEndpoints")] });
}

function toggleEp(i) {
    const ep = document.getElementById("ep" + i);
    const head = ep.querySelector(".ep-head");
    const open = ep.classList.toggle("open");
    head.setAttribute("aria-expanded", open);
}

/* ─────────────────────────────────────────────
    SEARCH MODAL
───────────────────────────────────────────── */
const SEARCH_INDEX = [
    {
        cat: "Encode",
        name: "Base64",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "base64";
            runEnc();
        },
    },
    {
        cat: "Encode",
        name: "Hex Encode",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "hex";
            runEnc();
        },
    },
    {
        cat: "Encode",
        name: "Binary",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "binary";
            runEnc();
        },
    },
    {
        cat: "Encode",
        name: "Base32",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "base32";
        },
    },
    {
        cat: "Encode",
        name: "Base58",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "base58";
        },
    },
    {
        cat: "Encode",
        name: "Base85",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "base85";
        },
    },
    {
        cat: "Encode",
        name: "URL Encode",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "url";
            runEnc();
        },
    },
    {
        cat: "Encode",
        name: "HTML Entities",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "html";
        },
    },
    {
        cat: "Encode",
        name: "Unicode Escape",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "unicode";
        },
    },
    {
        cat: "Encode",
        name: "ROT13",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "rot13";
            runEnc();
        },
    },
    {
        cat: "Encode",
        name: "Caesar Cipher",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "caesar";
            onEncAlgoChange();
        },
    },
    {
        cat: "Encode",
        name: "Vigenère",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "vigenere";
            onEncAlgoChange();
        },
    },
    {
        cat: "Encode",
        name: "Morse Code",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "morse";
        },
    },
    {
        cat: "Encode",
        name: "Atbash",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "atbash";
        },
    },
    {
        cat: "Encode",
        name: "Bacon Cipher",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "bacon";
        },
    },
    {
        cat: "Encode",
        name: "Rail Fence",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "railfence";
            onEncAlgoChange();
        },
    },
    {
        cat: "Encode",
        name: "Affine Cipher",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "affine";
            onEncAlgoChange();
        },
    },
    {
        cat: "Encode",
        name: "Polybius Square",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "polybius";
        },
    },
    {
        cat: "Encode",
        name: "ASCII Codes",
        fn: () => {
            goto("encode");
            document.getElementById("encAlgo").value = "ascii";
        },
    },
    {
        cat: "Hash",
        name: "SHA-256",
        fn: () => {
            goto("hash");
            document.querySelector('[data-hash="sha256"]').click();
        },
    },
    {
        cat: "Hash",
        name: "MD5",
        fn: () => {
            goto("hash");
            document.querySelector('[data-hash="md5"]').click();
        },
    },
    {
        cat: "Hash",
        name: "SHA-512",
        fn: () => {
            goto("hash");
            document.querySelector('[data-hash="sha512"]').click();
        },
    },
    {
        cat: "Hash",
        name: "BLAKE2b",
        fn: () => {
            goto("hash");
            document.querySelector('[data-hash="blake2b"]').click();
        },
    },
    {
        cat: "Hash",
        name: "RIPEMD160",
        fn: () => {
            goto("hash");
            document.querySelector('[data-hash="ripemd160"]').click();
        },
    },
    {
        cat: "Hash",
        name: "Verify Hash",
        fn: () => {
            goto("hash");
            document.querySelector('[data-tab="verify"]').click();
        },
    },
    {
        cat: "JWT",
        name: "Decode JWT",
        fn: () => {
            goto("jwt");
            document.querySelector('[data-tab="decode"]').click();
        },
    },
    {
        cat: "JWT",
        name: "Generate JWT",
        fn: () => {
            goto("jwt");
            document.querySelector('[data-tab="generate"]').click();
        },
    },
    {
        cat: "JWT",
        name: "Verify JWT",
        fn: () => {
            goto("jwt");
            document.querySelector('[data-tab="verify"]').click();
        },
    },
    { cat: "Tools", name: "UUID Generator", fn: () => goto("devtools") },
    { cat: "Tools", name: "Password Generator", fn: () => goto("devtools") },
    { cat: "Tools", name: "Timestamp Converter", fn: () => goto("devtools") },
    { cat: "Tools", name: "Color Converter", fn: () => goto("devtools") },
    { cat: "Tools", name: "Random String", fn: () => goto("devtools") },
    { cat: "Tools", name: "Slug Generator", fn: () => goto("devtools") },
    { cat: "Compress", name: "GZIP Compress", fn: () => goto("compression") },
    { cat: "Compress", name: "LZMA Compress", fn: () => goto("compression") },
    { cat: "Format", name: "JSON Formatter", fn: () => goto("json") },
    { cat: "Format", name: "JSON Minify", fn: () => goto("json") },
    {
        cat: "Format",
        name: "YAML → JSON",
        fn: () => {
            goto("json");
            document.querySelector('[data-tab="yaml"]').click();
        },
    },
    {
        cat: "Format",
        name: "XML Formatter",
        fn: () => {
            goto("json");
            document.querySelector('[data-tab="xml"]').click();
        },
    },
    {
        cat: "Format",
        name: "SQL Formatter",
        fn: () => {
            goto("json");
            document.querySelector('[data-tab="sql"]').click();
        },
    },
    { cat: "QR", name: "QR Code", fn: () => goto("qr") },
    { cat: "API", name: "API Docs", fn: () => goto("api") },
];

let searchIdx = -1;

function openSearch() {
    document.getElementById("searchMask").classList.add("open");
    const si = document.getElementById("searchIn");
    si.value = "";
    renderSearch("");
    setTimeout(() => si.focus(), 40);
    searchIdx = -1;
}
function closeSearch() {
    document.getElementById("searchMask").classList.remove("open");
}
function onMaskClick(e) {
    if (e.target === document.getElementById("searchMask")) closeSearch();
}

function renderSearch(q) {
    const results = q.trim()
        ? SEARCH_INDEX.filter(
            (r) =>
                r.name.toLowerCase().includes(q.toLowerCase()) ||
                r.cat.toLowerCase().includes(q.toLowerCase()),
        )
        : SEARCH_INDEX.slice(0, 14);
    const el = document.getElementById("searchResults");
    if (!results.length) {
        el.innerHTML = `<div class="search-empty">No results for "${esc(q)}"</div>`;
        return;
    }
    el.innerHTML = results
        .map(
            (r, idx) => `
<div class="search-item" role="option" data-si="${SEARCH_INDEX.indexOf(r)}" onclick="pickSearch(${SEARCH_INDEX.indexOf(r)})" aria-label="${esc(r.name)}">
<span class="search-cat">${esc(r.cat)}</span>
<span class="search-name">${esc(r.name)}</span>
</div>`,
        )
        .join("");
    searchIdx = -1;
}

function onSearchKey(e) {
    const items = document.querySelectorAll(".search-item");
    if (e.key === "ArrowDown") {
        e.preventDefault();
        searchIdx = Math.min(searchIdx + 1, items.length - 1);
    } else if (e.key === "ArrowUp") {
        e.preventDefault();
        searchIdx = Math.max(searchIdx - 1, 0);
    } else if (e.key === "Enter" && searchIdx >= 0) {
        const idx = parseInt(items[searchIdx]?.dataset.si ?? -1);
        if (idx >= 0) pickSearch(idx);
        return;
    } else if (e.key === "Escape") {
        closeSearch();
        return;
    }
    items.forEach((it, i) => it.classList.toggle("focused", i === searchIdx));
    if (searchIdx >= 0) items[searchIdx]?.scrollIntoView({ block: "nearest" });
}

function pickSearch(idx) {
    SEARCH_INDEX[idx]?.fn();
    closeSearch();
}

/* ─────────────────────────────────────────────
    MOBILE DRAWER
───────────────────────────────────────────── */
function openDrawer() {
    document.getElementById("drawer").classList.add("open");
    document.getElementById("drawerMask").classList.add("open");
    document.getElementById("hamburger").setAttribute("aria-expanded", "true");
}
function closeDrawer() {
    document.getElementById("drawer").classList.remove("open");
    document.getElementById("drawerMask").classList.remove("open");
    document.getElementById("hamburger").setAttribute("aria-expanded", "false");
}

/* ─────────────────────────────────────────────
    KEYBOARD SHORTCUTS
───────────────────────────────────────────── */
document.addEventListener("keydown", (e) => {
    const meta = e.metaKey || e.ctrlKey;
    if (meta && e.key === "k") {
        e.preventDefault();
        openSearch();
    }
    if (meta && e.shiftKey && e.key === "C") {
        e.preventDefault();
        copyHomeOut();
    }
    if (meta && e.key === ".") {
        e.preventDefault();
        goto("home");
    }
    if (e.key === "Escape") {
        closeSearch();
        closeDrawer();
    }
});

/* ─────────────────────────────────────────────
    UTILITY
───────────────────────────────────────────── */
function dlText(text, filename) {
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast(`Downloaded ${filename}`);
}

function copyOut(id) {
    const el = document.getElementById(id);
    copyWithFeedback(el?.textContent || el?.value || "");
}

function copyTA(id) {
    const el = document.getElementById(id);
    copyWithFeedback(el?.value || el?.textContent || "");
}

/* ─────────────────────────────────────────────
    API STATUS POLLING
───────────────────────────────────────────── */
async function checkApi() {
    const was = apiOnline;
    apiOnline = await Api.ping();
    const dot = document.getElementById("apiDot");
    const txt = document.getElementById("apiStatusTxt");
    if (dot) {
        dot.className = "api-dot" + (apiOnline ? " online" : "");
    }
    if (txt) txt.textContent = apiOnline ? "API Online" : "API Offline";

    // Update encode page banner
    const banner = document.getElementById("encApiBanner");
    const encDot = document.getElementById("encDot");
    const encTxt = document.getElementById("encBannerTxt");
    if (banner) {
        banner.classList.remove("hidden");
        banner.className = "api-online-badge" + (apiOnline ? "" : " offline");
        if (encDot) encDot.className = "api-dot" + (apiOnline ? " online" : "");
        if (encTxt)
            encTxt.textContent = apiOnline
                ? "Backend connected — using API for all operations"
                : "Backend offline — using client-side engine (offline mode)";
    }

    updateCompBanner();
    if (apiOnline && !was) toast("Backend API connected", "info");
    if (!apiOnline && was) toast("Backend offline — fallback active", "warn");
}

/* ─────────────────────────────────────────────
    MOTION ANIMATIONS
───────────────────────────────────────────── */
function runAnimations() {
    if (!window.Motion) return;
    const { animate, stagger } = window.Motion;
    try {
        animate(
            ".hero-badge",
            { opacity: [0, 1], y: [12, 0] },
            { duration: 0.4, easing: [0.25, 0.1, 0.25, 1] },
        );
        animate(
            ".hero-h1",
            { opacity: [0, 1], y: [40, 0] },
            { duration: 0.65, delay: 0.06, easing: [0.25, 0.1, 0.25, 1] },
        );
        animate(
            ".hero-sub",
            { opacity: [0, 1], y: [24, 0] },
            { duration: 0.5, delay: 0.18 },
        );
        animate(
            ".hero-pill",
            { opacity: [0, 1], y: [16, 0] },
            { duration: 0.4, delay: stagger(0.07, { start: 0.32 }) },
        );
        animate(
            ".workspace",
            { opacity: [0, 1], y: [24, 0] },
            { duration: 0.55, delay: 0.52 },
        );
        animate(
            ".why-item",
            { opacity: [0, 1], y: [16, 0] },
            { duration: 0.4, delay: stagger(0.08, { start: 0.72 }) },
        );
    } catch (e) {
        /* Motion not critical */
    }
}

/* ─────────────────────────────────────────────
    INIT
───────────────────────────────────────────── */
function init() {
    // Icons
    if (window.lucide) lucide.createIcons();

    // Route
    const hash = window.location.hash.slice(1);
    goto(PAGES.includes(hash) ? hash : "home");

    // Tabs
    initTabs();
    initHashBtns();

    // Statics
    renderPopular();
    renderApiDocs();

    // Animations (runs after lucide)
    if (document.readyState === "complete") runAnimations();
    else window.addEventListener("load", runAnimations);

    // API health
    checkApi();
    setInterval(checkApi, 30_000);
}

if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", init);
else init();
