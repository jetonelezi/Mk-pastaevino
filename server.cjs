"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = path.resolve(process.env.OTPADET_DB || path.join(ROOT, "otpadet.sqlite"));
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const MAX_IMAGE_BYTES = 500 * 1024;
const SESSION_COOKIE = "otpadet_session";
const PASSWORD_ITERATIONS = 310000;
const sessions = new Map();
const loginAttempts = new Map();

const db = new DatabaseSync(DB_PATH);
db.exec(`
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        phone TEXT NOT NULL UNIQUE,
        password_salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin', 'company')),
        company_id TEXT
    );
    CREATE TABLE IF NOT EXISTS companies (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL UNIQUE REFERENCES accounts(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        owner TEXT NOT NULL,
        phone TEXT NOT NULL,
        phone2 TEXT NOT NULL DEFAULT '',
        location TEXT NOT NULL,
        location_lat REAL,
        location_lng REAL,
        logo TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS parts (
        id TEXT PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        make TEXT NOT NULL,
        model TEXT NOT NULL,
        engine TEXT NOT NULL DEFAULT '',
        year_from INTEGER NOT NULL,
        year_to INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        photo TEXT NOT NULL DEFAULT ''
    );
`);

const statements = {
    accountByPhone: db.prepare("SELECT * FROM accounts WHERE phone = ?"),
    accountById: db.prepare("SELECT id, phone, role, company_id AS companyId FROM accounts WHERE id = ?"),
    companyByAccount: db.prepare("SELECT * FROM companies WHERE account_id = ?"),
    companyById: db.prepare("SELECT * FROM companies WHERE id = ?"),
    insertAccount: db.prepare("INSERT INTO accounts (id, phone, password_salt, password_hash, role, company_id) VALUES (?, ?, ?, ?, ?, ?)"),
    insertCompany: db.prepare(`INSERT INTO companies
        (id, account_id, name, owner, phone, phone2, location, location_lat, location_lng, logo)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
    insertPart: db.prepare(`INSERT INTO parts
        (id, company_id, make, model, engine, year_from, year_to, name, description, photo)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
    partsByCompany: db.prepare(`SELECT id, make, model, engine, year_from AS yearFrom, year_to AS yearTo,
        name, description, photo FROM parts WHERE company_id = ? ORDER BY name COLLATE NOCASE`),
    publicCompanies: db.prepare(`SELECT c.id, c.name, c.owner, c.phone, c.phone2, c.location,
        c.location_lat AS locationLat, c.location_lng AS locationLng, c.logo
        FROM companies c ORDER BY c.name COLLATE NOCASE`),
    publicCompanyById: db.prepare(`SELECT id, name, owner, phone, phone2, location,
        location_lat AS locationLat, location_lng AS locationLng, logo
        FROM companies WHERE id = ?`),
    adminCompanies: db.prepare(`SELECT c.id, c.account_id AS accountId, c.name, c.owner, c.phone, c.phone2,
        c.location, c.location_lat AS locationLat, c.location_lng AS locationLng, c.logo,
        a.phone AS loginPhone, (SELECT COUNT(*) FROM parts p WHERE p.company_id = c.id) AS partCount
        FROM companies c JOIN accounts a ON a.id = c.account_id ORDER BY c.name COLLATE NOCASE`),
    partByIdAndCompany: db.prepare("SELECT id FROM parts WHERE id = ? AND company_id = ?"),
    deletePart: db.prepare("DELETE FROM parts WHERE id = ? AND company_id = ?"),
    deletePartById: db.prepare("DELETE FROM parts WHERE id = ?"),
    deleteCompany: db.prepare("DELETE FROM companies WHERE id = ?"),
    deleteAccount: db.prepare("DELETE FROM accounts WHERE id = ?"),
    updateCompany: db.prepare(`UPDATE companies SET name = ?, owner = ?, phone = ?, phone2 = ?,
        location = ?, location_lat = ?, location_lng = ?, logo = ? WHERE id = ?`),
    updateAccountPhone: db.prepare("UPDATE accounts SET phone = ? WHERE id = ?"),
    accountByCompany: db.prepare("SELECT id FROM accounts WHERE company_id = ? AND role = 'company'"),
    updatePart: db.prepare(`UPDATE parts SET make = ?, model = ?, engine = ?, year_from = ?, year_to = ?,
        name = ?, description = ?, photo = ? WHERE id = ?`),
    adminParts: db.prepare(`SELECT id, make, model, engine, year_from AS yearFrom, year_to AS yearTo,
        name, description, photo FROM parts WHERE company_id = ? ORDER BY name COLLATE NOCASE`)
};

function normalizePhone(value) {
    return String(value || "").replace(/\D/g, "");
}

function hashPassword(password, salt) {
    return crypto.pbkdf2Sync(password, salt, PASSWORD_ITERATIONS, 32, "sha256").toString("hex");
}

function verifyPassword(password, account) {
    const actual = Buffer.from(hashPassword(password, account.password_salt), "hex");
    const expected = Buffer.from(account.password_hash, "hex");
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function seedAdmin() {
    const phone = normalizePhone(process.env.ADMIN_PHONE);
    const password = process.env.ADMIN_PASSWORD;
    if (!phone && !password) return;
    if (!phone || !password || phone.length < 6 || password.length < 12) {
        throw new Error("ADMIN_PHONE dhe ADMIN_PASSWORD kërkohen bashkë; fjalëkalimi admin duhet të ketë të paktën 12 karaktere.");
    }
    const current = statements.accountByPhone.get(phone);
    if (current && current.role !== "admin") {
        throw new Error("Numri i konfiguruar për admin është tashmë llogari kompanie; përdor një numër tjetër.");
    }
    if (current) {
        const salt = crypto.randomBytes(16).toString("hex");
        db.prepare("UPDATE accounts SET password_salt = ?, password_hash = ? WHERE id = ?")
            .run(salt, hashPassword(password, salt), current.id);
    } else {
        const salt = crypto.randomBytes(16).toString("hex");
        statements.insertAccount.run(crypto.randomUUID(), phone, salt, hashPassword(password, salt), "admin", null);
    }
}

seedAdmin();

function sendJson(response, status, payload, extraHeaders = {}) {
    response.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        ...extraHeaders
    });
    response.end(JSON.stringify(payload));
}

function sendError(response, status, message) {
    sendJson(response, status, { error: message });
}

function parseCookies(request) {
    const result = {};
    for (const item of String(request.headers.cookie || "").split(";")) {
        const separator = item.indexOf("=");
        if (separator > 0) result[item.slice(0, separator).trim()] = decodeURIComponent(item.slice(separator + 1).trim());
    }
    return result;
}

function getSession(request) {
    const token = parseCookies(request)[SESSION_COOKIE];
    if (!token) return null;
    const session = sessions.get(token);
    if (!session || session.expiresAt <= Date.now()) {
        sessions.delete(token);
        return null;
    }
    const account = statements.accountById.get(session.accountId);
    if (!account) {
        sessions.delete(token);
        return null;
    }
    return { token, account };
}

function setSession(response, account) {
    const token = crypto.randomBytes(32).toString("base64url");
    sessions.set(token, { accountId: account.id, expiresAt: Date.now() + SESSION_TTL_MS });
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    response.setHeader("Set-Cookie", `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}${secure}`);
}

function clearSession(request, response) {
    const token = parseCookies(request)[SESSION_COOKIE];
    if (token) sessions.delete(token);
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    response.setHeader("Set-Cookie", `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`);
}

function requireSession(request, response, role) {
    const session = getSession(request);
    if (!session) {
        sendError(response, 401, "Duhet të hysh në llogari.");
        return null;
    }
    if (role && session.account.role !== role) {
        sendError(response, 403, "Nuk ke leje për këtë veprim.");
        return null;
    }
    return session;
}

function checkOrigin(request, response) {
    const origin = request.headers.origin;
    if (!origin) {
        sendError(response, 403, "Kërkesa u refuzua.");
        return false;
    }
    const allowed = process.env.PUBLIC_ORIGIN;
    if (allowed) {
        if (origin !== allowed) {
            sendError(response, 403, "Kërkesa u refuzua.");
            return false;
        }
        return true;
    }
    try {
        const parsedOrigin = new URL(origin);
        if (parsedOrigin.host === request.headers.host) return true;
        const localHost = (host) => host === "localhost" || host === "127.0.0.1";
        const liveServerOrigin = process.env.NODE_ENV !== "production" &&
            parsedOrigin.protocol === "http:" &&
            localHost(parsedOrigin.hostname) &&
            parsedOrigin.port === "5500" &&
            localHost(new URL(`http://${request.headers.host}`).hostname);
        if (liveServerOrigin) return true;
        sendError(response, 403, "Kërkesa u refuzua.");
        return false;
    } catch {
        sendError(response, 403, "Kërkesa u refuzua.");
        return false;
    }
}

function applyApiCors(request, response) {
    const origin = request.headers.origin;
    if (!origin) return true;
    const allowed = process.env.PUBLIC_ORIGIN;
    let permitted = origin === allowed;
    if (!allowed) {
        try {
            const parsedOrigin = new URL(origin);
            const requestHost = new URL(`http://${request.headers.host || "localhost"}`);
            const localHost = (host) => host === "localhost" || host === "127.0.0.1";
            permitted = parsedOrigin.host === requestHost.host ||
                (process.env.NODE_ENV !== "production" &&
                    parsedOrigin.protocol === "http:" &&
                    localHost(parsedOrigin.hostname) &&
                    parsedOrigin.port === "5500" &&
                    localHost(requestHost.hostname));
        } catch {
            permitted = false;
        }
    }
    if (!permitted) return false;
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Access-Control-Allow-Credentials", "true");
    response.setHeader("Vary", "Origin");
    return true;
}

function readJson(request) {
    return new Promise((resolve, reject) => {
        let size = 0;
        let tooLarge = false;
        const chunks = [];
        request.on("data", (chunk) => {
            size += chunk.length;
            if (size > MAX_BODY_BYTES) {
                tooLarge = true;
                chunks.length = 0;
            } else if (!tooLarge) {
                chunks.push(chunk);
            }
        });
        request.on("end", () => {
            if (tooLarge) {
                reject(Object.assign(new Error("Kërkesa është shumë e madhe."), { status: 413 }));
                return;
            }
            try {
                const value = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
                if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Trupi i kërkesës nuk është i vlefshëm.");
                resolve(value);
            } catch {
                reject(Object.assign(new Error("Të dhënat e dërguara nuk janë JSON i vlefshëm."), { status: 400 }));
            }
        });
        request.on("error", reject);
    });
}

function text(value, field, maxLength, required = true) {
    if (typeof value !== "string") throw Object.assign(new Error(`${field} nuk është i vlefshëm.`), { status: 400 });
    const trimmed = value.trim();
    if (required && !trimmed) throw Object.assign(new Error(`${field} është i detyrueshëm.`), { status: 400 });
    if (trimmed.length > maxLength) throw Object.assign(new Error(`${field} është shumë i gjatë.`), { status: 400 });
    return trimmed;
}

function image(value, field) {
    if (value === undefined || value === null || value === "") return "";
    if (typeof value !== "string") throw Object.assign(new Error(`${field} nuk është i vlefshëm.`), { status: 400 });
    const match = /^data:image\/(png|jpeg|webp|gif);base64,([A-Za-z0-9+/=]+)$/.exec(value);
    if (!match || Buffer.from(match[2], "base64").length > MAX_IMAGE_BYTES) {
        throw Object.assign(new Error(`${field} duhet të jetë PNG, JPEG, WEBP ose GIF dhe maksimumi 500 KB.`), { status: 400 });
    }
    return value;
}

function coordinate(value, min, max, field) {
    if (value === null || value === undefined || value === "") return null;
    const number = Number(value);
    if (!Number.isFinite(number) || number < min || number > max) {
        throw Object.assign(new Error(`${field} nuk është koordinatë e vlefshme.`), { status: 400 });
    }
    return number;
}

function validateCompany(body) {
    const phone = text(body.phone, "Numri i kontaktit", 30);
    const normalizedPhone = normalizePhone(phone);
    if (normalizedPhone.length < 6 || normalizedPhone.length > 15) {
        throw Object.assign(new Error("Numri i kontaktit duhet të ketë 6 deri në 15 shifra."), { status: 400 });
    }
    return {
        name: text(body.name, "Emri i kompanisë", 100),
        owner: text(body.owner, "Emri i udhëheqësit", 100),
        phone,
        normalizedPhone,
        phone2: text(body.phone2 || "", "Numri i dytë", 30, false),
        location: text(body.location, "Lokacioni", 300),
        locationLat: coordinate(body.locationLat, -90, 90, "Gjerësia gjeografike"),
        locationLng: coordinate(body.locationLng, -180, 180, "Gjatësia gjeografike"),
        logo: image(body.logo, "Logo")
    };
}

function validatePart(body) {
    const yearFrom = Number(body.yearFrom);
    const yearTo = Number(body.yearTo);
    const currentYear = new Date().getFullYear();
    if (!Number.isInteger(yearFrom) || !Number.isInteger(yearTo) ||
        yearFrom < 1950 || yearFrom > currentYear + 1 ||
        yearTo < yearFrom || yearTo > currentYear + 1) {
        throw Object.assign(new Error("Vitet e prodhimit nuk janë të vlefshme."), { status: 400 });
    }
    return {
        make: text(body.make, "Marka", 60),
        model: text(body.model, "Modeli", 80),
        engine: text(body.engine || "", "Kubikazha", 40, false),
        yearFrom,
        yearTo,
        name: text(body.name, "Emri i pjesës", 100),
        description: text(body.description || "", "Përshkrimi", 400, false),
        photo: image(body.photo, "Fotografia")
    };
}

function toPublicCompany(row) {
    return {
        id: row.id,
        name: row.name,
        owner: row.owner,
        phone: row.phone,
        phone2: row.phone2,
        location: row.location,
        locationLat: row.locationLat ?? row.location_lat ?? null,
        locationLng: row.locationLng ?? row.location_lng ?? null,
        logo: row.logo,
        parts: statements.partsByCompany.all(row.id)
    };
}

function companyForAccount(account) {
    return account.role === "company" ? statements.companyByAccount.get(account.id) : null;
}

function adminList() {
    return statements.adminCompanies.all().map((company) => ({
        ...toPublicCompany(company),
        accountId: company.accountId,
        loginPhone: company.loginPhone,
        partCount: Number(company.partCount)
    }));
}

function transaction(callback) {
    db.exec("BEGIN IMMEDIATE");
    try {
        const result = callback();
        db.exec("COMMIT");
        return result;
    } catch (error) {
        db.exec("ROLLBACK");
        throw error;
    }
}

function checkLoginRate(request, phone) {
    const forwarded = request.socket.remoteAddress || "unknown";
    const key = `${forwarded}:${phone}`;
    const record = loginAttempts.get(key);
    if (!record || record.resetAt <= Date.now()) {
        loginAttempts.set(key, { count: 1, resetAt: Date.now() + 15 * 60 * 1000 });
        return true;
    }
    if (record.count >= 10) return false;
    record.count += 1;
    return true;
}

async function handleApi(request, response, url) {
    const method = request.method;
    const pathname = url.pathname;
    const mutating = ["POST", "PUT", "DELETE"].includes(method);
    if (mutating && !checkOrigin(request, response)) return;

    if (method === "GET" && pathname === "/api/health") {
        sendJson(response, 200, { status: "ok" });
        return;
    }

    if (method === "GET" && pathname === "/api/public") {
        const companies = statements.publicCompanies.all().map(toPublicCompany);
        sendJson(response, 200, { companies });
        return;
    }

    if (method === "POST" && pathname === "/api/register") {
        const body = await readJson(request);
        const phone = normalizePhone(body.phone);
        if (typeof body.password !== "string" || body.password.length > 128) {
            throw Object.assign(new Error("Fjalëkalimi nuk është i vlefshëm."), { status: 400 });
        }
        const password = body.password;
        if (phone.length < 6 || phone.length > 15) throw Object.assign(new Error("Numri i kontaktit duhet të ketë 6 deri në 15 shifra."), { status: 400 });
        if (password.length < 8) throw Object.assign(new Error("Fjalëkalimi duhet të ketë të paktën 8 karaktere."), { status: 400 });
        const details = validateCompany(body);
        if (statements.accountByPhone.get(phone)) throw Object.assign(new Error("Ky numër ka tashmë llogari."), { status: 409 });
        const accountId = crypto.randomUUID();
        const companyId = crypto.randomUUID();
        const salt = crypto.randomBytes(16).toString("hex");
        transaction(() => {
            statements.insertAccount.run(accountId, phone, salt, hashPassword(password, salt), "company", companyId);
            statements.insertCompany.run(companyId, accountId, details.name, details.owner, details.phone, details.phone2,
                details.location, details.locationLat, details.locationLng, details.logo);
        });
        setSession(response, { id: accountId });
        sendJson(response, 201, { company: toPublicCompany(statements.companyById.get(companyId)) });
        return;
    }

    if (method === "POST" && pathname === "/api/login") {
        const body = await readJson(request);
        const phone = normalizePhone(body.phone);
        if (!checkLoginRate(request, phone)) {
            sendError(response, 429, "Shumë tentativa hyrjeje. Provo përsëri pas 15 minutash.");
            return;
        }
        const account = statements.accountByPhone.get(phone);
        const password = typeof body.password === "string" ? body.password : "";
        if (!account || !verifyPassword(password, account)) {
            sendError(response, 401, "Numri ose fjalëkalimi nuk është i saktë.");
            return;
        }
        setSession(response, account);
        if (account.role === "admin") {
            sendJson(response, 200, { role: "admin" });
            return;
        }
        const company = companyForAccount(account);
        if (!company) {
            clearSession(request, response);
            sendError(response, 500, "Llogaria nuk ka kompani të lidhur. Kontakto administratorin.");
            return;
        }
        sendJson(response, 200, { role: "company", company: toPublicCompany(company) });
        return;
    }

    if (method === "POST" && pathname === "/api/logout") {
        clearSession(request, response);
        sendJson(response, 200, { ok: true });
        return;
    }

    if (method === "GET" && pathname === "/api/me") {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 200, { authenticated: false });
            return;
        }
        sendJson(response, 200, { authenticated: true, role: session.account.role });
        return;
    }

    if (method === "GET" && pathname === "/api/me/company") {
        const session = requireSession(request, response, "company");
        if (!session) return;
        const company = companyForAccount(session.account);
        if (!company) {
            sendError(response, 404, "Kompania nuk u gjet.");
            return;
        }
        sendJson(response, 200, { company: toPublicCompany(company) });
        return;
    }

    if (method === "PUT" && pathname === "/api/me/company") {
        const session = requireSession(request, response, "company");
        if (!session) return;
        const company = companyForAccount(session.account);
        if (!company) {
            sendError(response, 404, "Kompania nuk u gjet.");
            return;
        }
        const details = validateCompany(await readJson(request));
        const existingAccount = statements.accountByPhone.get(details.normalizedPhone);
        if (existingAccount && existingAccount.id !== session.account.id) {
            sendError(response, 409, "Ky numër telefoni përdoret nga një llogari tjetër.");
            return;
        }
        transaction(() => {
            statements.updateCompany.run(details.name, details.owner, details.phone, details.phone2, details.location,
                details.locationLat, details.locationLng, details.logo, company.id);
            statements.updateAccountPhone.run(details.normalizedPhone, session.account.id);
        });
        sendJson(response, 200, { company: toPublicCompany(statements.companyById.get(company.id)) });
        return;
    }

    if (method === "POST" && pathname === "/api/me/parts") {
        const session = requireSession(request, response, "company");
        if (!session) return;
        const company = companyForAccount(session.account);
        const details = validatePart(await readJson(request));
        const id = crypto.randomUUID();
        statements.insertPart.run(id, company.id, details.make, details.model, details.engine, details.yearFrom,
            details.yearTo, details.name, details.description, details.photo);
        sendJson(response, 201, { part: statements.partsByCompany.all(company.id).find((part) => part.id === id) });
        return;
    }

    const ownerPart = pathname.match(/^\/api\/me\/parts\/([0-9a-f-]+)$/i);
    if (ownerPart && (method === "PUT" || method === "DELETE")) {
        const session = requireSession(request, response, "company");
        if (!session) return;
        const company = companyForAccount(session.account);
        if (!company || !statements.partByIdAndCompany.get(ownerPart[1], company.id)) {
            sendError(response, 404, "Pjesa nuk u gjet.");
            return;
        }
        if (method === "DELETE") {
            statements.deletePart.run(ownerPart[1], company.id);
            sendJson(response, 200, { ok: true });
            return;
        }
        const details = validatePart(await readJson(request));
        statements.updatePart.run(details.make, details.model, details.engine, details.yearFrom, details.yearTo,
            details.name, details.description, details.photo, ownerPart[1]);
        sendJson(response, 200, { ok: true });
        return;
    }

    if (method === "DELETE" && pathname === "/api/me/account") {
        const session = requireSession(request, response, "company");
        if (!session) return;
        const company = companyForAccount(session.account);
        if (!company) {
            sendError(response, 404, "Kompania nuk u gjet.");
            return;
        }
        transaction(() => {
            db.prepare("DELETE FROM parts WHERE company_id = ?").run(company.id);
            statements.deleteCompany.run(company.id);
            statements.deleteAccount.run(session.account.id);
        });
        clearSession(request, response);
        sendJson(response, 200, { ok: true });
        return;
    }

    if (pathname === "/api/admin/companies" && method === "GET") {
        if (!requireSession(request, response, "admin")) return;
        sendJson(response, 200, { companies: adminList() });
        return;
    }

    if (pathname === "/api/admin/companies" && method === "DELETE") {
        if (!requireSession(request, response, "admin")) return;
        transaction(() => {
            db.exec("DELETE FROM parts; DELETE FROM companies; DELETE FROM accounts WHERE role = 'company';");
        });
        sendJson(response, 200, { ok: true });
        return;
    }

    const adminCompanyPassword = pathname.match(/^\/api\/admin\/companies\/([0-9a-f-]+)\/password$/i);
    if (adminCompanyPassword && method === "PUT") {
        if (!requireSession(request, response, "admin")) return;
        const company = statements.companyById.get(adminCompanyPassword[1]);
        if (!company) {
            sendError(response, 404, "Kompania nuk u gjet.");
            return;
        }
        const body = await readJson(request);
        if (typeof body.password !== "string" || body.password.length < 8 || body.password.length > 128) {
            sendError(response, 400, "Fjalëkalimi duhet të ketë 8 deri në 128 karaktere.");
            return;
        }
        const account = statements.accountByCompany.get(company.id);
        if (!account) {
            sendError(response, 404, "Llogaria e kompanisë nuk u gjet.");
            return;
        }
        const salt = crypto.randomBytes(16).toString("hex");
        db.prepare("UPDATE accounts SET password_salt = ?, password_hash = ? WHERE id = ?")
            .run(salt, hashPassword(body.password, salt), account.id);
        for (const [token, session] of sessions) {
            if (session.accountId === account.id) sessions.delete(token);
        }
        sendJson(response, 200, { ok: true });
        return;
    }

    const adminCompany = pathname.match(/^\/api\/admin\/companies\/([0-9a-f-]+)$/i);
    if (adminCompany && method === "PUT") {
        if (!requireSession(request, response, "admin")) return;
        const company = statements.companyById.get(adminCompany[1]);
        if (!company) {
            sendError(response, 404, "Kompania nuk u gjet.");
            return;
        }
        const details = validateCompany(await readJson(request));
        const account = statements.accountById.get(company.account_id);
        const otherAccount = statements.accountByPhone.get(details.normalizedPhone);
        if (otherAccount && otherAccount.id !== account.id) {
            sendError(response, 409, "Ky numër telefoni përdoret nga një llogari tjetër.");
            return;
        }
        transaction(() => {
            statements.updateCompany.run(details.name, details.owner, details.phone, details.phone2, details.location,
                details.locationLat, details.locationLng, details.logo, company.id);
            statements.updateAccountPhone.run(details.normalizedPhone, account.id);
        });
        sendJson(response, 200, { company: toPublicCompany(statements.companyById.get(company.id)) });
        return;
    }

    if (adminCompany && method === "DELETE") {
        if (!requireSession(request, response, "admin")) return;
        const company = statements.companyById.get(adminCompany[1]);
        if (!company) {
            sendError(response, 404, "Kompania nuk u gjet.");
            return;
        }
        transaction(() => {
            db.prepare("DELETE FROM parts WHERE company_id = ?").run(company.id);
            statements.deleteCompany.run(company.id);
            statements.deleteAccount.run(company.account_id);
        });
        sendJson(response, 200, { ok: true });
        return;
    }

    const adminPart = pathname.match(/^\/api\/admin\/companies\/([0-9a-f-]+)\/parts\/([0-9a-f-]+)$/i);
    if (adminPart && (method === "PUT" || method === "DELETE")) {
        if (!requireSession(request, response, "admin")) return;
        const [companyId, partId] = adminPart.slice(1);
        if (!statements.partByIdAndCompany.get(partId, companyId)) {
            sendError(response, 404, "Pjesa nuk u gjet.");
            return;
        }
        if (method === "DELETE") {
            statements.deletePart.run(partId, companyId);
            sendJson(response, 200, { ok: true });
            return;
        }
        const details = validatePart(await readJson(request));
        statements.updatePart.run(details.make, details.model, details.engine, details.yearFrom, details.yearTo,
            details.name, details.description, details.photo, partId);
        sendJson(response, 200, { ok: true });
        return;
    }

    sendError(response, 404, "Adresa API nuk u gjet.");
}

const mimeTypes = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".ico": "image/x-icon"
};

function serveFile(request, response, url) {
    const pathname = decodeURIComponent(url.pathname);
    const relative = pathname === "/" ? "index.html" : pathname.slice(1);
    const filename = path.resolve(ROOT, relative);
    const allowedPages = new Set(["index.html", "otpadi.html", "otpadet.html", "admin.html"]);
    const isAllowedPage = path.dirname(filename) === ROOT && allowedPages.has(path.basename(filename));
    const photoRoot = path.join(ROOT, "foto") + path.sep;
    const imageExtensions = new Set([".jpg", ".jpeg", ".png", ".webp", ".gif", ".svg"]);
    const isAllowedPhoto = filename.startsWith(photoRoot) &&
        imageExtensions.has(path.extname(filename).toLowerCase());
    if (!isAllowedPage && !isAllowedPhoto) {
        sendError(response, 403, "Nuk lejohet qasja te ky skedar.");
        return;
    }
    fs.stat(filename, (error, info) => {
        if (error || !info.isFile()) {
            sendError(response, 404, "Faqja nuk u gjet.");
            return;
        }
        response.writeHead(200, {
            "Content-Type": mimeTypes[path.extname(filename).toLowerCase()] || "application/octet-stream",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://unpkg.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' https: data: blob:; connect-src 'self' https://nominatim.openstreetmap.org; frame-ancestors 'none'"
        });
        if (request.method === "HEAD") {
            response.end();
            return;
        }
        fs.createReadStream(filename).pipe(response);
    });
}

const server = http.createServer(async (request, response) => {
    try {
        const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
        if (url.pathname.startsWith("/api/")) {
            if (!applyApiCors(request, response)) {
                sendError(response, 403, "Origjina e kërkesës nuk lejohet.");
                return;
            }
            if (request.method === "OPTIONS") {
                response.writeHead(204, {
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type",
                    "Access-Control-Max-Age": "600",
                    "Cache-Control": "no-store"
                });
                response.end();
                return;
            }
            await handleApi(request, response, url);
            return;
        }
        if (request.method !== "GET" && request.method !== "HEAD") {
            sendError(response, 405, "Metoda nuk lejohet.");
            return;
        }
        serveFile(request, response, url);
    } catch (error) {
        console.error("Kërkesa dështoi:", error);
        if (response.headersSent || response.destroyed) return;
        if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
            sendError(response, 409, "Numri i kontaktit është përdorur tashmë.");
            return;
        }
        sendError(response, error.status || 500, error.status ? error.message : "Gabim i brendshëm i serverit.");
    }
});

server.listen(PORT, () => {
    console.log(`AutoParts Tetov po punon në http://localhost:${PORT}`);
    console.log(`Baza e të dhënave: ${DB_PATH}`);
    if (!process.env.ADMIN_PHONE || !process.env.ADMIN_PASSWORD) {
        console.warn("Llogaria admin nuk është konfiguruar. Vendos ADMIN_PHONE dhe ADMIN_PASSWORD para nisjes.");
    }
});

setInterval(() => {
    const now = Date.now();
    for (const [token, session] of sessions) if (session.expiresAt <= now) sessions.delete(token);
    for (const [key, record] of loginAttempts) if (record.resetAt <= now) loginAttempts.delete(key);
}, 60 * 1000).unref();

for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
        server.close(() => {
            db.close();
            process.exit(0);
        });
    });
}
