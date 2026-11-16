"use strict";

const crypto = require("node:crypto");
const { promisify } = require("node:util");
const { cert, getApps, initializeApp } = require("firebase-admin/app");
const { getFirestore: createFirestoreClient } = require("firebase-admin/firestore");

const pbkdf2 = promisify(crypto.pbkdf2);
const SESSION_COOKIE = "otpadet_session";
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const MAX_IMAGE_BYTES = 500 * 1024;
const PASSWORD_ITERATIONS = 310000;
const loginAttempts = new Map();
let firestore;
let adminSeedPromise;

function getDb() {
    if (firestore) return firestore;
    const projectId = process.env.FIREBASE_PROJECT_ID;
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    const privateKey = process.env.FIREBASE_PRIVATE_KEY;
    if (!projectId || !clientEmail || !privateKey) {
        throw Object.assign(new Error("Firebase nuk është konfiguruar në Vercel."), { status: 503 });
    }
    const app = getApps()[0] || initializeApp({
        credential: cert({
            projectId,
            clientEmail,
            privateKey: privateKey.replace(/\\n/g, "\n")
        })
    });
    firestore = createFirestoreClient(app);
    return firestore;
}

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

function appError(status, message) {
    return Object.assign(new Error(message), { status });
}

function requestPath(request) {
    const url = new URL(request.url, `https://${request.headers.host || "localhost"}`);
    const route = request.query && request.query.route;
    if (typeof route === "string" || Array.isArray(route)) {
        const routePath = (Array.isArray(route) ? route.join("/") : route).replace(/^\/+|\/+$/g, "");
        return routePath ? `/api/${routePath}` : "/api";
    }
    return url.pathname;
}

function parseCookies(request) {
    const result = {};
    for (const item of String(request.headers.cookie || "").split(";")) {
        const separator = item.indexOf("=");
        if (separator <= 0) continue;
        try {
            result[item.slice(0, separator).trim()] = decodeURIComponent(item.slice(separator + 1).trim());
        } catch {
            continue;
        }
    }
    return result;
}

function sessionSecret() {
    const secret = process.env.SESSION_SECRET;
    if (!secret || secret.length < 32) {
        throw appError(503, "SESSION_SECRET duhet konfiguruar në Vercel (minimumi 32 karaktere).");
    }
    return secret;
}

function signSession(accountId, expiresAt, sessionVersion = 0) {
    const payload = Buffer.from(JSON.stringify({ accountId, expiresAt, sessionVersion })).toString("base64url");
    const signature = crypto.createHmac("sha256", sessionSecret()).update(payload).digest("base64url");
    return `${payload}.${signature}`;
}

function verifySession(token) {
    if (!token || typeof token !== "string") return null;
    const [payload, signature, extra] = token.split(".");
    if (!payload || !signature || extra) return null;
    const expected = crypto.createHmac("sha256", sessionSecret()).update(payload).digest();
    let actual;
    try {
        actual = Buffer.from(signature, "base64url");
    } catch {
        return null;
    }
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
    try {
        const value = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
        if (typeof value.accountId !== "string" || !Number.isFinite(value.expiresAt) || value.expiresAt <= Date.now()) return null;
        return value;
    } catch {
        return null;
    }
}

function secureCookie(request) {
    return process.env.NODE_ENV === "production" || request.headers["x-forwarded-proto"] === "https" ? "; Secure" : "";
}

function setSession(request, response, account) {
    const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
    const token = signSession(account.id, expiresAt, account.sessionVersion || 0);
    response.setHeader("Set-Cookie",
        `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_SECONDS}${secureCookie(request)}`);
}

function clearSession(request, response) {
    response.setHeader("Set-Cookie",
        `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secureCookie(request)}`);
}

function allowedOrigins(request) {
    const configured = (process.env.PUBLIC_ORIGINS || process.env.PUBLIC_ORIGIN || "")
        .split(",").map((origin) => origin.trim()).filter(Boolean);
    const host = request.headers.host;
    return new Set([
        ...configured,
        ...(host ? [`https://${host}`, `http://${host}`] : [])
    ]);
}

function checkOrigin(request, response) {
    const origin = request.headers.origin;
    if (!origin || !allowedOrigins(request).has(origin)) {
        sendError(response, 403, "Kërkesa u refuzua.");
        return false;
    }
    return true;
}

function readJson(request) {
    if (request.body !== undefined) {
        const body = typeof request.body === "string" ? request.body : request.body;
        if (Buffer.byteLength(typeof body === "string" ? body : JSON.stringify(body)) > MAX_BODY_BYTES) {
            return Promise.reject(appError(413, "Kërkesa është shumë e madhe."));
        }
        try {
            const value = typeof body === "string" ? JSON.parse(body || "{}") : body;
            if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
            return Promise.resolve(value);
        } catch {
            return Promise.reject(appError(400, "Të dhënat e dërguara nuk janë JSON i vlefshëm."));
        }
    }
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
            if (tooLarge) return reject(appError(413, "Kërkesa është shumë e madhe."));
            try {
                const value = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
                if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
                resolve(value);
            } catch {
                reject(appError(400, "Të dhënat e dërguara nuk janë JSON i vlefshëm."));
            }
        });
        request.on("error", reject);
    });
}

function normalizePhone(value) {
    return String(value || "").replace(/\D/g, "");
}

async function hashPassword(password, salt) {
    return (await pbkdf2(password, salt, PASSWORD_ITERATIONS, 32, "sha256")).toString("hex");
}

async function verifyPassword(password, account) {
    const actual = Buffer.from(await hashPassword(password, account.passwordSalt), "hex");
    const expected = Buffer.from(account.passwordHash, "hex");
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function text(value, field, maxLength, required = true) {
    if (typeof value !== "string") throw appError(400, `${field} nuk është i vlefshëm.`);
    const trimmed = value.trim();
    if (required && !trimmed) throw appError(400, `${field} është i detyrueshëm.`);
    if (trimmed.length > maxLength) throw appError(400, `${field} është shumë i gjatë.`);
    return trimmed;
}

function image(value, field) {
    if (value === undefined || value === null || value === "") return "";
    if (typeof value !== "string") throw appError(400, `${field} nuk është i vlefshëm.`);
    const match = /^data:image\/(png|jpeg|webp|gif);base64,([A-Za-z0-9+/=]+)$/.exec(value);
    if (!match || Buffer.from(match[2], "base64").length > MAX_IMAGE_BYTES) {
        throw appError(400, `${field} duhet të jetë PNG, JPEG, WEBP ose GIF dhe maksimumi 500 KB.`);
    }
    return value;
}

function coordinate(value, min, max, field) {
    if (value === null || value === undefined || value === "") return null;
    const number = Number(value);
    if (!Number.isFinite(number) || number < min || number > max) {
        throw appError(400, `${field} nuk është koordinatë e vlefshme.`);
    }
    return number;
}

function validateCompany(body) {
    const phone = text(body.phone, "Numri i kontaktit", 30);
    const normalizedPhone = normalizePhone(phone);
    if (normalizedPhone.length < 6 || normalizedPhone.length > 15) {
        throw appError(400, "Numri i kontaktit duhet të ketë 6 deri në 15 shifra.");
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
        throw appError(400, "Vitet e prodhimit nuk janë të vlefshme.");
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

function accountByPhone(db, phone) {
    return db.collection("accounts").where("phone", "==", phone).limit(2).get();
}

async function accountById(db, id) {
    const snapshot = await db.collection("accounts").doc(id).get();
    return snapshot.exists ? { id: snapshot.id, ...snapshot.data() } : null;
}

async function companyForAccount(db, account) {
    if (account.role !== "company" || !account.companyId) return null;
    const snapshot = await db.collection("companies").doc(account.companyId).get();
    return snapshot.exists ? { id: snapshot.id, ...snapshot.data() } : null;
}

async function partsForCompany(db, companyId) {
    const snapshot = await db.collection("parts").where("companyId", "==", companyId).get();
    return snapshot.docs.map((doc) => publicPart(doc.id, doc.data()))
        .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
}

function publicPart(id, part) {
    return {
        id,
        make: part.make,
        model: part.model,
        engine: part.engine || "",
        yearFrom: part.yearFrom,
        yearTo: part.yearTo,
        name: part.name,
        description: part.description || "",
        photo: part.photo || ""
    };
}

async function toPublicCompany(db, company) {
    return {
        id: company.id,
        name: company.name,
        owner: company.owner,
        phone: company.phone,
        phone2: company.phone2 || "",
        location: company.location,
        locationLat: company.locationLat ?? null,
        locationLng: company.locationLng ?? null,
        logo: company.logo || "",
        parts: await partsForCompany(db, company.id)
    };
}

async function adminList(db) {
    const [companiesSnapshot, accountsSnapshot, partsSnapshot] = await Promise.all([
        db.collection("companies").get(),
        db.collection("accounts").where("role", "==", "company").get(),
        db.collection("parts").get()
    ]);
    const accounts = new Map(accountsSnapshot.docs.map((doc) => [doc.id, doc.data()]));
    const parts = new Map();
    for (const doc of partsSnapshot.docs) {
        const value = { id: doc.id, ...doc.data() };
        if (!parts.has(value.companyId)) parts.set(value.companyId, []);
        parts.get(value.companyId).push(publicPart(doc.id, value));
    }
    return companiesSnapshot.docs.map((doc) => {
        const company = { id: doc.id, ...doc.data() };
        const account = accounts.get(company.accountId);
        const companyParts = (parts.get(company.id) || [])
            .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
        return {
            ...company,
            locationLat: company.locationLat ?? null,
            locationLng: company.locationLng ?? null,
            phone2: company.phone2 || "",
            logo: company.logo || "",
            parts: companyParts,
            accountId: company.accountId,
            loginPhone: account ? account.phone : "",
            partCount: companyParts.length
        };
    }).sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
}

async function requireSession(request, response, role) {
    const token = parseCookies(request)[SESSION_COOKIE];
    let payload;
    try {
        payload = verifySession(token);
    } catch (error) {
        if (error.status) throw error;
        payload = null;
    }
    const account = payload ? await accountById(getDb(), payload.accountId) : null;
    if (!account || (payload.sessionVersion || 0) !== (account.sessionVersion || 0)) {
        sendError(response, 401, "Duhet të hysh në llogari.");
        return null;
    }
    if (role && account.role !== role) {
        sendError(response, 403, "Nuk ke leje për këtë veprim.");
        return null;
    }
    return { account };
}

function clientAddress(request) {
    const forwarded = request.headers["x-forwarded-for"];
    if (typeof forwarded === "string" && forwarded) return forwarded.split(",")[0].trim();
    return request.socket && request.socket.remoteAddress || "unknown";
}

function checkLoginRate(request, phone) {
    const key = `${clientAddress(request)}:${phone}`;
    const record = loginAttempts.get(key);
    if (!record || record.resetAt <= Date.now()) {
        loginAttempts.set(key, { count: 1, resetAt: Date.now() + 15 * 60 * 1000 });
        return true;
    }
    if (record.count >= 10) return false;
    record.count += 1;
    return true;
}

async function seedAdmin(db) {
    const configuredPhone = normalizePhone(process.env.ADMIN_PHONE);
    const password = process.env.ADMIN_PASSWORD;
    if (!configuredPhone && !password) return;
    if (!configuredPhone || !password || configuredPhone.length < 6 || password.length < 12) {
        throw appError(503, "ADMIN_PHONE dhe ADMIN_PASSWORD kërkohen bashkë; fjalëkalimi admin duhet të ketë të paktën 12 karaktere.");
    }
    const existing = await accountByPhone(db, configuredPhone);
    if (!existing.empty) {
        if (existing.docs[0].data().role !== "admin") {
            throw appError(503, "Numri i konfiguruar për admin është tashmë llogari kompanie; përdor një numër tjetër.");
        }
        return;
    }
    const salt = crypto.randomBytes(16).toString("hex");
    const accountId = crypto.randomUUID();
    await db.collection("accounts").doc(accountId).create({
        phone: configuredPhone,
        passwordSalt: salt,
        passwordHash: await hashPassword(password, salt),
        role: "admin",
        companyId: null,
        sessionVersion: 0
    });
}

function ensureAdmin(db) {
    if (!adminSeedPromise) {
        adminSeedPromise = seedAdmin(db).catch((error) => {
            adminSeedPromise = null;
            throw error;
        });
    }
    return adminSeedPromise;
}

async function deleteQuery(db, query) {
    while (true) {
        const snapshot = await query.limit(400).get();
        if (snapshot.empty) return;
        const batch = db.batch();
        for (const doc of snapshot.docs) batch.delete(doc.ref);
        await batch.commit();
    }
}

async function handleApi(request, response, pathname) {
    const method = request.method;
    const db = getDb();

    if (["POST", "PUT", "DELETE"].includes(method) && !checkOrigin(request, response)) return;
    if (method === "GET" && pathname === "/api/health") {
        sendJson(response, 200, { status: "ok" });
        return;
    }

    if (method === "GET" && pathname === "/api/public") {
        const snapshot = await db.collection("companies").get();
        const companies = await Promise.all(snapshot.docs.map((doc) => toPublicCompany(db, { id: doc.id, ...doc.data() })));
        companies.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
        sendJson(response, 200, { companies });
        return;
    }

    if (method === "POST" && pathname === "/api/register") {
        const body = await readJson(request);
        const phone = normalizePhone(body.phone);
        if (typeof body.password !== "string" || body.password.length > 128) {
            throw appError(400, "Fjalëkalimi nuk është i vlefshëm.");
        }
        if (phone.length < 6 || phone.length > 15) {
            throw appError(400, "Numri i kontaktit duhet të ketë 6 deri në 15 shifra.");
        }
        if (body.password.length < 8) throw appError(400, "Fjalëkalimi duhet të ketë të paktën 8 karaktere.");
        const details = validateCompany(body);
        const existing = await accountByPhone(db, phone);
        if (!existing.empty) throw appError(409, "Ky numër ka tashmë llogari.");
        const accountId = crypto.randomUUID();
        const companyId = crypto.randomUUID();
        const salt = crypto.randomBytes(16).toString("hex");
        const accountRef = db.collection("accounts").doc(accountId);
        const companyRef = db.collection("companies").doc(companyId);
        try {
            await db.runTransaction(async (transaction) => {
                const duplicate = await transaction.get(db.collection("accounts").where("phone", "==", phone).limit(1));
                if (!duplicate.empty) throw appError(409, "Ky numër ka tashmë llogari.");
                transaction.create(accountRef, {
                    phone,
                    passwordSalt: salt,
                    passwordHash: await hashPassword(body.password, salt),
                    role: "company",
                    companyId,
                    sessionVersion: 0
                });
                transaction.create(companyRef, {
                    accountId,
                    name: details.name,
                    owner: details.owner,
                    phone: details.phone,
                    phone2: details.phone2,
                    location: details.location,
                    locationLat: details.locationLat,
                    locationLng: details.locationLng,
                    logo: details.logo
                });
            });
        } catch (error) {
            if (error.code === 6 || error.code === "already-exists") throw appError(409, "Ky numër ka tashmë llogari.");
            throw error;
        }
        setSession(request, response, { id: accountId, sessionVersion: 0 });
        sendJson(response, 201, { company: await toPublicCompany(db, { id: companyId, ...details }) });
        return;
    }

    if (method === "POST" && pathname === "/api/login") {
        const body = await readJson(request);
        const phone = normalizePhone(body.phone);
        if (!checkLoginRate(request, phone)) {
            sendError(response, 429, "Shumë tentativa hyrjeje. Provo përsëri pas 15 minutash.");
            return;
        }
        const matches = await accountByPhone(db, phone);
        const account = matches.empty ? null : { id: matches.docs[0].id, ...matches.docs[0].data() };
        const password = typeof body.password === "string" ? body.password : "";
        if (!account || !await verifyPassword(password, account)) {
            sendError(response, 401, "Numri ose fjalëkalimi nuk është i saktë.");
            return;
        }
        setSession(request, response, account);
        if (account.role === "admin") {
            sendJson(response, 200, { role: "admin" });
            return;
        }
        const company = await companyForAccount(db, account);
        if (!company) {
            clearSession(request, response);
            sendError(response, 500, "Llogaria nuk ka kompani të lidhur. Kontakto administratorin.");
            return;
        }
        sendJson(response, 200, { role: "company", company: await toPublicCompany(db, company) });
        return;
    }

    if (method === "POST" && pathname === "/api/logout") {
        clearSession(request, response);
        sendJson(response, 200, { ok: true });
        return;
    }

    if (method === "GET" && pathname === "/api/me") {
        const token = parseCookies(request)[SESSION_COOKIE];
        let payload;
        try {
            payload = verifySession(token);
        } catch (error) {
            if (error.status) throw error;
            payload = null;
        }
        const account = payload ? await accountById(db, payload.accountId) : null;
        sendJson(response, 200, account && (payload.sessionVersion || 0) === (account.sessionVersion || 0)
            ? { authenticated: true, role: account.role }
            : { authenticated: false });
        return;
    }

    if (method === "GET" && pathname === "/api/me/company") {
        const session = await requireSession(request, response, "company");
        if (!session) return;
        const company = await companyForAccount(db, session.account);
        if (!company) throw appError(404, "Kompania nuk u gjet.");
        sendJson(response, 200, { company: await toPublicCompany(db, company) });
        return;
    }

    if (method === "PUT" && pathname === "/api/me/company") {
        const session = await requireSession(request, response, "company");
        if (!session) return;
        const details = validateCompany(await readJson(request));
        const accountRef = db.collection("accounts").doc(session.account.id);
        const companyRef = db.collection("companies").doc(session.account.companyId);
        await db.runTransaction(async (transaction) => {
            const duplicate = await transaction.get(db.collection("accounts").where("phone", "==", details.normalizedPhone).limit(2));
            if (duplicate.docs.some((doc) => doc.id !== session.account.id)) {
                throw appError(409, "Ky numër telefoni përdoret nga një llogari tjetër.");
            }
            const companySnapshot = await transaction.get(companyRef);
            if (!companySnapshot.exists) throw appError(404, "Kompania nuk u gjet.");
            transaction.update(companyRef, {
                name: details.name,
                owner: details.owner,
                phone: details.phone,
                phone2: details.phone2,
                location: details.location,
                locationLat: details.locationLat,
                locationLng: details.locationLng,
                logo: details.logo
            });
            transaction.update(accountRef, { phone: details.normalizedPhone });
        });
        const updated = await companyRef.get();
        sendJson(response, 200, { company: await toPublicCompany(db, { id: updated.id, ...updated.data() }) });
        return;
    }

    if (method === "POST" && pathname === "/api/me/parts") {
        const session = await requireSession(request, response, "company");
        if (!session) return;
        const details = validatePart(await readJson(request));
        const id = crypto.randomUUID();
        await db.collection("parts").doc(id).create({ companyId: session.account.companyId, ...details });
        sendJson(response, 201, { part: { id, ...details } });
        return;
    }

    const ownerPart = pathname.match(/^\/api\/me\/parts\/([0-9a-f-]+)$/i);
    if (ownerPart && (method === "PUT" || method === "DELETE")) {
        const session = await requireSession(request, response, "company");
        if (!session) return;
        const partRef = db.collection("parts").doc(ownerPart[1]);
        const partSnapshot = await partRef.get();
        if (!partSnapshot.exists || partSnapshot.data().companyId !== session.account.companyId) {
            throw appError(404, "Pjesa nuk u gjet.");
        }
        if (method === "DELETE") {
            await partRef.delete();
            sendJson(response, 200, { ok: true });
            return;
        }
        const details = validatePart(await readJson(request));
        await partRef.update(details);
        sendJson(response, 200, { ok: true });
        return;
    }

    if (method === "DELETE" && pathname === "/api/me/account") {
        const session = await requireSession(request, response, "company");
        if (!session) return;
        const company = await companyForAccount(db, session.account);
        if (!company) throw appError(404, "Kompania nuk u gjet.");
        await deleteQuery(db, db.collection("parts").where("companyId", "==", company.id));
        await db.collection("companies").doc(company.id).delete();
        await db.collection("accounts").doc(session.account.id).delete();
        clearSession(request, response);
        sendJson(response, 200, { ok: true });
        return;
    }

    if (pathname === "/api/admin/companies" && method === "GET") {
        const session = await requireSession(request, response, "admin");
        if (!session) return;
        sendJson(response, 200, { companies: await adminList(db) });
        return;
    }

    if (pathname === "/api/admin/companies" && method === "DELETE") {
        const session = await requireSession(request, response, "admin");
        if (!session) return;
        await deleteQuery(db, db.collection("parts"));
        await deleteQuery(db, db.collection("companies"));
        await deleteQuery(db, db.collection("accounts").where("role", "==", "company"));
        sendJson(response, 200, { ok: true });
        return;
    }

    const adminCompanyPassword = pathname.match(/^\/api\/admin\/companies\/([0-9a-f-]+)\/password$/i);
    if (adminCompanyPassword && method === "PUT") {
        const session = await requireSession(request, response, "admin");
        if (!session) return;
        const companyRef = db.collection("companies").doc(adminCompanyPassword[1]);
        const company = await companyRef.get();
        if (!company.exists) throw appError(404, "Kompania nuk u gjet.");
        const accountId = company.data().accountId;
        const accountRef = db.collection("accounts").doc(accountId);
        const account = await accountRef.get();
        if (!account.exists) throw appError(404, "Llogaria e kompanisë nuk u gjet.");
        const body = await readJson(request);
        if (typeof body.password !== "string" || body.password.length < 8 || body.password.length > 128) {
            throw appError(400, "Fjalëkalimi duhet të ketë 8 deri në 128 karaktere.");
        }
        const salt = crypto.randomBytes(16).toString("hex");
        await accountRef.update({
            passwordSalt: salt,
            passwordHash: await hashPassword(body.password, salt),
            sessionVersion: (account.data().sessionVersion || 0) + 1
        });
        sendJson(response, 200, { ok: true });
        return;
    }

    const adminCompany = pathname.match(/^\/api\/admin\/companies\/([0-9a-f-]+)$/i);
    if (adminCompany && method === "PUT") {
        const session = await requireSession(request, response, "admin");
        if (!session) return;
        const companyRef = db.collection("companies").doc(adminCompany[1]);
        const companySnapshot = await companyRef.get();
        if (!companySnapshot.exists) throw appError(404, "Kompania nuk u gjet.");
        const company = { id: companySnapshot.id, ...companySnapshot.data() };
        const details = validateCompany(await readJson(request));
        const accountRef = db.collection("accounts").doc(company.accountId);
        await db.runTransaction(async (transaction) => {
            const duplicate = await transaction.get(db.collection("accounts").where("phone", "==", details.normalizedPhone).limit(2));
            if (duplicate.docs.some((doc) => doc.id !== company.accountId)) {
                throw appError(409, "Ky numër telefoni përdoret nga një llogari tjetër.");
            }
            transaction.update(companyRef, {
                name: details.name,
                owner: details.owner,
                phone: details.phone,
                phone2: details.phone2,
                location: details.location,
                locationLat: details.locationLat,
                locationLng: details.locationLng,
                logo: details.logo
            });
            transaction.update(accountRef, { phone: details.normalizedPhone });
        });
        sendJson(response, 200, { company: await toPublicCompany(db, { id: company.id, ...details }) });
        return;
    }

    if (adminCompany && method === "DELETE") {
        const session = await requireSession(request, response, "admin");
        if (!session) return;
        const companyRef = db.collection("companies").doc(adminCompany[1]);
        const company = await companyRef.get();
        if (!company.exists) throw appError(404, "Kompania nuk u gjet.");
        await deleteQuery(db, db.collection("parts").where("companyId", "==", company.id));
        await companyRef.delete();
        await db.collection("accounts").doc(company.data().accountId).delete();
        sendJson(response, 200, { ok: true });
        return;
    }

    const adminPart = pathname.match(/^\/api\/admin\/companies\/([0-9a-f-]+)\/parts\/([0-9a-f-]+)$/i);
    if (adminPart && (method === "PUT" || method === "DELETE")) {
        const session = await requireSession(request, response, "admin");
        if (!session) return;
        const [, companyId, partId] = adminPart;
        const partRef = db.collection("parts").doc(partId);
        const part = await partRef.get();
        if (!part.exists || part.data().companyId !== companyId) throw appError(404, "Pjesa nuk u gjet.");
        if (method === "DELETE") {
            await partRef.delete();
            sendJson(response, 200, { ok: true });
            return;
        }
        await partRef.update(validatePart(await readJson(request)));
        sendJson(response, 200, { ok: true });
        return;
    }

    sendError(response, 404, "Adresa API nuk u gjet.");
}

module.exports = async function handler(request, response) {
    try {
        const pathname = requestPath(request);
        if (!pathname.startsWith("/api/")) {
            sendError(response, 404, "Adresa API nuk u gjet.");
            return;
        }
        await ensureAdmin(getDb());
        await handleApi(request, response, pathname);
    } catch (error) {
        console.error("Firebase API request failed:", error);
        if (response.headersSent || response.destroyed) return;
        if (error.code === 6 || error.code === "already-exists") {
            sendError(response, 409, "Numri i kontaktit është përdorur tashmë.");
            return;
        }
        sendError(response, error.status || 500,
            error.status ? error.message : "Gabim i brendshëm i serverit.");
    }
};
