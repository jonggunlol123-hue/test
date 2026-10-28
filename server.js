// server.js
const express = require("express");
const session = require("express-session");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, "data");

fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "heukwol.sqlite"));
db.pragma("journal_mode = WAL");

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 12 * 60 * 60 * 1000
  }
}));

// 데이터베이스 테이블
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'staff'
);

CREATE TABLE IF NOT EXISTS members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  rank TEXT NOT NULL DEFAULT '조직원',
  note TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ranks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  level INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  price INTEGER NOT NULL DEFAULT 0,
  description TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL CHECK(type IN ('수입','지출')),
  description TEXT NOT NULL,
  amount INTEGER NOT NULL CHECK(amount > 0),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS loans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  borrower TEXT NOT NULL,
  amount INTEGER NOT NULL CHECK(amount > 0),
  repaid INTEGER NOT NULL DEFAULT 0,
  description TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT '진행 중',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

// 최초 관리자 계정 생성.
// Render 환경변수 ADMIN_USERNAME, ADMIN_PASSWORD를 설정해야 함.
const adminExists = db.prepare(
  "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
).get();

if (!adminExists) {
  const adminUsername = process.env.ADMIN_USERNAME;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (adminUsername && adminPassword && adminPassword.length >= 8) {
    const salt = crypto.randomBytes(16).toString("hex");

    db.prepare(`
      INSERT INTO users (username, salt, hash, role)
      VALUES (?, ?, ?, 'admin')
    `).run(
      adminUsername,
      salt,
      hashPassword(adminPassword, salt)
    );

    console.log("관리자 계정이 환경변수로 생성되었습니다.");
  } else {
    console.warn(
      "관리자 계정이 없습니다. Render에 ADMIN_USERNAME과 ADMIN_PASSWORD를 설정하세요."
    );
  }
}

function cleanText(value, maxLength = 200) {
  return typeof value === "string"
    ? value.trim().slice(0, maxLength)
    : "";
}

function validAmount(value) {
  const amount = Number(value);
  return Number.isSafeInteger(amount) && amount > 0
    ? amount
    : null;
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "로그인이 필요합니다." });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "로그인이 필요합니다." });
  }

  if (req.session.user.role !== "admin") {
    return res.status(403).json({ error: "관리자 권한이 필요합니다." });
  }

  next();
}

function addLedger(type, description, amount, username) {
  return db.prepare(`
    INSERT INTO ledger (type, description, amount, created_by)
    VALUES (?, ?, ?, ?)
  `).run(type, description, amount, username);
}

// 로그인
app.post("/api/login", (req, res) => {
  const username = cleanText(req.body.username, 32);
  const password = typeof req.body.password === "string"
    ? req.body.password
    : "";

  const user = db.prepare(`
    SELECT id, username, salt, hash, role
    FROM users
    WHERE username = ?
  `).get(username);

  if (!user) {
    return res.status(401).json({
      error: "아이디 또는 비밀번호가 올바르지 않습니다."
    });
  }

  const actualHash = Buffer.from(
    hashPassword(password, user.salt),
    "hex"
  );
  const savedHash = Buffer.from(user.hash, "hex");

  if (
    actualHash.length !== savedHash.length ||
    !crypto.timingSafeEqual(actualHash, savedHash)
  ) {
    return res.status(401).json({
      error: "아이디 또는 비밀번호가 올바르지 않습니다."
    });
  }

  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role
  };

  res.json({ user: req.session.user });
});

// 로그아웃
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

// 현재 로그인 사용자
app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

// 관리자: 조직원 로그인 계정 생성
app.post("/api/staff", requireAdmin, (req, res) => {
  const username = cleanText(req.body.username, 32);
  const password = typeof req.body.password === "string"
    ? req.body.password
    : "";

  if (!/^[A-Za-z0-9_-]{3,32}$/.test(username)) {
    return res.status(400).json({
      error: "아이디는 영문, 숫자, _ 또는 -로 3~32자여야 합니다."
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      error: "비밀번호는 8자 이상이어야 합니다."
    });
  }

  const salt = crypto.randomBytes(16).toString("hex");

  try {
    db.prepare(`
      INSERT INTO users (username, salt, hash, role)
      VALUES (?, ?, ?, 'staff')
    `).run(username, salt, hashPassword(password, salt));

    res.status(201).json({ ok: true, username });
  } catch {
    res.status(409).json({ error: "이미 사용 중인 아이디입니다." });
  }
});

// 대시보드 통계
app.get("/api/dashboard", requireLogin, (req, res) => {
  const members = db.prepare(
    "SELECT COUNT(*) AS count FROM members"
  ).get().count;

  const totals = db.prepare(`
    SELECT
      COALESCE(SUM(CASE WHEN type = '수입' THEN amount ELSE 0 END), 0) AS income,
      COALESCE(SUM(CASE WHEN type = '지출' THEN amount ELSE 0 END), 0) AS expense
    FROM ledger
  `).get();

  res.json({
    members,
    income: totals.income,
    expense: totals.expense,
    net: totals.income - totals.expense
  });
});

// 장부 조회
app.get("/api/ledger", requireLogin, (req, res) => {
  const ledger = db.prepare(`
    SELECT * FROM ledger
    ORDER BY id DESC
    LIMIT 500
  `).all();

  res.json({ ledger });
});

// 전체 거래내역 조회
app.get("/api/transactions", requireLogin, (req, res) => {
  const transactions = db.prepare(`
    SELECT * FROM ledger
    ORDER BY id DESC
    LIMIT 2000
  `).all();

  res.json({ transactions });
});

// 장부 작성
app.post("/api/ledger", requireLogin, (req, res) => {
  const type = req.body.type;
  const description = cleanText(req.body.description);
  const amount = validAmount(req.body.amount);

  if (!["수입", "지출"].includes(type) || !description || !amount) {
    return res.status(400).json({
      error: "구분, 항목명, 1원 이상의 금액을 확인하세요."
    });
  }

  const result = addLedger(
    type,
    description,
    amount,
    req.session.user.username
  );

  res.status(201).json({ id: result.lastInsertRowid });
});

// 조직원 명단
app.get("/api/members", requireLogin, (req, res) => {
  const members = db.prepare(
    "SELECT * FROM members ORDER BY id DESC"
  ).all();

  res.json({ members });
});

app.post("/api/members", requireAdmin, (req, res) => {
  const name = cleanText(req.body.name, 80);
  const rank = cleanText(req.body.rank, 80) || "조직원";
  const note = cleanText(req.body.note, 300);

  if (!name) {
    return res.status(400).json({ error: "IC 성명을 입력하세요." });
  }

  const result = db.prepare(`
    INSERT INTO members (name, rank, note)
    VALUES (?, ?, ?)
  `).run(name, rank, note);

  res.status(201).json({ id: result.lastInsertRowid });
});

app.delete("/api/members/:id", requireAdmin, (req, res) => {
  db.prepare("DELETE FROM members WHERE id = ?")
    .run(Number(req.params.id));

  res.json({ ok: true });
});

// 직급표
app.get("/api/ranks", requireLogin, (req, res) => {
  const ranks = db.prepare(
    "SELECT * FROM ranks ORDER BY level ASC, id ASC"
  ).all();

  res.json({ ranks });
});

app.post("/api/ranks", requireAdmin, (req, res) => {
  const name = cleanText(req.body.name, 80);
  const level = Number(req.body.level ?? 0);

  if (!name || !Number.isInteger(level) || level < 0) {
    return res.status(400).json({ error: "직급명과 순서를 확인하세요." });
  }

  try {
    const result = db.prepare(`
      INSERT INTO ranks (name, level)
      VALUES (?, ?)
    `).run(name, level);

    res.status(201).json({ id: result.lastInsertRowid });
  } catch {
    res.status(409).json({ error: "이미 등록된 직급입니다." });
  }
});

app.delete("/api/ranks/:id", requireAdmin, (req, res) => {
  db.prepare("DELETE FROM ranks WHERE id = ?")
    .run(Number(req.params.id));

  res.json({ ok: true });
});

// 품목 관리
app.get("/api/items", requireLogin, (req, res) => {
  const items = db.prepare(
    "SELECT * FROM items ORDER BY name"
  ).all();

  res.json({ items });
});

app.post("/api/items", requireAdmin, (req, res) => {
  const name = cleanText(req.body.name, 100);
  const price = Number(req.body.price ?? 0);
  const description = cleanText(req.body.description, 300);

  if (!name || !Number.isSafeInteger(price) || price < 0) {
    return res.status(400).json({ error: "품목명과 가격을 확인하세요." });
  }

  try {
    const result = db.prepare(`
      INSERT INTO items (name, price, description)
      VALUES (?, ?, ?)
    `).run(name, price, description);

    res.status(201).json({ id: result.lastInsertRowid });
  } catch {
    res.status(409).json({ error: "이미 등록된 품목입니다." });
  }
});

app.delete("/api/items/:id", requireAdmin, (req, res) => {
  db.prepare("DELETE FROM items WHERE id = ?")
    .run(Number(req.params.id));

  res.json({ ok: true });
});

// 대출 내역
app.get("/api/loans", requireLogin, (req, res) => {
  const loans = db.prepare(
    "SELECT * FROM loans ORDER BY id DESC"
  ).all();

  res.json({ loans });
});

// 대출 지급: 대출 기록 + 장부 지출을 한 번에 저장
app.post("/api/loans", requireAdmin, (req, res) => {
  const borrower = cleanText(req.body.borrower, 100);
  const amount = validAmount(req.body.amount);
  const description = cleanText(req.body.description, 200);

  if (!borrower || !amount) {
    return res.status(400).json({
      error: "대출자와 1원 이상의 금액을 입력하세요."
    });
  }

  const transaction = db.transaction(() => {
    const loan = db.prepare(`
      INSERT INTO loans (borrower, amount, description, created_by)
      VALUES (?, ?, ?, ?)
    `).run(
      borrower,
      amount,
      description,
      req.session.user.username
    );

    addLedger(
      "지출",
      `대출 지급 - ${borrower}`,
      amount,
      req.session.user.username
    );

    return loan.lastInsertRowid;
  });

  res.status(201).json({ id: transaction() });
});

// 대출 상환: 상환액 업데이트 + 장부 수입을 한 번에 저장
app.post("/api/loans/:id/repay", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const amount = validAmount(req.body.amount);

  const loan = db.prepare(
    "SELECT * FROM loans WHERE id = ?"
  ).get(id);

  if (!loan) {
    return res.status(404).json({ error: "대출 내역을 찾을 수 없습니다." });
  }

  if (!amount || amount > loan.amount - loan.repaid) {
    return res.status(400).json({
      error: "상환 금액이 남은 대출 잔액보다 큽니다."
    });
  }

  const transaction = db.transaction(() => {
    const repaid = loan.repaid + amount;

    db.prepare(`
      UPDATE loans
      SET repaid = ?, status = ?
      WHERE id = ?
    `).run(
      repaid,
      repaid === loan.amount ? "상환 완료" : "진행 중",
      id
    );

    addLedger(
      "수입",
      `대출 상환 - ${loan.borrower}`,
      amount,
      req.session.user.username
    );
  });

  transaction();
  res.json({ ok: true });
});

// 상태 확인
app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

// public/index.html 제공
app.use(express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "서버 내부 오류가 발생했습니다." });
});

app.listen(PORT, () => {
  console.log(`흑월 포털 실행 중: ${PORT}`);
});
