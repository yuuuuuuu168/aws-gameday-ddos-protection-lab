const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// 意図的に脆弱なセッション設定
app.use(session({
  secret: 'weak-secret-key', // 弱いシークレットキー
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: false, // HTTPでも動作（本番環境では危険）
    maxAge: 24 * 60 * 60 * 1000 // 24時間（長すぎる）
  }
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// データベース初期化
const db = new sqlite3.Database('./gameday.db');

// 意図的に脆弱なデータベース初期化（パラメータ化クエリ未使用）
db.serialize(() => {
  // ユーザーテーブル作成
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // セッションテーブル作成
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
  )`);

  // 脆弱なサンプルデータ挿入
  db.run(`INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES 
    (1, 'admin', 'password123', 'admin@gameday.com', 'admin'),
    (2, 'user1', 'qwerty', 'user1@gameday.com', 'user'),
    (3, 'test', 'test', 'test@gameday.com', 'user')`);
});

// ホームページ
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>GameDay Vulnerable App</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .vulnerability { background: #ffebee; padding: 20px; margin: 20px 0; border-left: 4px solid #f44336; }
        form { background: #f5f5f5; padding: 20px; margin: 20px 0; }
        input, textarea { width: 100%; padding: 10px; margin: 5px 0; }
        button { background: #2196F3; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        .nav { background: #333; padding: 10px; }
        .nav a { color: white; text-decoration: none; margin: 0 10px; }
      </style>
    </head>
    <body>
      <div class="nav">
        <a href="/">Home</a>
        <a href="/login">Login</a>
        <a href="/search">Search</a>
        <a href="/upload">Upload</a>
        <a href="/profile">Profile</a>
      </div>
      <div class="container">
        <h1>🎯 AWS GameDay - Vulnerable Web Application</h1>
        <div class="vulnerability">
          <h3>⚠️ Warning: This is an intentionally vulnerable application!</h3>
          <p>This application contains multiple security vulnerabilities for educational purposes:</p>
          <ul>
            <li>SQL Injection vulnerabilities</li>
            <li>Cross-Site Scripting (XSS) vulnerabilities</li>
            <li>Insecure file upload functionality</li>
            <li>Weak authentication mechanisms</li>
          </ul>
        </div>
        
        <h2>Available Features:</h2>
        <ul>
          <li><a href="/login">Login System</a> - Test SQL injection attacks</li>
          <li><a href="/search">Search Function</a> - Test XSS attacks</li>
          <li><a href="/upload">File Upload</a> - Test file upload vulnerabilities</li>
          <li><a href="/profile">User Profile</a> - Test authentication bypass</li>
        </ul>
      </div>
    </body>
    </html>
  `);
});
// 意図的
なSQLインジェクション脆弱性 - ログイン機能
app.get('/login', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Login - GameDay Vulnerable App</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 400px; margin: 0 auto; }
        form { background: #f5f5f5; padding: 20px; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        button { background: #2196F3; color: white; padding: 10px 20px; border: none; cursor: pointer; width: 100%; }
        .vulnerability-hint { background: #fff3cd; padding: 10px; margin: 10px 0; border: 1px solid #ffeaa7; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>Login</h2>
        <div class="vulnerability-hint">
          <strong>Hint for SQL Injection:</strong> Try username: <code>admin' OR '1'='1</code>
        </div>
        <form method="POST" action="/login">
          <input type="text" name="username" placeholder="Username" required>
          <input type="password" name="password" placeholder="Password" required>
          <button type="submit">Login</button>
        </form>
        <p><a href="/">← Back to Home</a></p>
      </div>
    </body>
    </html>
  `);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // 意図的なSQLインジェクション脆弱性 - パラメータ化クエリ未使用
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  console.log('Executing vulnerable query:', query); // デバッグ情報の露出
  
  db.get(query, (err, row) => {
    if (err) {
      // 意図的に詳細なエラー情報を露出
      res.status(500).send(`
        <h2>Database Error</h2>
        <p>Error: ${err.message}</p>
        <p>Query: ${query}</p>
        <a href="/login">Try Again</a>
      `);
      return;
    }
    
    if (row) {
      req.session.userId = row.id;
      req.session.username = row.username;
      req.session.role = row.role;
      
      res.send(`
        <h2>Login Successful!</h2>
        <p>Welcome, ${row.username}!</p>
        <p>Role: ${row.role}</p>
        <p>User ID: ${row.id}</p>
        <a href="/profile">View Profile</a> | <a href="/">Home</a>
      `);
    } else {
      res.send(`
        <h2>Login Failed</h2>
        <p>Invalid username or password</p>
        <p>Query executed: ${query}</p>
        <a href="/login">Try Again</a>
      `);
    }
  });
});

// XSS脆弱性 - 検索機能
app.get('/search', (req, res) => {
  const query = req.query.q || '';
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Search - GameDay Vulnerable App</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        form { background: #f5f5f5; padding: 20px; }
        input { width: 80%; padding: 10px; margin: 5px 0; }
        button { background: #2196F3; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        .vulnerability-hint { background: #fff3cd; padding: 10px; margin: 10px 0; border: 1px solid #ffeaa7; }
        .results { background: #e8f5e8; padding: 20px; margin: 20px 0; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>Search</h2>
        <div class="vulnerability-hint">
          <strong>Hint for XSS:</strong> Try searching for: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
        </div>
        <form method="GET" action="/search">
          <input type="text" name="q" placeholder="Search..." value="${query}">
          <button type="submit">Search</button>
        </form>
        
        ${query ? `
          <div class="results">
            <h3>Search Results for: ${query}</h3>
            <p>Your search query was: ${query}</p>
            <p>No results found, but your input is displayed above without sanitization!</p>
          </div>
        ` : ''}
        
        <p><a href="/">← Back to Home</a></p>
      </div>
    </body>
    </html>
  `);
});

// ファイルアップロード脆弱性
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = './uploads';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    // 意図的に危険 - ファイル名の検証なし
    cb(null, file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  // 意図的に制限なし - 危険なファイルタイプも許可
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB
  }
});

app.get('/upload', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>File Upload - GameDay Vulnerable App</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        form { background: #f5f5f5; padding: 20px; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        button { background: #2196F3; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        .vulnerability-hint { background: #fff3cd; padding: 10px; margin: 10px 0; border: 1px solid #ffeaa7; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>File Upload</h2>
        <div class="vulnerability-hint">
          <strong>Hint for File Upload Vulnerability:</strong> Try uploading files with extensions like .php, .jsp, .exe
        </div>
        <form method="POST" action="/upload" enctype="multipart/form-data">
          <input type="file" name="file" required>
          <button type="submit">Upload File</button>
        </form>
        <p><a href="/">← Back to Home</a></p>
      </div>
    </body>
    </html>
  `);
});

app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded');
  }
  
  // 意図的に危険 - アップロードされたファイル情報を全て露出
  res.send(`
    <h2>File Upload Successful!</h2>
    <p><strong>Filename:</strong> ${req.file.originalname}</p>
    <p><strong>Size:</strong> ${req.file.size} bytes</p>
    <p><strong>MIME Type:</strong> ${req.file.mimetype}</p>
    <p><strong>Saved as:</strong> ${req.file.filename}</p>
    <p><strong>Path:</strong> ${req.file.path}</p>
    <div style="background: #ffebee; padding: 10px; margin: 10px 0; border: 1px solid #f44336;">
      <strong>Security Issue:</strong> This application accepts any file type without validation!
    </div>
    <a href="/upload">Upload Another File</a> | <a href="/">Home</a>
  `);
});// 弱い認
証システム - プロファイル機能
app.get('/profile', (req, res) => {
  // 意図的に弱い認証チェック
  if (!req.session.userId) {
    return res.send(`
      <h2>Access Denied</h2>
      <p>Please login first</p>
      <a href="/login">Login</a>
    `);
  }
  
  // 意図的なSQLインジェクション脆弱性 - ユーザーID直接使用
  const userId = req.query.id || req.session.userId;
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  console.log('Profile query:', query);
  
  db.get(query, (err, user) => {
    if (err) {
      return res.status(500).send(`
        <h2>Database Error</h2>
        <p>Error: ${err.message}</p>
        <p>Query: ${query}</p>
      `);
    }
    
    if (!user) {
      return res.send('<h2>User not found</h2>');
    }
    
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Profile - GameDay Vulnerable App</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
          .container { max-width: 600px; margin: 0 auto; }
          .profile { background: #f5f5f5; padding: 20px; margin: 20px 0; }
          .vulnerability-hint { background: #fff3cd; padding: 10px; margin: 10px 0; border: 1px solid #ffeaa7; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>User Profile</h2>
          <div class="vulnerability-hint">
            <strong>Hint for Authentication Bypass:</strong> Try changing the URL parameter: <code>?id=1</code> to access admin profile
          </div>
          <div class="profile">
            <p><strong>ID:</strong> ${user.id}</p>
            <p><strong>Username:</strong> ${user.username}</p>
            <p><strong>Email:</strong> ${user.email}</p>
            <p><strong>Role:</strong> ${user.role}</p>
            <p><strong>Password:</strong> ${user.password}</p>
            <p><strong>Created:</strong> ${user.created_at}</p>
          </div>
          
          ${user.role === 'admin' ? `
            <div style="background: #ffebee; padding: 20px; border: 1px solid #f44336;">
              <h3>🔑 Admin Panel Access</h3>
              <p>Congratulations! You've accessed the admin profile.</p>
              <p>This demonstrates an authentication bypass vulnerability.</p>
            </div>
          ` : ''}
          
          <a href="/logout">Logout</a> | <a href="/">Home</a>
        </div>
      </body>
      </html>
    `);
  });
});

// ログアウト機能
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Could not log out');
    }
    res.send(`
      <h2>Logged Out</h2>
      <p>You have been successfully logged out</p>
      <a href="/">Home</a> | <a href="/login">Login Again</a>
    `);
  });
});

// 意図的に詳細なエラー情報を露出するエラーハンドラー
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send(`
    <h2>Application Error</h2>
    <p><strong>Error:</strong> ${err.message}</p>
    <p><strong>Stack Trace:</strong></p>
    <pre>${err.stack}</pre>
    <p><strong>Request URL:</strong> ${req.url}</p>
    <p><strong>Request Method:</strong> ${req.method}</p>
    <p><strong>Request Headers:</strong></p>
    <pre>${JSON.stringify(req.headers, null, 2)}</pre>
    <p><strong>Request Body:</strong></p>
    <pre>${JSON.stringify(req.body, null, 2)}</pre>
  `);
});

// サーバー起動
app.listen(PORT, () => {
  console.log(`🎯 GameDay Vulnerable App running on port ${PORT}`);
  console.log(`⚠️  WARNING: This application contains intentional security vulnerabilities!`);
  console.log(`📝 Access the application at: http://localhost:${PORT}`);
});

module.exports = app;