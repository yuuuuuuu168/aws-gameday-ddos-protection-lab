-- GameDay Vulnerable Application Database Schema
-- 意図的にセキュリティ脆弱性を含むデータベース設計

-- ユーザーテーブル（意図的な脆弱性を含む）
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,  -- 平文パスワード保存（脆弱性）
    email TEXT,
    role TEXT DEFAULT 'user',
    api_key TEXT,  -- APIキーを平文で保存（脆弱性）
    credit_card TEXT,  -- 機密情報を平文で保存（脆弱性）
    ssn TEXT,  -- 社会保障番号を平文で保存（脆弱性）
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    failed_login_attempts INTEGER DEFAULT 0,  -- アカウントロックアウト機能なし（脆弱性）
    is_active INTEGER DEFAULT 1
);

-- セッションテーブル（脆弱なセッション管理）
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,  -- 長期間有効なセッション（脆弱性）
    ip_address TEXT,  -- IPアドレス検証なし（脆弱性）
    user_agent TEXT,
    is_active INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 投稿テーブル（XSS脆弱性用）
CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,  -- HTMLタグがそのまま保存される（XSS脆弱性）
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_published INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ファイルアップロードテーブル（不適切なファイル管理）
CREATE TABLE IF NOT EXISTS uploaded_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    file_path TEXT NOT NULL,  -- ファイルパスが直接露出（脆弱性）
    file_size INTEGER,
    mime_type TEXT,  -- MIME type検証なし（脆弱性）
    upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_public INTEGER DEFAULT 1,  -- デフォルトで公開（脆弱性）
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 検索ログテーブル（SQLインジェクション脆弱性用）
CREATE TABLE IF NOT EXISTS search_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    search_query TEXT NOT NULL,  -- 検索クエリがそのまま保存される
    results_count INTEGER,
    search_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 管理者アクションログ（権限昇格脆弱性用）
CREATE TABLE IF NOT EXISTS admin_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    target_user_id INTEGER,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (target_user_id) REFERENCES users(id)
);

-- 設定テーブル（設定改ざん脆弱性用）
CREATE TABLE IF NOT EXISTS app_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_key TEXT NOT NULL UNIQUE,
    setting_value TEXT NOT NULL,
    description TEXT,
    is_public INTEGER DEFAULT 0,  -- 機密設定も含む
    updated_by INTEGER,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

-- インデックス作成（パフォーマンス向上のため）
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id);
CREATE INDEX IF NOT EXISTS idx_uploaded_files_user_id ON uploaded_files(user_id);
CREATE INDEX IF NOT EXISTS idx_search_logs_user_id ON search_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_actions_user_id ON admin_actions(user_id);