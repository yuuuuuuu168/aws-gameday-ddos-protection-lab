-- GameDay Vulnerable Application Sample Data
-- 意図的に脆弱なサンプルデータ

-- 脆弱なユーザーデータの挿入
INSERT OR IGNORE INTO users (id, username, password, email, role, api_key, credit_card, ssn, last_login, failed_login_attempts) VALUES 
(1, 'admin', 'password123', 'admin@gameday.com', 'admin', 'api_key_12345_admin', '4111-1111-1111-1111', '123-45-6789', datetime('now', '-1 hour'), 0),
(2, 'user1', 'qwerty', 'user1@gameday.com', 'user', 'api_key_67890_user1', '4222-2222-2222-2222', '987-65-4321', datetime('now', '-2 hours'), 0),
(3, 'test', 'test', 'test@gameday.com', 'user', 'api_key_11111_test', '4333-3333-3333-3333', '555-55-5555', datetime('now', '-3 hours'), 0),
(4, 'guest', 'guest123', 'guest@gameday.com', 'guest', 'api_key_22222_guest', '4444-4444-4444-4444', '111-11-1111', datetime('now', '-4 hours'), 0),
(5, 'developer', 'dev123', 'dev@gameday.com', 'developer', 'api_key_33333_dev', '4555-5555-5555-5555', '222-22-2222', datetime('now', '-5 hours'), 0),
(6, 'manager', 'manager456', 'manager@gameday.com', 'manager', 'api_key_44444_mgr', '4666-6666-6666-6666', '333-33-3333', datetime('now', '-6 hours'), 0),
(7, 'support', 'support789', 'support@gameday.com', 'support', 'api_key_55555_sup', '4777-7777-7777-7777', '444-44-4444', datetime('now', '-7 hours'), 0),
(8, 'analyst', 'analyst000', 'analyst@gameday.com', 'analyst', 'api_key_66666_ana', '4888-8888-8888-8888', '666-66-6666', datetime('now', '-8 hours'), 0);

-- 脆弱なセッションデータ（長期間有効）
INSERT OR IGNORE INTO sessions (session_id, user_id, created_at, expires_at, ip_address, user_agent, is_active) VALUES 
('sess_admin_12345', 1, datetime('now', '-1 hour'), datetime('now', '+30 days'), '192.168.1.100', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 1),
('sess_user1_67890', 2, datetime('now', '-2 hours'), datetime('now', '+30 days'), '192.168.1.101', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 1),
('sess_test_11111', 3, datetime('now', '-3 hours'), datetime('now', '+30 days'), '192.168.1.102', 'Mozilla/5.0 (X11; Linux x86_64)', 1);

-- XSS脆弱性を含む投稿データ
INSERT OR IGNORE INTO posts (id, user_id, title, content, created_at, is_published) VALUES 
(1, 1, 'Welcome to GameDay!', '<h2>Welcome to our vulnerable application!</h2><p>This is a <strong>test post</strong> with HTML content.</p>', datetime('now', '-1 day'), 1),
(2, 2, 'XSS Test Post', '<script>alert("XSS Vulnerability!")</script><p>This post contains malicious JavaScript code.</p>', datetime('now', '-2 hours'), 1),
(3, 3, 'Image Upload Test', '<img src="javascript:alert(''XSS'')" onerror="alert(''Image XSS'')">', datetime('now', '-1 hour'), 1),
(4, 1, 'Admin Notice', '<iframe src="javascript:alert(''Admin XSS'')"></iframe><p>Important security notice from admin.</p>', datetime('now', '-30 minutes'), 1);

-- ファイルアップロード履歴（危険なファイルを含む）
INSERT OR IGNORE INTO uploaded_files (id, user_id, original_filename, stored_filename, file_path, file_size, mime_type, upload_date, is_public) VALUES 
(1, 2, 'malicious.php', 'malicious_12345.php', '/opt/gameday-app/uploads/malicious_12345.php', 1024, 'application/x-php', datetime('now', '-2 hours'), 1),
(2, 3, 'backdoor.jsp', 'backdoor_67890.jsp', '/opt/gameday-app/uploads/backdoor_67890.jsp', 2048, 'application/x-jsp', datetime('now', '-1 hour'), 1),
(3, 2, 'virus.exe', 'virus_11111.exe', '/opt/gameday-app/uploads/virus_11111.exe', 4096, 'application/x-executable', datetime('now', '-30 minutes'), 1),
(4, 1, 'shell.sh', 'shell_22222.sh', '/opt/gameday-app/uploads/shell_22222.sh', 512, 'application/x-sh', datetime('now', '-15 minutes'), 1);

-- SQLインジェクション用の検索ログ
INSERT OR IGNORE INTO search_logs (id, user_id, search_query, results_count, search_date, ip_address) VALUES 
(1, 2, 'admin', 1, datetime('now', '-2 hours'), '192.168.1.101'),
(2, 3, "' OR '1'='1", 8, datetime('now', '-1 hour'), '192.168.1.102'),
(3, NULL, "'; DROP TABLE users; --", 0, datetime('now', '-30 minutes'), '192.168.1.103'),
(4, 2, "admin' UNION SELECT password FROM users WHERE username='admin", 1, datetime('now', '-15 minutes'), '192.168.1.101');

-- 管理者アクションログ（権限昇格の痕跡）
INSERT OR IGNORE INTO admin_actions (id, user_id, action, target_user_id, details, timestamp) VALUES 
(1, 1, 'USER_ROLE_CHANGE', 2, 'Changed user1 role from user to admin', datetime('now', '-3 hours')),
(2, 2, 'PASSWORD_RESET', 3, 'Reset password for test user', datetime('now', '-2 hours')),
(3, 1, 'DELETE_USER', 4, 'Attempted to delete guest user', datetime('now', '-1 hour')),
(4, 2, 'VIEW_SENSITIVE_DATA', 1, 'Accessed admin credit card information', datetime('now', '-30 minutes'));

-- アプリケーション設定（機密情報を含む）
INSERT OR IGNORE INTO app_settings (id, setting_key, setting_value, description, is_public, updated_by, updated_at) VALUES 
(1, 'database_password', 'super_secret_db_pass', 'Database connection password', 0, 1, datetime('now', '-1 day')),
(2, 'api_secret_key', 'sk_live_12345abcdef67890', 'Secret key for API authentication', 0, 1, datetime('now', '-1 day')),
(3, 'encryption_key', 'aes256_key_very_secret_123456', 'Encryption key for sensitive data', 0, 1, datetime('now', '-1 day')),
(4, 'admin_email', 'admin@gameday.com', 'Administrator email address', 1, 1, datetime('now', '-1 day')),
(5, 'max_upload_size', '10485760', 'Maximum file upload size in bytes', 1, 1, datetime('now', '-1 day')),
(6, 'debug_mode', 'true', 'Enable debug mode (shows sensitive errors)', 1, 1, datetime('now', '-1 day')),
(7, 'backup_location', '/var/backups/gameday/', 'Database backup location', 0, 1, datetime('now', '-1 day')),
(8, 'jwt_secret', 'jwt_super_secret_key_12345', 'JWT token signing secret', 0, 1, datetime('now', '-1 day'));

-- 統計情報の更新
-- SQLiteの場合、ANALYZE文でクエリプランナーの統計を更新
ANALYZE;