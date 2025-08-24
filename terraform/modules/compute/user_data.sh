#!/bin/bash
set -e

# ログ関数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a /var/log/app-install.log
}

log "=== 脆弱なWebアプリケーション初期化開始 ==="

# システム更新
yum update -y

# Apache HTTP Serverのインストール
log "Apache HTTP Serverをインストール中..."
yum install -y httpd

# 簡単なテストページを作成
log "テストページを作成中..."
cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>AWS GameDay - 脆弱なWebアプリケーション</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .form-group { margin: 15px 0; }
        input, textarea { width: 300px; padding: 8px; margin: 5px 0; }
        button { background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h1>AWS GameDay - 脆弱なWebアプリケーション</h1>
        <div class="warning">
            <strong>警告:</strong> このアプリケーションは学習目的で意図的に脆弱性を含んでいます。
        </div>
        
        <h2>ログイン</h2>
        <form action="/login.php" method="post">
            <div class="form-group">
                <input type="text" name="username" placeholder="ユーザー名" required>
            </div>
            <div class="form-group">
                <input type="password" name="password" placeholder="パスワード" required>
            </div>
            <button type="submit">ログイン</button>
        </form>
        
        <h2>検索</h2>
        <form action="/search.php" method="get">
            <div class="form-group">
                <input type="text" name="q" placeholder="検索キーワード">
            </div>
            <button type="submit">検索</button>
        </form>
        
        <h2>コメント投稿</h2>
        <form action="/comment.php" method="post">
            <div class="form-group">
                <textarea name="comment" placeholder="コメントを入力してください" rows="4"></textarea>
            </div>
            <button type="submit">投稿</button>
        </form>
        
        <h2>ヘルスチェック</h2>
        <p><a href="/health.html">ヘルスチェックページ</a></p>
        
        <div class="warning">
            <strong>注意:</strong> このアプリケーションは教育目的のみに使用してください。
        </div>
    </div>
</body>
</html>
EOF

# ヘルスチェック用ページを作成
cat > /var/www/html/health.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Health Check</title>
</head>
<body>
    <h1>Health Check</h1>
    <p>Status: OK</p>
    <p>Timestamp: $(date)</p>
</body>
</html>
EOF

# Apacheの設定
log "Apacheを設定中..."

# ポート3000でリッスンするように設定
echo "Listen 3000" >> /etc/httpd/conf/httpd.conf

# VirtualHostの設定
cat >> /etc/httpd/conf/httpd.conf << 'EOF'

<VirtualHost *:3000>
    DocumentRoot /var/www/html
    ServerName localhost
    
    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
    
    # ログ設定
    ErrorLog /var/log/httpd/error_log
    CustomLog /var/log/httpd/access_log combined
</VirtualHost>
EOF

# Apacheサービスの有効化と開始
systemctl enable httpd
systemctl start httpd

# サービス状態の確認
sleep 5
systemctl status httpd

# ポート3000でのテスト
log "ポート3000でのテストを実行中..."
curl -I http://localhost:3000/ || log "ローカルテスト失敗"

log "=== 脆弱なWebアプリケーション初期化完了 ==="

# 初期化完了の通知
echo "Vulnerable web application setup completed" > /tmp/app_initialization_complete