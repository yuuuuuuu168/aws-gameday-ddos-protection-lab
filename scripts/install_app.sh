#!/bin/bash

# GameDay Vulnerable App Installation Script
# This script is designed to run as EC2 user-data

set -e

# ログ設定
LOG_FILE="/var/log/gameday-app-install.log"
exec > >(tee -a $LOG_FILE)
exec 2>&1

echo "=== GameDay Vulnerable App Installation Started ==="
echo "Timestamp: $(date)"

# システム更新
echo "Updating system packages..."
yum update -y

# Node.js 18.x インストール
echo "Installing Node.js..."
curl -fsSL https://rpm.nodesource.com/setup_18.x | bash -
yum install -y nodejs

# 必要なパッケージのインストール
echo "Installing additional packages..."
yum install -y git wget curl unzip

# アプリケーション用ユーザー作成
echo "Creating application user..."
useradd -m -s /bin/bash gameday-app || true

# アプリケーションディレクトリ作成
APP_DIR="/opt/gameday-app"
echo "Creating application directory: $APP_DIR"
mkdir -p $APP_DIR
chown gameday-app:gameday-app $APP_DIR

# アプリケーションファイルのダウンロード/コピー
echo "Setting up application files..."
cd $APP_DIR

# package.jsonの作成
cat > package.json << 'EOF'
{
  "name": "gameday-vulnerable-app",
  "version": "1.0.0",
  "description": "Intentionally vulnerable web application for AWS GameDay DDoS learning",
  "main": "app.js",
  "scripts": {
    "start": "node app.js",
    "dev": "nodemon app.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "sqlite3": "^5.1.6",
    "multer": "^1.4.5-lts.1",
    "body-parser": "^1.20.2",
    "express-session": "^1.17.3"
  },
  "keywords": ["vulnerable", "security", "learning", "gameday"],
  "author": "AWS GameDay Team",
  "license": "MIT"
}
EOF

# アプリケーションコードの作成（Base64エンコードされたコードをデコード）
# 実際のデプロイメントでは、S3やGitHubからダウンロードすることを推奨
echo "Creating application code..."
cat > app.js << 'EOF'
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
  secret: 'weak-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: false,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// データベース初期化
const db = new sqlite3.Database('./gameday.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
  )`);

  db.run(`INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES 
    (1, 'admin', 'password123', 'admin@gameday.com', 'admin'),
    (2, 'user1', 'qwerty', 'user1@gameday.com', 'user'),
    (3, 'test', 'test', 'test@gameday.com', 'user')`);
});

// ルート定義（簡略版）
app.get('/', (req, res) => {
  res.send(`
    <h1>🎯 AWS GameDay - Vulnerable Web Application</h1>
    <p>Application is running successfully!</p>
    <p>Instance ID: ${process.env.EC2_INSTANCE_ID || 'Unknown'}</p>
    <p>Timestamp: ${new Date().toISOString()}</p>
  `);
});

app.listen(PORT, () => {
  console.log(`🎯 GameDay Vulnerable App running on port ${PORT}`);
});
EOF

# 依存関係のインストール
echo "Installing Node.js dependencies..."
npm install

# アプリケーションファイルの所有権設定
chown -R gameday-app:gameday-app $APP_DIR

# ログディレクトリ作成
mkdir -p /var/log/gameday-app
chown gameday-app:gameday-app /var/log/gameday-app

# アップロードディレクトリ作成
mkdir -p $APP_DIR/uploads
chown gameday-app:gameday-app $APP_DIR/uploads

echo "=== Application installation completed ==="

# systemdサービス設定
echo "Creating systemd service..."
cat > /etc/systemd/system/gameday-app.service << 'EOF'
[Unit]
Description=GameDay Vulnerable Web Application
After=network.target

[Service]
Type=simple
User=gameday-app
Group=gameday-app
WorkingDirectory=/opt/gameday-app
ExecStart=/usr/bin/node app.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production
Environment=PORT=3000

# ログ設定
StandardOutput=append:/var/log/gameday-app/app.log
StandardError=append:/var/log/gameday-app/error.log

# セキュリティ設定（意図的に緩い設定）
NoNewPrivileges=false
PrivateTmp=false

[Install]
WantedBy=multi-user.target
EOF

# systemdサービスの有効化と開始
echo "Enabling and starting gameday-app service..."
systemctl daemon-reload
systemctl enable gameday-app.service
systemctl start gameday-app.service

# サービス状態確認
echo "Checking service status..."
systemctl status gameday-app.service --no-pager

# ファイアウォール設定（Amazon Linux 2の場合）
echo "Configuring firewall..."
if command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=3000/tcp
    firewall-cmd --reload
fi

# CloudWatch Logs エージェント設定
echo "Setting up CloudWatch Logs agent..."
yum install -y amazon-cloudwatch-agent

# CloudWatch設定ファイル作成
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/gameday-app/app.log",
            "log_group_name": "/aws/ec2/gameday-app",
            "log_stream_name": "{instance_id}/application",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/log/gameday-app/error.log",
            "log_group_name": "/aws/ec2/gameday-app",
            "log_stream_name": "{instance_id}/error",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/log/gameday-app-install.log",
            "log_group_name": "/aws/ec2/gameday-app",
            "log_stream_name": "{instance_id}/install",
            "timezone": "UTC"
          }
        ]
      }
    }
  }
}
EOF

# CloudWatch エージェント開始
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json \
    -s

echo "=== GameDay Vulnerable App Installation Completed Successfully ==="
echo "Application should be accessible on port 3000"
echo "Service status: $(systemctl is-active gameday-app.service)"
echo "Installation log: $LOG_FILE"