#!/bin/bash
set -e

# 変数設定
TARGET_ALB_DNS="${target_alb_dns}"
TARGET_CLOUDFRONT_DOMAIN="${target_cloudfront_domain}"
AWS_REGION="${aws_region}"
LOG_GROUP_NAME="${log_group_name}"
LOG_FILE="/var/log/attack-simulation.log"
SCRIPTS_DIR="/home/ec2-user/attack-scripts"

# ログ関数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "=== 攻撃シミュレーション初期化開始 ==="

# 基本ツールのインストール
yum update -y
yum install -y curl wget git python3 python3-pip httpd-tools
pip3 install --upgrade pip requests

# 攻撃スクリプト用ディレクトリ作成
mkdir -p "$SCRIPTS_DIR"
mkdir -p "$SCRIPTS_DIR/logs"
chown -R ec2-user:ec2-user "$SCRIPTS_DIR"

# 簡単なDDoS攻撃スクリプト作成
cat > "$SCRIPTS_DIR/ddos_test.sh" << 'EOF'
#!/bin/bash
if [[ $# -lt 1 ]]; then
    echo "使用方法: $0 <target_url>"
    exit 1
fi
TARGET_URL="$1"
echo "DDoS攻撃テスト開始: $TARGET_URL"
ab -n 1000 -c 10 "$TARGET_URL"
EOF

chmod +x "$SCRIPTS_DIR/ddos_test.sh"
chown -R ec2-user:ec2-user "$SCRIPTS_DIR"

log "=== 攻撃シミュレーション初期化完了 ==="
echo "初期化完了" > /tmp/initialization_complete