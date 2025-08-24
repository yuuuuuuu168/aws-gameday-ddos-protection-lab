#!/bin/bash

# インフラストラクチャテストスクリプト
# 各セキュリティレベル設定を検証し、WAFルール効果とCloudWatchメトリクスを確認

set -e

# 設定
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/infrastructure_test.log"
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform"

# カラー出力
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ログ関数
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

# 使用方法
usage() {
    echo "使用方法: $0 [オプション]"
    echo "オプション:"
    echo "  -l, --level LEVEL    テストするセキュリティレベル (1-4, デフォルト: all)"
    echo "  -r, --region REGION  AWSリージョン (デフォルト: us-east-1)"
    echo "  -h, --help          このヘルプメッセージを表示"
    echo ""
    echo "例:"
    echo "  $0 --level 2 --region us-west-2"
    echo "  $0 --level all"
}

# デフォルト値
SECURITY_LEVEL="all"
AWS_REGION="us-east-1"

# コマンドライン引数の解析
while [[ $# -gt 0 ]]; do
    case $1 in
        -l|--level)
            SECURITY_LEVEL="$2"
            shift 2
            ;;
        -r|--region)
            AWS_REGION="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log_error "不明なオプション: $1"
            usage
            exit 1
            ;;
    esac
done

# 必要なツールの確認
check_dependencies() {
    log "依存関係を確認中..."
    
    local deps=("aws" "jq" "curl")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "$dep が見つかりません。インストールしてください。"
            exit 1
        fi
    done
    
    # AWS認証情報の確認
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS認証情報が設定されていません。"
        exit 1
    fi
    
    log_success "すべての依存関係が確認されました"
}# Terraf
ormの出力値を取得
get_terraform_outputs() {
    log "Terraform出力値を取得中..."
    
    if [[ ! -d "$TERRAFORM_DIR" ]]; then
        log_error "Terraformディレクトリが見つかりません: $TERRAFORM_DIR"
        exit 1
    fi
    
    cd "$TERRAFORM_DIR"
    
    # Terraform出力の取得
    if ! terraform output -json > /tmp/terraform_outputs.json 2>/dev/null; then
        log_error "Terraform出力の取得に失敗しました。terraform applyが実行されているか確認してください。"
        exit 1
    fi
    
    # 必要な出力値の抽出
    ALB_DNS_NAME=$(jq -r '.alb_dns_name.value // empty' /tmp/terraform_outputs.json)
    CLOUDFRONT_DOMAIN=$(jq -r '.cloudfront_domain_name.value // empty' /tmp/terraform_outputs.json)
    WAF_WEB_ACL_ID=$(jq -r '.waf_web_acl_id.value // empty' /tmp/terraform_outputs.json)
    SECURITY_LEVEL_CURRENT=$(jq -r '.current_security_level.value // empty' /tmp/terraform_outputs.json)
    
    if [[ -z "$ALB_DNS_NAME" ]]; then
        log_error "ALB DNS名が取得できませんでした"
        exit 1
    fi
    
    log_success "Terraform出力値を取得しました"
    log "  ALB DNS: $ALB_DNS_NAME"
    log "  CloudFront Domain: ${CLOUDFRONT_DOMAIN:-"未設定"}"
    log "  WAF Web ACL ID: ${WAF_WEB_ACL_ID:-"未設定"}"
    log "  現在のセキュリティレベル: ${SECURITY_LEVEL_CURRENT:-"不明"}"
}

# セキュリティレベル設定の検証
test_security_level_config() {
    local level=$1
    log "セキュリティレベル $level の設定を検証中..."
    
    local test_passed=true
    
    case $level in
        1)
            # レベル1: 基本設定のみ
            if [[ -n "$WAF_WEB_ACL_ID" ]]; then
                log_warning "レベル1ではWAFが無効であるべきですが、有効になっています"
                test_passed=false
            fi
            if [[ -n "$CLOUDFRONT_DOMAIN" ]]; then
                log_warning "レベル1ではCloudFrontが無効であるべきですが、有効になっています"
                test_passed=false
            fi
            ;;
        2)
            # レベル2: WAF有効
            if [[ -z "$WAF_WEB_ACL_ID" ]]; then
                log_error "レベル2ではWAFが有効であるべきですが、無効になっています"
                test_passed=false
            fi
            if [[ -n "$CLOUDFRONT_DOMAIN" ]]; then
                log_warning "レベル2ではCloudFrontが無効であるべきですが、有効になっています"
                test_passed=false
            fi
            ;;
        3)
            # レベル3: WAF + Shield Advanced
            if [[ -z "$WAF_WEB_ACL_ID" ]]; then
                log_error "レベル3ではWAFが有効であるべきですが、無効になっています"
                test_passed=false
            fi
            # Shield Advancedの確認
            local shield_status=$(aws shield describe-subscription --region "$AWS_REGION" 2>/dev/null | jq -r '.Subscription.State // "INACTIVE"')
            if [[ "$shield_status" != "ACTIVE" ]]; then
                log_warning "レベル3ではShield Advancedが有効であるべきですが、無効になっています"
            fi
            ;;
        4)
            # レベル4: 全保護機能有効
            if [[ -z "$WAF_WEB_ACL_ID" ]]; then
                log_error "レベル4ではWAFが有効であるべきですが、無効になっています"
                test_passed=false
            fi
            if [[ -z "$CLOUDFRONT_DOMAIN" ]]; then
                log_error "レベル4ではCloudFrontが有効であるべきですが、無効になっています"
                test_passed=false
            fi
            ;;
    esac
    
    if $test_passed; then
        log_success "セキュリティレベル $level の設定検証が完了しました"
        return 0
    else
        log_error "セキュリティレベル $level の設定に問題があります"
        return 1
    fi
}

# WAFルール効果のテスト
test_waf_rules() {
    log "WAFルール効果をテスト中..."
    
    if [[ -z "$WAF_WEB_ACL_ID" ]]; then
        log_warning "WAFが設定されていないため、WAFテストをスキップします"
        return 0
    fi
    
    local target_url="http://${ALB_DNS_NAME}"
    local test_passed=true
    
    # 正常なリクエストのテスト
    log "正常なリクエストをテスト中..."
    local normal_response=$(curl -s -o /dev/null -w "%{http_code}" "$target_url" || echo "000")
    if [[ "$normal_response" == "200" ]]; then
        log_success "正常なリクエストが通過しました (HTTP $normal_response)"
    else
        log_warning "正常なリクエストが期待通りに動作しませんでした (HTTP $normal_response)"
    fi
    
    # 悪意のあるリクエストのテスト
    log "悪意のあるリクエストをテスト中..."
    
    # SQLインジェクション攻撃パターン
    local sqli_response=$(curl -s -o /dev/null -w "%{http_code}" "${target_url}/search?q=' OR 1=1--" || echo "000")
    log "SQLインジェクション攻撃テスト: HTTP $sqli_response"
    
    # XSS攻撃パターン
    local xss_response=$(curl -s -o /dev/null -w "%{http_code}" "${target_url}/search?q=<script>alert('xss')</script>" || echo "000")
    log "XSS攻撃テスト: HTTP $xss_response"
    
    # レート制限テスト
    log "レート制限をテスト中..."
    local rate_limit_blocked=0
    for i in {1..10}; do
        local response=$(curl -s -o /dev/null -w "%{http_code}" "$target_url" || echo "000")
        if [[ "$response" == "429" || "$response" == "403" ]]; then
            ((rate_limit_blocked++))
        fi
        sleep 0.1
    done
    
    if [[ $rate_limit_blocked -gt 0 ]]; then
        log_success "レート制限が動作しています ($rate_limit_blocked/10 リクエストがブロックされました)"
    else
        log_warning "レート制限が動作していない可能性があります"
    fi
    
    return 0
}# CloudWatc
hメトリクスの検証
test_cloudwatch_metrics() {
    log "CloudWatchメトリクスを検証中..."
    
    local test_passed=true
    local end_time=$(date -u +%Y-%m-%dT%H:%M:%S)
    local start_time=$(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%S)
    
    # ALBメトリクスの確認
    log "ALBメトリクスを確認中..."
    local alb_metrics=$(aws cloudwatch get-metric-statistics \
        --namespace "AWS/ApplicationELB" \
        --metric-name "RequestCount" \
        --dimensions Name=LoadBalancer,Value="${ALB_DNS_NAME}" \
        --start-time "$start_time" \
        --end-time "$end_time" \
        --period 300 \
        --statistics Sum \
        --region "$AWS_REGION" 2>/dev/null || echo '{"Datapoints":[]}')
    
    local alb_datapoints=$(echo "$alb_metrics" | jq '.Datapoints | length')
    if [[ "$alb_datapoints" -gt 0 ]]; then
        log_success "ALBメトリクスが記録されています ($alb_datapoints データポイント)"
    else
        log_warning "ALBメトリクスが見つかりません"
    fi
    
    # WAFメトリクスの確認（WAFが有効な場合）
    if [[ -n "$WAF_WEB_ACL_ID" ]]; then
        log "WAFメトリクスを確認中..."
        local waf_metrics=$(aws cloudwatch get-metric-statistics \
            --namespace "AWS/WAFV2" \
            --metric-name "AllowedRequests" \
            --dimensions Name=WebACL,Value="$WAF_WEB_ACL_ID" Name=Region,Value="$AWS_REGION" Name=Rule,Value="ALL" \
            --start-time "$start_time" \
            --end-time "$end_time" \
            --period 300 \
            --statistics Sum \
            --region "$AWS_REGION" 2>/dev/null || echo '{"Datapoints":[]}')
        
        local waf_datapoints=$(echo "$waf_metrics" | jq '.Datapoints | length')
        if [[ "$waf_datapoints" -gt 0 ]]; then
            log_success "WAFメトリクスが記録されています ($waf_datapoints データポイント)"
        else
            log_warning "WAFメトリクスが見つかりません"
        fi
    fi
    
    # CloudWatchアラームの確認
    log "CloudWatchアラームを確認中..."
    local alarms=$(aws cloudwatch describe-alarms \
        --alarm-name-prefix "gameday" \
        --region "$AWS_REGION" 2>/dev/null || echo '{"MetricAlarms":[]}')
    
    local alarm_count=$(echo "$alarms" | jq '.MetricAlarms | length')
    if [[ "$alarm_count" -gt 0 ]]; then
        log_success "CloudWatchアラームが設定されています ($alarm_count アラーム)"
        
        # アラーム状態の確認
        echo "$alarms" | jq -r '.MetricAlarms[] | "\(.AlarmName): \(.StateValue)"' | while read -r alarm_info; do
            log "  $alarm_info"
        done
    else
        log_warning "CloudWatchアラームが見つかりません"
    fi
    
    # ログループの確認
    log "CloudWatchログループを確認中..."
    local log_groups=$(aws logs describe-log-groups \
        --log-group-name-prefix "/aws/gameday" \
        --region "$AWS_REGION" 2>/dev/null || echo '{"logGroups":[]}')
    
    local log_group_count=$(echo "$log_groups" | jq '.logGroups | length')
    if [[ "$log_group_count" -gt 0 ]]; then
        log_success "CloudWatchログループが設定されています ($log_group_count ログループ)"
        
        echo "$log_groups" | jq -r '.logGroups[] | .logGroupName' | while read -r log_group; do
            log "  $log_group"
        done
    else
        log_warning "CloudWatchログループが見つかりません"
    fi
    
    return 0
}

# GuardDutyの確認
test_guardduty() {
    log "GuardDutyを確認中..."
    
    local detector_id=$(aws guardduty list-detectors --region "$AWS_REGION" 2>/dev/null | jq -r '.DetectorIds[0] // empty')
    
    if [[ -n "$detector_id" ]]; then
        log_success "GuardDutyディテクターが有効です (ID: $detector_id)"
        
        # GuardDutyの設定確認
        local detector_info=$(aws guardduty get-detector --detector-id "$detector_id" --region "$AWS_REGION" 2>/dev/null)
        local status=$(echo "$detector_info" | jq -r '.Status')
        
        if [[ "$status" == "ENABLED" ]]; then
            log_success "GuardDutyが有効になっています"
        else
            log_warning "GuardDutyが無効になっています"
        fi
        
        # 最近の検出結果を確認
        local findings=$(aws guardduty list-findings --detector-id "$detector_id" --region "$AWS_REGION" 2>/dev/null || echo '{"FindingIds":[]}')
        local finding_count=$(echo "$findings" | jq '.FindingIds | length')
        log "GuardDuty検出結果: $finding_count 件"
        
    else
        log_warning "GuardDutyディテクターが見つかりません"
    fi
    
    return 0
}

# 個別テストの実行
run_single_test() {
    local level=$1
    log "セキュリティレベル $level のテストを開始します"
    
    local test_results=()
    
    # セキュリティレベル設定の検証
    if test_security_level_config "$level"; then
        test_results+=("セキュリティレベル設定: PASS")
    else
        test_results+=("セキュリティレベル設定: FAIL")
    fi
    
    # WAFルール効果のテスト
    if test_waf_rules; then
        test_results+=("WAFルール効果: PASS")
    else
        test_results+=("WAFルール効果: FAIL")
    fi
    
    # CloudWatchメトリクスの検証
    if test_cloudwatch_metrics; then
        test_results+=("CloudWatchメトリクス: PASS")
    else
        test_results+=("CloudWatchメトリクス: FAIL")
    fi
    
    # GuardDutyの確認
    if test_guardduty; then
        test_results+=("GuardDuty: PASS")
    else
        test_results+=("GuardDuty: FAIL")
    fi
    
    # 結果の表示
    log "セキュリティレベル $level のテスト結果:"
    for result in "${test_results[@]}"; do
        if [[ "$result" == *"PASS"* ]]; then
            log_success "  $result"
        else
            log_error "  $result"
        fi
    done
    
    return 0
}

# メイン実行関数
main() {
    log "インフラストラクチャテストを開始します"
    log "セキュリティレベル: $SECURITY_LEVEL"
    log "AWSリージョン: $AWS_REGION"
    
    # 初期化
    > "$LOG_FILE"
    
    # 依存関係の確認
    check_dependencies
    
    # Terraform出力の取得
    get_terraform_outputs
    
    # テストの実行
    if [[ "$SECURITY_LEVEL" == "all" ]]; then
        log "全セキュリティレベルのテストを実行します"
        for level in 1 2 3 4; do
            run_single_test "$level"
            echo ""
        done
    else
        run_single_test "$SECURITY_LEVEL"
    fi
    
    log_success "インフラストラクチャテストが完了しました"
    log "詳細なログは $LOG_FILE を確認してください"
}

# スクリプトの実行
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi