#!/bin/bash

# エンドツーエンドセキュリティテストパイプライン
# 全セキュリティレベル検証、テストレポート生成、自動クリーンアップ機能

set -e

# 設定
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/security_pipeline.log"
REPORT_FILE="${SCRIPT_DIR}/security_test_report.html"
JSON_REPORT_FILE="${SCRIPT_DIR}/security_test_report.json"
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform"

# カラー出力
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
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

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_pipeline() {
    echo -e "${PURPLE}[PIPELINE]${NC} $1" | tee -a "$LOG_FILE"
}

# 使用方法
usage() {
    echo "使用方法: $0 [オプション]"
    echo "オプション:"
    echo "  -l, --levels LEVELS  テストするセキュリティレベル (1,2,3,4 または all, デフォルト: all)"
    echo "  -r, --region REGION  AWSリージョン (デフォルト: us-east-1)"
    echo "  -c, --cleanup        テスト後にリソースをクリーンアップ"
    echo "  -s, --skip-deploy    デプロイメントをスキップ（既存環境を使用）"
    echo "  -v, --verbose        詳細出力を有効にする"
    echo "  -o, --output FORMAT  レポート形式 (html|json|both, デフォルト: both)"
    echo "  -h, --help          このヘルプメッセージを表示"
    echo ""
    echo "例:"
    echo "  $0 --levels 1,2,3 --cleanup"
    echo "  $0 --skip-deploy --output html"
    echo "  $0 --levels all --verbose"
}

# デフォルト値
SECURITY_LEVELS="all"
AWS_REGION="us-east-1"
CLEANUP_AFTER_TEST=false
SKIP_DEPLOYMENT=false
VERBOSE=false
OUTPUT_FORMAT="both"

# テスト結果を格納する配列
declare -A TEST_RESULTS
declare -A TEST_DETAILS
declare -A SECURITY_LEVEL_CONFIGS

# コマンドライン引数の解析
while [[ $# -gt 0 ]]; do
    case $1 in
        -l|--levels)
            SECURITY_LEVELS="$2"
            shift 2
            ;;
        -r|--region)
            AWS_REGION="$2"
            shift 2
            ;;
        -c|--cleanup)
            CLEANUP_AFTER_TEST=true
            shift
            ;;
        -s|--skip-deploy)
            SKIP_DEPLOYMENT=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -o|--output)
            OUTPUT_FORMAT="$2"
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
    log_pipeline "依存関係を確認中..."
    
    local deps=("terraform" "aws" "curl" "jq")
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
    
    # テストスクリプトの存在確認
    local test_scripts=("test_infrastructure.sh" "test_vulnerabilities.sh")
    for script in "${test_scripts[@]}"; do
        if [[ ! -f "$SCRIPT_DIR/$script" ]]; then
            log_error "テストスクリプトが見つかりません: $script"
            exit 1
        fi
        
        if [[ ! -x "$SCRIPT_DIR/$script" ]]; then
            chmod +x "$SCRIPT_DIR/$script"
        fi
    done
    
    log_success "すべての依存関係が確認されました"
}

# セキュリティレベルの解析
parse_security_levels() {
    log_pipeline "セキュリティレベルを解析中..."
    
    if [[ "$SECURITY_LEVELS" == "all" ]]; then
        SECURITY_LEVELS="1,2,3,4"
    fi
    
    IFS=',' read -ra LEVELS <<< "$SECURITY_LEVELS"
    
    for level in "${LEVELS[@]}"; do
        if [[ ! "$level" =~ ^[1-4]$ ]]; then
            log_error "無効なセキュリティレベル: $level (1-4の範囲で指定してください)"
            exit 1
        fi
    done
    
    log_success "テスト対象セキュリティレベル: ${LEVELS[*]}"
}# Terraf
ormデプロイメント
deploy_security_level() {
    local level=$1
    log_pipeline "セキュリティレベル $level をデプロイ中..."
    
    if [[ ! -d "$TERRAFORM_DIR" ]]; then
        log_error "Terraformディレクトリが見つかりません: $TERRAFORM_DIR"
        return 1
    fi
    
    cd "$TERRAFORM_DIR"
    
    # Terraform変数の設定
    export TF_VAR_security_level="$level"
    export TF_VAR_aws_region="$AWS_REGION"
    
    # Terraform初期化（必要に応じて）
    if [[ ! -d ".terraform" ]]; then
        log_info "Terraformを初期化中..."
        if ! terraform init; then
            log_error "Terraform初期化に失敗しました"
            return 1
        fi
    fi
    
    # Terraformプラン
    log_info "Terraformプランを作成中..."
    if ! terraform plan -out="level_${level}.tfplan" -var="security_level=${level}"; then
        log_error "Terraformプランの作成に失敗しました"
        return 1
    fi
    
    # Terraform適用
    log_info "Terraformを適用中..."
    if ! terraform apply -auto-approve "level_${level}.tfplan"; then
        log_error "Terraformの適用に失敗しました"
        return 1
    fi
    
    # デプロイメント完了の待機
    log_info "デプロイメント完了を待機中..."
    sleep 30
    
    log_success "セキュリティレベル $level のデプロイが完了しました"
    return 0
}

# インフラストラクチャテストの実行
run_infrastructure_test() {
    local level=$1
    log_pipeline "セキュリティレベル $level のインフラストラクチャテストを実行中..."
    
    local test_output
    local test_result
    
    if $VERBOSE; then
        test_output=$("$SCRIPT_DIR/test_infrastructure.sh" --level "$level" --region "$AWS_REGION" 2>&1)
        test_result=$?
    else
        test_output=$("$SCRIPT_DIR/test_infrastructure.sh" --level "$level" --region "$AWS_REGION" 2>&1)
        test_result=$?
    fi
    
    TEST_DETAILS["infra_level_${level}"]="$test_output"
    
    if [[ $test_result -eq 0 ]]; then
        TEST_RESULTS["infra_level_${level}"]="PASS"
        log_success "インフラストラクチャテスト (レベル $level): PASS"
    else
        TEST_RESULTS["infra_level_${level}"]="FAIL"
        log_error "インフラストラクチャテスト (レベル $level): FAIL"
    fi
    
    return $test_result
}

# 脆弱性テストの実行
run_vulnerability_test() {
    local level=$1
    log_pipeline "セキュリティレベル $level の脆弱性テストを実行中..."
    
    local test_output
    local test_result
    
    if $VERBOSE; then
        test_output=$("$SCRIPT_DIR/test_vulnerabilities.sh" --test all 2>&1)
        test_result=$?
    else
        test_output=$("$SCRIPT_DIR/test_vulnerabilities.sh" --test all 2>&1)
        test_result=$?
    fi
    
    TEST_DETAILS["vuln_level_${level}"]="$test_output"
    
    # 脆弱性テストでは、脆弱性が見つかることが期待される（学習環境）
    if [[ $test_result -eq 1 ]]; then
        TEST_RESULTS["vuln_level_${level}"]="PASS"
        log_success "脆弱性テスト (レベル $level): PASS (脆弱性が確認されました)"
    else
        TEST_RESULTS["vuln_level_${level}"]="FAIL"
        log_warning "脆弱性テスト (レベル $level): FAIL (脆弱性が検出されませんでした)"
    fi
    
    return 0
}

# DDoS攻撃シミュレーション
run_ddos_simulation() {
    local level=$1
    log_pipeline "セキュリティレベル $level でDDoS攻撃シミュレーションを実行中..."
    
    # Terraform出力からターゲットURLを取得
    cd "$TERRAFORM_DIR"
    local alb_dns=$(terraform output -raw alb_dns_name 2>/dev/null || echo "")
    local cloudfront_domain=$(terraform output -raw cloudfront_domain_name 2>/dev/null || echo "")
    
    local target_url
    if [[ -n "$cloudfront_domain" ]]; then
        target_url="https://$cloudfront_domain"
    elif [[ -n "$alb_dns" ]]; then
        target_url="http://$alb_dns"
    else
        log_error "ターゲットURLが取得できませんでした"
        TEST_RESULTS["ddos_level_${level}"]="FAIL"
        return 1
    fi
    
    log_info "DDoS攻撃対象: $target_url"
    
    # 基準パフォーマンスの測定
    log_info "基準パフォーマンスを測定中..."
    local baseline_time=$(curl -s -o /dev/null -w "%{time_total}" "$target_url" || echo "999")
    log_info "基準レスポンス時間: ${baseline_time}秒"
    
    # DDoS攻撃の実行
    log_info "DDoS攻撃を開始中..."
    local attack_duration=30
    local concurrent_requests=50
    
    # バックグラウンドで攻撃を実行
    for i in $(seq 1 $concurrent_requests); do
        {
            for j in $(seq 1 $attack_duration); do
                curl -s "$target_url" > /dev/null 2>&1 &
                sleep 1
            done
        } &
    done
    
    # 攻撃中のパフォーマンス測定
    sleep 5
    local attack_time=$(curl -s -o /dev/null -w "%{time_total}" "$target_url" || echo "999")
    log_info "攻撃中レスポンス時間: ${attack_time}秒"
    
    # 攻撃の完了を待機
    wait
    
    # 結果の評価
    local performance_degradation=$(echo "$attack_time > $baseline_time * 2" | bc -l 2>/dev/null || echo "0")
    
    if [[ "$performance_degradation" == "1" ]]; then
        case $level in
            1|2)
                TEST_RESULTS["ddos_level_${level}"]="PASS"
                log_success "DDoS攻撃シミュレーション (レベル $level): PASS (期待通りパフォーマンス劣化)"
                ;;
            3|4)
                TEST_RESULTS["ddos_level_${level}"]="FAIL"
                log_warning "DDoS攻撃シミュレーション (レベル $level): FAIL (保護が不十分)"
                ;;
        esac
    else
        case $level in
            1|2)
                TEST_RESULTS["ddos_level_${level}"]="FAIL"
                log_warning "DDoS攻撃シミュレーション (レベル $level): FAIL (攻撃効果が不十分)"
                ;;
            3|4)
                TEST_RESULTS["ddos_level_${level}"]="PASS"
                log_success "DDoS攻撃シミュレーション (レベル $level): PASS (適切に保護されています)"
                ;;
        esac
    fi
    
    TEST_DETAILS["ddos_level_${level}"]="基準時間: ${baseline_time}秒, 攻撃中時間: ${attack_time}秒"
    
    return 0
}

# セキュリティレベルの完全テスト
test_security_level() {
    local level=$1
    log_pipeline "セキュリティレベル $level の完全テストを開始します"
    
    # デプロイメント（スキップされていない場合）
    if ! $SKIP_DEPLOYMENT; then
        if ! deploy_security_level "$level"; then
            log_error "セキュリティレベル $level のデプロイに失敗しました"
            return 1
        fi
    fi
    
    # テストの実行
    run_infrastructure_test "$level"
    run_vulnerability_test "$level"
    run_ddos_simulation "$level"
    
    log_success "セキュリティレベル $level のテストが完了しました"
    return 0
}# JSONレ
ポートの生成
generate_json_report() {
    log_pipeline "JSONレポートを生成中..."
    
    local json_content="{
  \"test_execution\": {
    \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"security_levels_tested\": [$(printf '%s,' "${LEVELS[@]}" | sed 's/,$//')]
  },
  \"results\": {"
    
    local first=true
    for key in "${!TEST_RESULTS[@]}"; do
        if ! $first; then
            json_content+=","
        fi
        first=false
        
        local status="${TEST_RESULTS[$key]}"
        local details="${TEST_DETAILS[$key]:-""}"
        
        json_content+="
    \"$key\": {
      \"status\": \"$status\",
      \"details\": \"$(echo "$details" | sed 's/"/\\"/g' | tr '\n' ' ')\"
    }"
    done
    
    json_content+="
  },
  \"summary\": {
    \"total_tests\": ${#TEST_RESULTS[@]},
    \"passed_tests\": $(printf '%s\n' "${TEST_RESULTS[@]}" | grep -c "PASS" || echo "0"),
    \"failed_tests\": $(printf '%s\n' "${TEST_RESULTS[@]}" | grep -c "FAIL" || echo "0")
  }
}"
    
    echo "$json_content" > "$JSON_REPORT_FILE"
    log_success "JSONレポートが生成されました: $JSON_REPORT_FILE"
}

# HTMLレポートの生成
generate_html_report() {
    log_pipeline "HTMLレポートを生成中..."
    
    cat > "$REPORT_FILE" << 'EOF'
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS GameDay セキュリティテストレポート</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .summary {
            display: flex;
            justify-content: space-around;
            padding: 30px;
            background-color: #f8f9fa;
        }
        .summary-item {
            text-align: center;
        }
        .summary-number {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .summary-label {
            color: #666;
            font-size: 0.9em;
        }
        .pass { color: #28a745; }
        .fail { color: #dc3545; }
        .content {
            padding: 30px;
        }
        .test-section {
            margin-bottom: 40px;
        }
        .test-section h2 {
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        .test-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .test-card {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            background-color: #fff;
        }
        .test-card h3 {
            margin-top: 0;
            color: #333;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .status-pass {
            background-color: #d4edda;
            color: #155724;
        }
        .status-fail {
            background-color: #f8d7da;
            color: #721c24;
        }
        .details {
            margin-top: 15px;
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9em;
            max-height: 200px;
            overflow-y: auto;
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            border-top: 1px solid #eee;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AWS GameDay セキュリティテストレポート</h1>
            <p>実行日時: TIMESTAMP_PLACEHOLDER</p>
        </div>
        
        <div class="summary">
            <div class="summary-item">
                <div class="summary-number">TOTAL_TESTS_PLACEHOLDER</div>
                <div class="summary-label">総テスト数</div>
            </div>
            <div class="summary-item">
                <div class="summary-number pass">PASSED_TESTS_PLACEHOLDER</div>
                <div class="summary-label">成功</div>
            </div>
            <div class="summary-item">
                <div class="summary-number fail">FAILED_TESTS_PLACEHOLDER</div>
                <div class="summary-label">失敗</div>
            </div>
        </div>
        
        <div class="content">
            TEST_RESULTS_PLACEHOLDER
        </div>
        
        <div class="footer">
            <p>AWS GameDay "Winning the DDoS Game" 環境テストレポート</p>
        </div>
    </div>
</body>
</html>
EOF
    
    # プレースホルダーの置換
    local timestamp=$(date '+%Y年%m月%d日 %H:%M:%S')
    local total_tests=${#TEST_RESULTS[@]}
    local passed_tests=$(printf '%s\n' "${TEST_RESULTS[@]}" | grep -c "PASS" || echo "0")
    local failed_tests=$(printf '%s\n' "${TEST_RESULTS[@]}" | grep -c "FAIL" || echo "0")
    
    sed -i.bak "s/TIMESTAMP_PLACEHOLDER/$timestamp/g" "$REPORT_FILE"
    sed -i.bak "s/TOTAL_TESTS_PLACEHOLDER/$total_tests/g" "$REPORT_FILE"
    sed -i.bak "s/PASSED_TESTS_PLACEHOLDER/$passed_tests/g" "$REPORT_FILE"
    sed -i.bak "s/FAILED_TESTS_PLACEHOLDER/$failed_tests/g" "$REPORT_FILE"
    
    # テスト結果の生成
    local test_results_html=""
    
    # セキュリティレベル別にグループ化
    for level in "${LEVELS[@]}"; do
        test_results_html+="<div class=\"test-section\">
            <h2>セキュリティレベル $level</h2>
            <div class=\"test-grid\">"
        
        # インフラストラクチャテスト
        local infra_status="${TEST_RESULTS["infra_level_${level}"]:-"N/A"}"
        local infra_details="${TEST_DETAILS["infra_level_${level}"]:-"詳細なし"}"
        local infra_badge_class="status-$(echo "$infra_status" | tr '[:upper:]' '[:lower:]')"
        
        test_results_html+="<div class=\"test-card\">
                <h3>インフラストラクチャテスト</h3>
                <span class=\"status-badge $infra_badge_class\">$infra_status</span>
                <div class=\"details\">$(echo "$infra_details" | head -10)</div>
            </div>"
        
        # 脆弱性テスト
        local vuln_status="${TEST_RESULTS["vuln_level_${level}"]:-"N/A"}"
        local vuln_details="${TEST_DETAILS["vuln_level_${level}"]:-"詳細なし"}"
        local vuln_badge_class="status-$(echo "$vuln_status" | tr '[:upper:]' '[:lower:]')"
        
        test_results_html+="<div class=\"test-card\">
                <h3>脆弱性テスト</h3>
                <span class=\"status-badge $vuln_badge_class\">$vuln_status</span>
                <div class=\"details\">$(echo "$vuln_details" | head -10)</div>
            </div>"
        
        # DDoS攻撃シミュレーション
        local ddos_status="${TEST_RESULTS["ddos_level_${level}"]:-"N/A"}"
        local ddos_details="${TEST_DETAILS["ddos_level_${level}"]:-"詳細なし"}"
        local ddos_badge_class="status-$(echo "$ddos_status" | tr '[:upper:]' '[:lower:]')"
        
        test_results_html+="<div class=\"test-card\">
                <h3>DDoS攻撃シミュレーション</h3>
                <span class=\"status-badge $ddos_badge_class\">$ddos_status</span>
                <div class=\"details\">$ddos_details</div>
            </div>"
        
        test_results_html+="</div></div>"
    done
    
    # HTMLファイルに結果を挿入
    sed -i.bak "s|TEST_RESULTS_PLACEHOLDER|$test_results_html|g" "$REPORT_FILE"
    
    # バックアップファイルの削除
    rm -f "${REPORT_FILE}.bak"
    
    log_success "HTMLレポートが生成されました: $REPORT_FILE"
}

# リソースのクリーンアップ
cleanup_resources() {
    log_pipeline "リソースをクリーンアップ中..."
    
    if [[ ! -d "$TERRAFORM_DIR" ]]; then
        log_error "Terraformディレクトリが見つかりません: $TERRAFORM_DIR"
        return 1
    fi
    
    cd "$TERRAFORM_DIR"
    
    log_info "Terraformリソースを削除中..."
    if terraform destroy -auto-approve; then
        log_success "リソースのクリーンアップが完了しました"
    else
        log_error "リソースのクリーンアップに失敗しました"
        return 1
    fi
    
    return 0
}

# メイン実行関数
main() {
    log_pipeline "エンドツーエンドセキュリティテストパイプラインを開始します"
    
    # 初期化
    > "$LOG_FILE"
    
    # 依存関係の確認
    check_dependencies
    
    # セキュリティレベルの解析
    parse_security_levels
    
    # 各セキュリティレベルのテスト実行
    for level in "${LEVELS[@]}"; do
        test_security_level "$level"
    done
    
    # レポートの生成
    case $OUTPUT_FORMAT in
        "json")
            generate_json_report
            ;;
        "html")
            generate_html_report
            ;;
        "both")
            generate_json_report
            generate_html_report
            ;;
    esac
    
    # クリーンアップ（要求された場合）
    if $CLEANUP_AFTER_TEST; then
        cleanup_resources
    fi
    
    # 結果サマリーの表示
    log_pipeline "テストパイプライン完了サマリー:"
    log_info "総テスト数: ${#TEST_RESULTS[@]}"
    log_success "成功: $(printf '%s\n' "${TEST_RESULTS[@]}" | grep -c "PASS" || echo "0")"
    log_error "失敗: $(printf '%s\n' "${TEST_RESULTS[@]}" | grep -c "FAIL" || echo "0")"
    
    if [[ "$OUTPUT_FORMAT" == "html" ]] || [[ "$OUTPUT_FORMAT" == "both" ]]; then
        log_info "HTMLレポート: $REPORT_FILE"
    fi
    
    if [[ "$OUTPUT_FORMAT" == "json" ]] || [[ "$OUTPUT_FORMAT" == "both" ]]; then
        log_info "JSONレポート: $JSON_REPORT_FILE"
    fi
    
    log_success "エンドツーエンドセキュリティテストパイプラインが完了しました"
}

# スクリプトの実行
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi