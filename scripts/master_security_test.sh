#!/bin/bash

# マスターセキュリティテストスクリプト
# 全セキュリティレベル検証を実行し、包括的なテストレポートを生成

set -e

# 設定
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/master_security_test.log"
REPORT_DIR="${SCRIPT_DIR}/reports"
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

log_master() {
    echo -e "${PURPLE}[MASTER]${NC} $1" | tee -a "$LOG_FILE"
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
    echo "  -o, --output FORMAT  レポート形式 (html|json|csv|all, デフォルト: all)"
    echo "  -p, --parallel       並列テスト実行を有効にする"
    echo "  -t, --timeout SEC    各テストのタイムアウト秒数 (デフォルト: 300)"
    echo "  -h, --help          このヘルプメッセージを表示"
    echo ""
    echo "例:"
    echo "  $0 --levels 1,2,3 --cleanup --parallel"
    echo "  $0 --skip-deploy --output html --verbose"
    echo "  $0 --levels all --timeout 600"
}

# デフォルト値
SECURITY_LEVELS="all"
AWS_REGION="us-east-1"
CLEANUP_AFTER_TEST=false
SKIP_DEPLOYMENT=false
VERBOSE=false
OUTPUT_FORMAT="all"
PARALLEL_EXECUTION=false
TEST_TIMEOUT=300

# テスト結果を格納する連想配列
declare -A TEST_RESULTS
declare -A TEST_DETAILS
declare -A TEST_DURATIONS
declare -A SECURITY_CONFIGS

# グローバル統計
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

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
        -p|--parallel)
            PARALLEL_EXECUTION=true
            shift
            ;;
        -t|--timeout)
            TEST_TIMEOUT="$2"
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
    log_master "依存関係を確認中..."
    
    local deps=("terraform" "aws" "curl" "jq" "timeout")
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
    local test_scripts=("test_infrastructure.sh" "test_vulnerabilities.sh" "test_security_pipeline.sh")
    for script in "${test_scripts[@]}"; do
        if [[ ! -f "$SCRIPT_DIR/$script" ]]; then
            log_error "テストスクリプトが見つかりません: $script"
            exit 1
        fi
        
        if [[ ! -x "$SCRIPT_DIR/$script" ]]; then
            chmod +x "$SCRIPT_DIR/$script"
        fi
    done
    
    # レポートディレクトリの作成
    mkdir -p "$REPORT_DIR"
    
    log_success "すべての依存関係が確認されました"
}

# セキュリティレベルの解析
parse_security_levels() {
    log_master "セキュリティレベルを解析中..."
    
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
}# セキュ
リティレベル設定の定義
define_security_configs() {
    log_master "セキュリティレベル設定を定義中..."
    
    SECURITY_CONFIGS[1]="基本設定のみ - WAF無効、CloudFront無効、Shield Standard"
    SECURITY_CONFIGS[2]="WAF有効 - 基本的なWeb攻撃保護、レート制限"
    SECURITY_CONFIGS[3]="WAF + Shield Advanced - 高度なDDoS保護、脅威インテリジェンス"
    SECURITY_CONFIGS[4]="完全保護 - CloudFront + WAF + Shield Advanced"
    
    log_success "セキュリティレベル設定が定義されました"
}

# Terraformデプロイメント
deploy_security_level() {
    local level=$1
    local start_time=$(date +%s)
    
    log_master "セキュリティレベル $level をデプロイ中..."
    log_info "設定: ${SECURITY_CONFIGS[$level]}"
    
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
        if ! timeout $TEST_TIMEOUT terraform init; then
            log_error "Terraform初期化に失敗しました"
            return 1
        fi
    fi
    
    # Terraformプラン
    log_info "Terraformプランを作成中..."
    if ! timeout $TEST_TIMEOUT terraform plan -out="level_${level}.tfplan" -var="security_level=${level}" -var="aws_region=${AWS_REGION}"; then
        log_error "Terraformプランの作成に失敗しました"
        return 1
    fi
    
    # Terraform適用
    log_info "Terraformを適用中..."
    if ! timeout $((TEST_TIMEOUT * 2)) terraform apply -auto-approve "level_${level}.tfplan"; then
        log_error "Terraformの適用に失敗しました"
        return 1
    fi
    
    # デプロイメント完了の待機
    log_info "デプロイメント完了を待機中..."
    sleep 60
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    TEST_DURATIONS["deploy_level_${level}"]=$duration
    
    log_success "セキュリティレベル $level のデプロイが完了しました (${duration}秒)"
    return 0
}

# インフラストラクチャテストの実行
run_infrastructure_test() {
    local level=$1
    local start_time=$(date +%s)
    
    log_master "セキュリティレベル $level のインフラストラクチャテストを実行中..."
    
    local test_output_file="$REPORT_DIR/infra_test_level_${level}.log"
    local test_result
    
    if $VERBOSE; then
        timeout $TEST_TIMEOUT "$SCRIPT_DIR/test_infrastructure.sh" --level "$level" --region "$AWS_REGION" 2>&1 | tee "$test_output_file"
        test_result=${PIPESTATUS[0]}
    else
        timeout $TEST_TIMEOUT "$SCRIPT_DIR/test_infrastructure.sh" --level "$level" --region "$AWS_REGION" > "$test_output_file" 2>&1
        test_result=$?
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    TEST_DURATIONS["infra_level_${level}"]=$duration
    
    TEST_DETAILS["infra_level_${level}"]=$(cat "$test_output_file")
    
    if [[ $test_result -eq 0 ]]; then
        TEST_RESULTS["infra_level_${level}"]="PASS"
        log_success "インフラストラクチャテスト (レベル $level): PASS (${duration}秒)"
        ((PASSED_TESTS++))
    elif [[ $test_result -eq 124 ]]; then
        TEST_RESULTS["infra_level_${level}"]="TIMEOUT"
        log_error "インフラストラクチャテスト (レベル $level): TIMEOUT (${TEST_TIMEOUT}秒)"
        ((FAILED_TESTS++))
    else
        TEST_RESULTS["infra_level_${level}"]="FAIL"
        log_error "インフラストラクチャテスト (レベル $level): FAIL (${duration}秒)"
        ((FAILED_TESTS++))
    fi
    
    ((TOTAL_TESTS++))
    return $test_result
}

# 脆弱性テストの実行
run_vulnerability_test() {
    local level=$1
    local start_time=$(date +%s)
    
    log_master "セキュリティレベル $level の脆弱性テストを実行中..."
    
    local test_output_file="$REPORT_DIR/vuln_test_level_${level}.log"
    local test_result
    
    if $VERBOSE; then
        timeout $TEST_TIMEOUT "$SCRIPT_DIR/test_vulnerabilities.sh" --test all 2>&1 | tee "$test_output_file"
        test_result=${PIPESTATUS[0]}
    else
        timeout $TEST_TIMEOUT "$SCRIPT_DIR/test_vulnerabilities.sh" --test all > "$test_output_file" 2>&1
        test_result=$?
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    TEST_DURATIONS["vuln_level_${level}"]=$duration
    
    TEST_DETAILS["vuln_level_${level}"]=$(cat "$test_output_file")
    
    # 脆弱性テストでは、脆弱性が見つかることが期待される（学習環境）
    if [[ $test_result -eq 1 ]]; then
        TEST_RESULTS["vuln_level_${level}"]="PASS"
        log_success "脆弱性テスト (レベル $level): PASS - 脆弱性が確認されました (${duration}秒)"
        ((PASSED_TESTS++))
    elif [[ $test_result -eq 124 ]]; then
        TEST_RESULTS["vuln_level_${level}"]="TIMEOUT"
        log_error "脆弱性テスト (レベル $level): TIMEOUT (${TEST_TIMEOUT}秒)"
        ((FAILED_TESTS++))
    elif [[ $test_result -eq 0 ]]; then
        TEST_RESULTS["vuln_level_${level}"]="FAIL"
        log_warning "脆弱性テスト (レベル $level): FAIL - 脆弱性が検出されませんでした (${duration}秒)"
        ((FAILED_TESTS++))
    else
        TEST_RESULTS["vuln_level_${level}"]="ERROR"
        log_error "脆弱性テスト (レベル $level): ERROR (${duration}秒)"
        ((FAILED_TESTS++))
    fi
    
    ((TOTAL_TESTS++))
    return 0
}

# DDoS攻撃シミュレーション
run_ddos_simulation() {
    local level=$1
    local start_time=$(date +%s)
    
    log_master "セキュリティレベル $level でDDoS攻撃シミュレーションを実行中..."
    
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
        TEST_RESULTS["ddos_level_${level}"]="ERROR"
        TEST_DETAILS["ddos_level_${level}"]="ターゲットURLの取得に失敗"
        ((FAILED_TESTS++))
        ((TOTAL_TESTS++))
        return 1
    fi
    
    log_info "DDoS攻撃対象: $target_url"
    
    # 基準パフォーマンスの測定
    log_info "基準パフォーマンスを測定中..."
    local baseline_time=$(timeout 10 curl -s -o /dev/null -w "%{time_total}" "$target_url" 2>/dev/null || echo "999")
    log_info "基準レスポンス時間: ${baseline_time}秒"
    
    # DDoS攻撃の実行
    log_info "DDoS攻撃を開始中..."
    local attack_duration=30
    local concurrent_requests=100
    
    # 攻撃スクリプトの実行
    if [[ -f "$SCRIPT_DIR/ddos_simulation.sh" ]]; then
        timeout $TEST_TIMEOUT "$SCRIPT_DIR/ddos_simulation.sh" "$target_url" "$concurrent_requests" "$attack_duration" > "$REPORT_DIR/ddos_level_${level}.log" 2>&1
    else
        # 簡易DDoS攻撃の実行
        {
            for i in $(seq 1 $concurrent_requests); do
                {
                    for j in $(seq 1 $attack_duration); do
                        timeout 5 curl -s "$target_url" > /dev/null 2>&1 &
                        sleep 1
                    done
                } &
            done
            wait
        } > "$REPORT_DIR/ddos_level_${level}.log" 2>&1
    fi
    
    # 攻撃中のパフォーマンス測定
    sleep 5
    local attack_time=$(timeout 10 curl -s -o /dev/null -w "%{time_total}" "$target_url" 2>/dev/null || echo "999")
    log_info "攻撃中レスポンス時間: ${attack_time}秒"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    TEST_DURATIONS["ddos_level_${level}"]=$duration
    
    # 結果の評価
    local performance_degradation=0
    if (( $(echo "$attack_time > $baseline_time * 2" | bc -l 2>/dev/null || echo "0") )); then
        performance_degradation=1
    fi
    
    local test_details="基準時間: ${baseline_time}秒, 攻撃中時間: ${attack_time}秒, パフォーマンス劣化: $([[ $performance_degradation -eq 1 ]] && echo "あり" || echo "なし")"
    TEST_DETAILS["ddos_level_${level}"]="$test_details"
    
    case $level in
        1|2)
            if [[ $performance_degradation -eq 1 ]]; then
                TEST_RESULTS["ddos_level_${level}"]="PASS"
                log_success "DDoS攻撃シミュレーション (レベル $level): PASS - 期待通りパフォーマンス劣化 (${duration}秒)"
                ((PASSED_TESTS++))
            else
                TEST_RESULTS["ddos_level_${level}"]="FAIL"
                log_warning "DDoS攻撃シミュレーション (レベル $level): FAIL - 攻撃効果が不十分 (${duration}秒)"
                ((FAILED_TESTS++))
            fi
            ;;
        3|4)
            if [[ $performance_degradation -eq 0 ]]; then
                TEST_RESULTS["ddos_level_${level}"]="PASS"
                log_success "DDoS攻撃シミュレーション (レベル $level): PASS - 適切に保護されています (${duration}秒)"
                ((PASSED_TESTS++))
            else
                TEST_RESULTS["ddos_level_${level}"]="FAIL"
                log_warning "DDoS攻撃シミュレーション (レベル $level): FAIL - 保護が不十分 (${duration}秒)"
                ((FAILED_TESTS++))
            fi
            ;;
    esac
    
    ((TOTAL_TESTS++))
    return 0
}

# セキュリティレベルの完全テスト
test_security_level() {
    local level=$1
    log_master "セキュリティレベル $level の完全テストを開始します"
    log_info "設定: ${SECURITY_CONFIGS[$level]}"
    
    # デプロイメント（スキップされていない場合）
    if ! $SKIP_DEPLOYMENT; then
        if ! deploy_security_level "$level"; then
            log_error "セキュリティレベル $level のデプロイに失敗しました"
            # デプロイ失敗時は該当レベルのテストをスキップ
            TEST_RESULTS["infra_level_${level}"]="SKIPPED"
            TEST_RESULTS["vuln_level_${level}"]="SKIPPED"
            TEST_RESULTS["ddos_level_${level}"]="SKIPPED"
            ((SKIPPED_TESTS += 3))
            ((TOTAL_TESTS += 3))
            return 1
        fi
    fi
    
    # テストの実行
    if $PARALLEL_EXECUTION; then
        # 並列実行
        run_infrastructure_test "$level" &
        local infra_pid=$!
        
        run_vulnerability_test "$level" &
        local vuln_pid=$!
        
        run_ddos_simulation "$level" &
        local ddos_pid=$!
        
        # 全テストの完了を待機
        wait $infra_pid $vuln_pid $ddos_pid
    else
        # 順次実行
        run_infrastructure_test "$level"
        run_vulnerability_test "$level"
        run_ddos_simulation "$level"
    fi
    
    log_success "セキュリティレベル $level のテストが完了しました"
    return 0
}#
 JSONレポートの生成
generate_json_report() {
    log_master "JSONレポートを生成中..."
    
    local json_file="$REPORT_DIR/master_security_test_report.json"
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    cat > "$json_file" << EOF
{
  "test_execution": {
    "timestamp": "$timestamp",
    "security_levels_tested": [$(printf '%s,' "${LEVELS[@]}" | sed 's/,$//')]
    "aws_region": "$AWS_REGION",
    "parallel_execution": $PARALLEL_EXECUTION,
    "test_timeout": $TEST_TIMEOUT
  },
  "summary": {
    "total_tests": $TOTAL_TESTS,
    "passed_tests": $PASSED_TESTS,
    "failed_tests": $FAILED_TESTS,
    "skipped_tests": $SKIPPED_TESTS,
    "success_rate": $(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l 2>/dev/null || echo "0")
  },
  "security_configurations": {
EOF
    
    # セキュリティ設定の追加
    local first_config=true
    for level in "${LEVELS[@]}"; do
        if ! $first_config; then
            echo "," >> "$json_file"
        fi
        first_config=false
        
        echo "    \"level_$level\": \"${SECURITY_CONFIGS[$level]}\"" >> "$json_file"
    done
    
    echo "  }," >> "$json_file"
    echo "  \"test_results\": {" >> "$json_file"
    
    # テスト結果の追加
    local first_result=true
    for key in $(printf '%s\n' "${!TEST_RESULTS[@]}" | sort); do
        if ! $first_result; then
            echo "," >> "$json_file"
        fi
        first_result=false
        
        local status="${TEST_RESULTS[$key]}"
        local details="${TEST_DETAILS[$key]:-""}"
        local duration="${TEST_DURATIONS[$key]:-0}"
        
        cat >> "$json_file" << EOF
    "$key": {
      "status": "$status",
      "duration_seconds": $duration,
      "details": "$(echo "$details" | sed 's/"/\\"/g' | tr '\n' ' ' | head -c 500)"
    }
EOF
    done
    
    echo "" >> "$json_file"
    echo "  }" >> "$json_file"
    echo "}" >> "$json_file"
    
    log_success "JSONレポートが生成されました: $json_file"
}

# CSVレポートの生成
generate_csv_report() {
    log_master "CSVレポートを生成中..."
    
    local csv_file="$REPORT_DIR/master_security_test_report.csv"
    
    # CSVヘッダーの作成
    echo "Test_Type,Security_Level,Status,Duration_Seconds,Details" > "$csv_file"
    
    # テスト結果の追加
    for key in $(printf '%s\n' "${!TEST_RESULTS[@]}" | sort); do
        local test_type=$(echo "$key" | cut -d'_' -f1)
        local security_level=$(echo "$key" | cut -d'_' -f3)
        local status="${TEST_RESULTS[$key]}"
        local duration="${TEST_DURATIONS[$key]:-0}"
        local details="${TEST_DETAILS[$key]:-""}"
        
        # CSVエスケープ処理
        details=$(echo "$details" | sed 's/"/\\"/g' | tr '\n' ' ' | head -c 200)
        
        echo "\"$test_type\",\"$security_level\",\"$status\",$duration,\"$details\"" >> "$csv_file"
    done
    
    log_success "CSVレポートが生成されました: $csv_file"
}

# HTMLレポートの生成
generate_html_report() {
    log_master "HTMLレポートを生成中..."
    
    local html_file="$REPORT_DIR/master_security_test_report.html"
    local timestamp=$(date '+%Y年%m月%d日 %H:%M:%S')
    
    cat > "$html_file" << 'EOF'
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS GameDay マスターセキュリティテストレポート</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            line-height: 1.6;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.8em;
            font-weight: 300;
        }
        .header p {
            margin: 15px 0 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background-color: #f8f9fa;
        }
        .summary-item {
            text-align: center;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .summary-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 8px;
        }
        .summary-label {
            color: #666;
            font-size: 0.95em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .pass { color: #28a745; }
        .fail { color: #dc3545; }
        .timeout { color: #fd7e14; }
        .skip { color: #6c757d; }
        .content {
            padding: 40px;
        }
        .level-section {
            margin-bottom: 50px;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            overflow: hidden;
        }
        .level-header {
            background: linear-gradient(90deg, #495057 0%, #6c757d 100%);
            color: white;
            padding: 20px;
            font-size: 1.3em;
            font-weight: 500;
        }
        .level-config {
            background: #e9ecef;
            padding: 15px 20px;
            font-style: italic;
            color: #495057;
        }
        .test-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            padding: 20px;
        }
        .test-card {
            border: 1px solid #dee2e6;
            border-radius: 8px;
            background-color: #fff;
            overflow: hidden;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .test-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        .test-card-header {
            padding: 15px 20px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .test-card h3 {
            margin: 0;
            color: #333;
            font-size: 1.1em;
        }
        .status-badge {
            display: inline-block;
            padding: 6px 12px;
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
        .status-timeout {
            background-color: #fff3cd;
            color: #856404;
        }
        .status-skipped {
            background-color: #e2e3e5;
            color: #383d41;
        }
        .test-card-body {
            padding: 20px;
        }
        .duration {
            color: #6c757d;
            font-size: 0.9em;
            margin-bottom: 10px;
        }
        .details {
            background-color: #f8f9fa;
            border-radius: 4px;
            padding: 12px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            max-height: 150px;
            overflow-y: auto;
            border-left: 4px solid #007bff;
        }
        .footer {
            text-align: center;
            padding: 30px;
            color: #666;
            border-top: 1px solid #eee;
            background: #f8f9fa;
        }
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
            margin: 10px 0;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #28a745 0%, #20c997 100%);
            transition: width 0.3s ease;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AWS GameDay マスターセキュリティテストレポート</h1>
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
            <div class="summary-item">
                <div class="summary-number skip">SKIPPED_TESTS_PLACEHOLDER</div>
                <div class="summary-label">スキップ</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">SUCCESS_RATE_PLACEHOLDER%</div>
                <div class="summary-label">成功率</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: SUCCESS_RATE_PLACEHOLDER%"></div>
                </div>
            </div>
        </div>
        
        <div class="content">
            TEST_RESULTS_PLACEHOLDER
        </div>
        
        <div class="footer">
            <p>AWS GameDay "Winning the DDoS Game" 環境 - マスターセキュリティテストレポート</p>
            <p>このレポートは自動生成されました</p>
        </div>
    </div>
</body>
</html>
EOF
    
    # プレースホルダーの置換
    local success_rate=$(echo "scale=1; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l 2>/dev/null || echo "0")
    
    sed -i.bak "s/TIMESTAMP_PLACEHOLDER/$timestamp/g" "$html_file"
    sed -i.bak "s/TOTAL_TESTS_PLACEHOLDER/$TOTAL_TESTS/g" "$html_file"
    sed -i.bak "s/PASSED_TESTS_PLACEHOLDER/$PASSED_TESTS/g" "$html_file"
    sed -i.bak "s/FAILED_TESTS_PLACEHOLDER/$FAILED_TESTS/g" "$html_file"
    sed -i.bak "s/SKIPPED_TESTS_PLACEHOLDER/$SKIPPED_TESTS/g" "$html_file"
    sed -i.bak "s/SUCCESS_RATE_PLACEHOLDER/$success_rate/g" "$html_file"
    
    # テスト結果の生成
    local test_results_html=""
    
    # セキュリティレベル別にグループ化
    for level in "${LEVELS[@]}"; do
        test_results_html+="<div class=\"level-section\">
            <div class=\"level-header\">セキュリティレベル $level</div>
            <div class=\"level-config\">${SECURITY_CONFIGS[$level]}</div>
            <div class=\"test-grid\">"
        
        # 各テストタイプの結果を追加
        local test_types=("infra" "vuln" "ddos")
        local test_names=("インフラストラクチャテスト" "脆弱性テスト" "DDoS攻撃シミュレーション")
        
        for i in "${!test_types[@]}"; do
            local test_type="${test_types[$i]}"
            local test_name="${test_names[$i]}"
            local key="${test_type}_level_${level}"
            
            local status="${TEST_RESULTS[$key]:-"N/A"}"
            local duration="${TEST_DURATIONS[$key]:-0}"
            local details="${TEST_DETAILS[$key]:-"詳細なし"}"
            
            local badge_class="status-$(echo "$status" | tr '[:upper:]' '[:lower:]')"
            
            # 詳細を短縮
            local short_details=$(echo "$details" | head -c 300)
            if [[ ${#details} -gt 300 ]]; then
                short_details="${short_details}..."
            fi
            
            test_results_html+="<div class=\"test-card\">
                <div class=\"test-card-header\">
                    <h3>$test_name</h3>
                    <span class=\"status-badge $badge_class\">$status</span>
                </div>
                <div class=\"test-card-body\">
                    <div class=\"duration\">実行時間: ${duration}秒</div>
                    <div class=\"details\">$(echo "$short_details" | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g')</div>
                </div>
            </div>"
        done
        
        test_results_html+="</div></div>"
    done
    
    # HTMLファイルに結果を挿入
    sed -i.bak "s|TEST_RESULTS_PLACEHOLDER|$test_results_html|g" "$html_file"
    
    # バックアップファイルの削除
    rm -f "${html_file}.bak"
    
    log_success "HTMLレポートが生成されました: $html_file"
}# リソ
ースのクリーンアップ
cleanup_resources() {
    log_master "リソースをクリーンアップ中..."
    
    if [[ ! -d "$TERRAFORM_DIR" ]]; then
        log_error "Terraformディレクトリが見つかりません: $TERRAFORM_DIR"
        return 1
    fi
    
    cd "$TERRAFORM_DIR"
    
    log_info "Terraformリソースを削除中..."
    if timeout $((TEST_TIMEOUT * 2)) terraform destroy -auto-approve; then
        log_success "リソースのクリーンアップが完了しました"
    else
        log_error "リソースのクリーンアップに失敗しました"
        return 1
    fi
    
    # 一時ファイルのクリーンアップ
    log_info "一時ファイルをクリーンアップ中..."
    rm -f "$TERRAFORM_DIR"/*.tfplan
    
    return 0
}

# テストサイクルのリセット
reset_test_cycle() {
    log_master "テストサイクルをリセット中..."
    
    # テスト結果のクリア
    unset TEST_RESULTS
    unset TEST_DETAILS
    unset TEST_DURATIONS
    declare -gA TEST_RESULTS
    declare -gA TEST_DETAILS
    declare -gA TEST_DURATIONS
    
    # 統計のリセット
    TOTAL_TESTS=0
    PASSED_TESTS=0
    FAILED_TESTS=0
    SKIPPED_TESTS=0
    
    # 古いレポートファイルの削除
    if [[ -d "$REPORT_DIR" ]]; then
        find "$REPORT_DIR" -name "*.log" -mtime +7 -delete 2>/dev/null || true
        find "$REPORT_DIR" -name "*.html" -mtime +7 -delete 2>/dev/null || true
        find "$REPORT_DIR" -name "*.json" -mtime +7 -delete 2>/dev/null || true
        find "$REPORT_DIR" -name "*.csv" -mtime +7 -delete 2>/dev/null || true
    fi
    
    log_success "テストサイクルがリセットされました"
}

# レポート生成の統合関数
generate_reports() {
    log_master "テストレポートを生成中..."
    
    case $OUTPUT_FORMAT in
        "json")
            generate_json_report
            ;;
        "csv")
            generate_csv_report
            ;;
        "html")
            generate_html_report
            ;;
        "all")
            generate_json_report
            generate_csv_report
            generate_html_report
            ;;
        *)
            log_error "不明なレポート形式: $OUTPUT_FORMAT"
            return 1
            ;;
    esac
    
    log_success "すべてのレポートが生成されました"
}

# テスト実行の統計表示
display_test_statistics() {
    log_master "テスト実行統計:"
    log_info "総テスト数: $TOTAL_TESTS"
    log_success "成功: $PASSED_TESTS"
    log_error "失敗: $FAILED_TESTS"
    log_warning "スキップ: $SKIPPED_TESTS"
    
    if [[ $TOTAL_TESTS -gt 0 ]]; then
        local success_rate=$(echo "scale=1; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l 2>/dev/null || echo "0")
        log_info "成功率: ${success_rate}%"
    fi
    
    # 実行時間の統計
    local total_duration=0
    for duration in "${TEST_DURATIONS[@]}"; do
        total_duration=$((total_duration + duration))
    done
    
    log_info "総実行時間: ${total_duration}秒"
    
    # レベル別統計
    for level in "${LEVELS[@]}"; do
        local level_passed=0
        local level_total=0
        
        for test_type in "infra" "vuln" "ddos"; do
            local key="${test_type}_level_${level}"
            if [[ -n "${TEST_RESULTS[$key]}" ]]; then
                ((level_total++))
                if [[ "${TEST_RESULTS[$key]}" == "PASS" ]]; then
                    ((level_passed++))
                fi
            fi
        done
        
        if [[ $level_total -gt 0 ]]; then
            local level_rate=$(echo "scale=1; $level_passed * 100 / $level_total" | bc -l 2>/dev/null || echo "0")
            log_info "レベル $level 成功率: ${level_rate}% ($level_passed/$level_total)"
        fi
    done
}

# メイン実行関数
main() {
    local start_time=$(date +%s)
    
    log_master "AWS GameDay マスターセキュリティテストを開始します"
    log_info "セキュリティレベル: $SECURITY_LEVELS"
    log_info "AWSリージョン: $AWS_REGION"
    log_info "並列実行: $PARALLEL_EXECUTION"
    log_info "テストタイムアウト: ${TEST_TIMEOUT}秒"
    log_info "出力形式: $OUTPUT_FORMAT"
    
    # 初期化
    > "$LOG_FILE"
    
    # 依存関係の確認
    check_dependencies
    
    # セキュリティレベルの解析
    parse_security_levels
    
    # セキュリティ設定の定義
    define_security_configs
    
    # テストサイクルのリセット
    reset_test_cycle
    
    # 各セキュリティレベルのテスト実行
    for level in "${LEVELS[@]}"; do
        test_security_level "$level"
    done
    
    # レポートの生成
    generate_reports
    
    # 統計の表示
    display_test_statistics
    
    # クリーンアップ（要求された場合）
    if $CLEANUP_AFTER_TEST; then
        cleanup_resources
    fi
    
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    # 最終結果の表示
    log_master "マスターセキュリティテスト完了"
    log_info "総実行時間: ${total_duration}秒"
    
    # レポートファイルの場所を表示
    if [[ "$OUTPUT_FORMAT" == "html" ]] || [[ "$OUTPUT_FORMAT" == "all" ]]; then
        log_info "HTMLレポート: $REPORT_DIR/master_security_test_report.html"
    fi
    
    if [[ "$OUTPUT_FORMAT" == "json" ]] || [[ "$OUTPUT_FORMAT" == "all" ]]; then
        log_info "JSONレポート: $REPORT_DIR/master_security_test_report.json"
    fi
    
    if [[ "$OUTPUT_FORMAT" == "csv" ]] || [[ "$OUTPUT_FORMAT" == "all" ]]; then
        log_info "CSVレポート: $REPORT_DIR/master_security_test_report.csv"
    fi
    
    # 終了コードの決定
    if [[ $FAILED_TESTS -eq 0 ]]; then
        log_success "すべてのテストが成功しました"
        exit 0
    else
        log_warning "$FAILED_TESTS 個のテストが失敗しました"
        exit 1
    fi
}

# トラップでクリーンアップを確実に実行
trap 'log_error "スクリプトが中断されました"; cleanup_resources 2>/dev/null || true' INT TERM

# スクリプトの実行
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi