#!/bin/bash

# エンドツーエンドテスト実行検証スクリプト（簡易版）
# テスト実行前の環境チェックと実行後の結果検証

set -e

# 設定
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/validate_e2e_execution.log"
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

log_validate() {
    echo -e "${PURPLE}[VALIDATE]${NC} $1" | tee -a "$LOG_FILE"
}

# 使用方法
usage() {
    echo "使用方法: $0 [オプション] [モード]"
    echo ""
    echo "エンドツーエンドテスト実行の検証スクリプト"
    echo ""
    echo "モード:"
    echo "  pre-check     実行前の環境チェック"
    echo "  post-check    実行後の結果検証"
    echo "  full-check    実行前後の完全チェック"
    echo ""
    echo "オプション:"
    echo "  -r, --region REGION  AWSリージョン (デフォルト: us-east-1)"
    echo "  -v, --verbose        詳細出力を有効にする"
    echo "  -f, --fix           自動修正を試行する"
    echo "  -h, --help          このヘルプメッセージを表示"
}

# デフォルト値
MODE="full-check"
AWS_REGION="us-east-1"
VERBOSE=false
AUTO_FIX=false

# 検証結果カウンタ
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# コマンドライン引数の解析
while [[ $# -gt 0 ]]; do
    case $1 in
        pre-check|post-check|full-check)
            MODE="$1"
            shift
            ;;
        -r|--region)
            AWS_REGION="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -f|--fix)
            AUTO_FIX=true
            shift
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

# 検証結果の記録
record_check_result() {
    local check_name="$1"
    local result="$2"
    local message="$3"
    
    ((TOTAL_CHECKS++))
    
    case $result in
        "PASS")
            ((PASSED_CHECKS++))
            log_success "$check_name: $message"
            ;;
        "FAIL")
            ((FAILED_CHECKS++))
            log_error "$check_name: $message"
            ;;
        "WARNING")
            ((WARNING_CHECKS++))
            log_warning "$check_name: $message"
            ;;
    esac
}

# 実行前環境チェック
pre_execution_checks() {
    log_validate "実行前環境チェックを開始します"
    
    # 1. 必須ツールの確認
    log_info "必須ツールを確認中..."
    local required_tools=("terraform" "aws" "curl" "jq")
    
    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            record_check_result "tool_$tool" "PASS" "$tool が利用可能"
        else
            record_check_result "tool_$tool" "FAIL" "$tool が見つかりません"
        fi
    done
    
    # 2. AWS認証情報の確認
    log_info "AWS認証情報を確認中..."
    if aws sts get-caller-identity &> /dev/null; then
        local account_id=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || echo "不明")
        record_check_result "aws_auth" "PASS" "AWS認証成功 (Account: $account_id)"
    else
        record_check_result "aws_auth" "FAIL" "AWS認証情報が設定されていません"
    fi
    
    # 3. Terraformプロジェクト構造の確認
    log_info "Terraformプロジェクト構造を確認中..."
    if [[ -d "$TERRAFORM_DIR" ]]; then
        record_check_result "terraform_dir" "PASS" "Terraformディレクトリが存在します"
        
        local required_tf_files=("main.tf" "variables.tf" "outputs.tf")
        for tf_file in "${required_tf_files[@]}"; do
            if [[ -f "$TERRAFORM_DIR/$tf_file" ]]; then
                record_check_result "tf_file_$tf_file" "PASS" "$tf_file が存在します"
            else
                record_check_result "tf_file_$tf_file" "FAIL" "$tf_file が見つかりません"
            fi
        done
    else
        record_check_result "terraform_dir" "FAIL" "Terraformディレクトリが見つかりません"
    fi
    
    # 4. 必要なスクリプトの確認
    log_info "必要なスクリプトを確認中..."
    local required_scripts=(
        "master_security_test.sh"
        "test_infrastructure.sh"
        "comprehensive_e2e_test.sh"
        "run_end_to_end_tests.sh"
    )
    
    for script in "${required_scripts[@]}"; do
        if [[ -f "$SCRIPT_DIR/$script" ]]; then
            if [[ -x "$SCRIPT_DIR/$script" ]]; then
                record_check_result "script_$script" "PASS" "$script が実行可能です"
            else
                record_check_result "script_$script" "WARNING" "$script に実行権限がありません"
                if $AUTO_FIX; then
                    chmod +x "$SCRIPT_DIR/$script"
                    log_info "$script に実行権限を付与しました"
                fi
            fi
        else
            record_check_result "script_$script" "FAIL" "$script が見つかりません"
        fi
    done
    
    log_validate "実行前環境チェックが完了しました"
}

# 実行後結果検証
post_execution_checks() {
    log_validate "実行後結果検証を開始します"
    
    # 1. レポートファイルの確認
    log_info "生成されたレポートファイルを確認中..."
    local report_dir="$SCRIPT_DIR/reports"
    
    if [[ -d "$report_dir" ]]; then
        record_check_result "report_dir" "PASS" "レポートディレクトリが存在します"
        
        local expected_reports=("master_security_test_report.json" "comprehensive_e2e_test_report.md")
        for report in "${expected_reports[@]}"; do
            if [[ -f "$report_dir/$report" ]]; then
                local file_size=$(wc -c < "$report_dir/$report" 2>/dev/null || echo "0")
                if [[ $file_size -gt 0 ]]; then
                    record_check_result "report_$report" "PASS" "$report が生成されました (${file_size}バイト)"
                else
                    record_check_result "report_$report" "FAIL" "$report が空です"
                fi
            else
                record_check_result "report_$report" "WARNING" "$report が見つかりません"
            fi
        done
    else
        record_check_result "report_dir" "WARNING" "レポートディレクトリが見つかりません"
    fi
    
    # 2. Terraform状態の確認
    log_info "Terraform状態を確認中..."
    if [[ -d "$TERRAFORM_DIR" ]]; then
        if [[ -f "$TERRAFORM_DIR/.terraform.lock.hcl" ]]; then
            record_check_result "terraform_lock" "PASS" "Terraformロックファイルが存在します"
        else
            record_check_result "terraform_lock" "WARNING" "Terraformロックファイルが見つかりません"
        fi
    fi
    
    log_validate "実行後結果検証が完了しました"
}

# 検証結果の表示
display_validation_results() {
    log_validate "検証結果サマリー:"
    log_info "総チェック数: $TOTAL_CHECKS"
    log_success "成功: $PASSED_CHECKS"
    log_warning "警告: $WARNING_CHECKS"
    log_error "失敗: $FAILED_CHECKS"
    
    if [[ $TOTAL_CHECKS -gt 0 ]]; then
        local success_rate=$(echo "scale=1; $PASSED_CHECKS * 100 / $TOTAL_CHECKS" | bc -l 2>/dev/null || echo "0")
        log_info "成功率: ${success_rate}%"
    fi
    
    # 推奨事項の表示
    if [[ $FAILED_CHECKS -gt 0 ]] || [[ $WARNING_CHECKS -gt 0 ]]; then
        echo ""
        log_validate "推奨事項:"
        
        if [[ $FAILED_CHECKS -gt 0 ]]; then
            log_error "失敗したチェックがあります。以下を確認してください:"
            log_error "- 必要なツールがインストールされているか"
            log_error "- AWS認証情報が正しく設定されているか"
            log_error "- 必要なファイルとスクリプトが存在するか"
        fi
        
        if [[ $WARNING_CHECKS -gt 0 ]]; then
            log_warning "警告があります。以下を検討してください:"
            log_warning "- スクリプトの実行権限の確認"
            log_warning "- レポートファイルの生成状況の確認"
        fi
    else
        log_success "すべてのチェックが成功しました！"
    fi
}

# メイン実行関数
main() {
    log_validate "エンドツーエンドテスト実行検証を開始します"
    log_info "モード: $MODE"
    log_info "AWSリージョン: $AWS_REGION"
    log_info "自動修正: $AUTO_FIX"
    
    # 初期化
    > "$LOG_FILE"
    
    # モードに応じた実行
    case $MODE in
        "pre-check")
            pre_execution_checks
            ;;
        "post-check")
            post_execution_checks
            ;;
        "full-check")
            pre_execution_checks
            echo ""
            post_execution_checks
            ;;
        *)
            log_error "不明なモード: $MODE"
            exit 1
            ;;
    esac
    
    # 結果の表示
    display_validation_results
    
    # 終了コードの決定
    if [[ $FAILED_CHECKS -gt 0 ]]; then
        log_error "検証に失敗しました"
        exit 1
    elif [[ $WARNING_CHECKS -gt 0 ]]; then
        log_warning "検証で警告が発生しました"
        exit 2
    else
        log_success "検証が正常に完了しました"
        exit 0
    fi
}

# スクリプトの実行
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi