#!/bin/bash

# エンドツーエンドセキュリティテスト実行スクリプト
# マスターテスト、レポート生成、クリーンアップの統合実行

set -e

# 設定
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/end_to_end_test.log"

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

log_e2e() {
    echo -e "${PURPLE}[E2E]${NC} $1" | tee -a "$LOG_FILE"
}

# 使用方法
usage() {
    echo "使用方法: $0 [オプション]"
    echo ""
    echo "このスクリプトは以下の処理を順次実行します:"
    echo "1. マスターセキュリティテストの実行"
    echo "2. 詳細レポートの生成"
    echo "3. 自動クリーンアップ（オプション）"
    echo ""
    echo "オプション:"
    echo "  -l, --levels LEVELS  テストするセキュリティレベル (1,2,3,4 または all, デフォルト: all)"
    echo "  -r, --region REGION  AWSリージョン (デフォルト: us-east-1)"
    echo "  -c, --cleanup        テスト後にリソースをクリーンアップ"
    echo "  -s, --skip-deploy    デプロイメントをスキップ（既存環境を使用）"
    echo "  -p, --parallel       並列テスト実行を有効にする"
    echo "  -t, --timeout SEC    各テストのタイムアウト秒数 (デフォルト: 300)"
    echo "  -o, --output FORMAT  レポート形式 (html|json|csv|all, デフォルト: all)"
    echo "  -f, --force          確認なしで実行"
    echo "  -v, --verbose        詳細出力を有効にする"
    echo "  --report-only        テストをスキップしてレポートのみ生成"
    echo "  --cleanup-only       クリーンアップのみ実行"
    echo "  --comprehensive      包括的エンドツーエンドテストを実行"
    echo "  -h, --help          このヘルプメッセージを表示"
    echo ""
    echo "例:"
    echo "  $0 --levels 1,2,3 --cleanup --parallel"
    echo "  $0 --skip-deploy --output html --verbose"
    echo "  $0 --report-only --output all"
    echo "  $0 --cleanup-only --force"
    echo "  $0 --comprehensive --cleanup --verbose"
}

# デフォルト値
SECURITY_LEVELS="all"
AWS_REGION="us-east-1"
CLEANUP_AFTER_TEST=false
SKIP_DEPLOYMENT=false
PARALLEL_EXECUTION=false
TEST_TIMEOUT=300
OUTPUT_FORMAT="all"
FORCE_EXECUTION=false
VERBOSE=false
REPORT_ONLY=false
CLEANUP_ONLY=false
COMPREHENSIVE_MODE=false

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
        -p|--parallel)
            PARALLEL_EXECUTION=true
            shift
            ;;
        -t|--timeout)
            TEST_TIMEOUT="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        -f|--force)
            FORCE_EXECUTION=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --report-only)
            REPORT_ONLY=true
            shift
            ;;
        --cleanup-only)
            CLEANUP_ONLY=true
            shift
            ;;
        --comprehensive)
            COMPREHENSIVE_MODE=true
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

# 必要なスクリプトの確認
check_scripts() {
    log_e2e "必要なスクリプトを確認中..."
    
    local required_scripts=(
        "master_security_test.sh"
        "test_report_generator.py"
        "auto_cleanup_reset.sh"
        "comprehensive_e2e_test.sh"
    )
    
    for script in "${required_scripts[@]}"; do
        if [[ ! -f "$SCRIPT_DIR/$script" ]]; then
            log_error "必要なスクリプトが見つかりません: $script"
            exit 1
        fi
        
        if [[ ! -x "$SCRIPT_DIR/$script" ]]; then
            chmod +x "$SCRIPT_DIR/$script"
        fi
    done
    
    log_success "すべての必要なスクリプトが確認されました"
}

# Python依存関係の確認
check_python_dependencies() {
    log_e2e "Python依存関係を確認中..."
    
    if ! command -v python3 &> /dev/null; then
        log_error "python3 が見つかりません。レポート生成機能が制限されます。"
        return 1
    fi
    
    # 必要なPythonパッケージの確認
    local python_packages=("matplotlib" "pandas")
    local missing_packages=()
    
    for package in "${python_packages[@]}"; do
        if ! python3 -c "import $package" &> /dev/null; then
            missing_packages+=("$package")
        fi
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        log_warning "以下のPythonパッケージが見つかりません: ${missing_packages[*]}"
        log_info "インストールするには: pip3 install ${missing_packages[*]}"
        log_info "基本的なレポート生成は継続されます"
    else
        log_success "すべてのPython依存関係が確認されました"
    fi
    
    return 0
}

# マスターセキュリティテストの実行
run_master_security_test() {
    log_e2e "マスターセキュリティテストを実行中..."
    
    local test_args=()
    test_args+=("--levels" "$SECURITY_LEVELS")
    test_args+=("--region" "$AWS_REGION")
    test_args+=("--timeout" "$TEST_TIMEOUT")
    test_args+=("--output" "$OUTPUT_FORMAT")
    
    if $CLEANUP_AFTER_TEST; then
        test_args+=("--cleanup")
    fi
    
    if $SKIP_DEPLOYMENT; then
        test_args+=("--skip-deploy")
    fi
    
    if $PARALLEL_EXECUTION; then
        test_args+=("--parallel")
    fi
    
    if $VERBOSE; then
        test_args+=("--verbose")
    fi
    
    log_info "実行コマンド: $SCRIPT_DIR/master_security_test.sh ${test_args[*]}"
    
    if "$SCRIPT_DIR/master_security_test.sh" "${test_args[@]}"; then
        log_success "マスターセキュリティテストが正常に完了しました"
        return 0
    else
        local exit_code=$?
        log_error "マスターセキュリティテストでエラーが発生しました (終了コード: $exit_code)"
        return $exit_code
    fi
}

# 詳細レポートの生成
generate_detailed_reports() {
    log_e2e "詳細レポートを生成中..."
    
    local report_dir="$SCRIPT_DIR/reports"
    local json_report="$report_dir/master_security_test_report.json"
    
    if [[ ! -f "$json_report" ]]; then
        log_error "JSONレポートファイルが見つかりません: $json_report"
        log_warning "マスターテストが実行されていない可能性があります"
        return 1
    fi
    
    # Pythonレポート生成ツールの実行
    local report_args=()
    report_args+=("$json_report")
    report_args+=("--output" "$report_dir")
    
    case $OUTPUT_FORMAT in
        "html")
            report_args+=("--format" "markdown")
            ;;
        "json")
            report_args+=("--format" "csv")
            ;;
        "csv")
            report_args+=("--format" "csv")
            ;;
        "all")
            report_args+=("--format" "all")
            ;;
    esac
    
    log_info "実行コマンド: python3 $SCRIPT_DIR/test_report_generator.py ${report_args[*]}"
    
    if python3 "$SCRIPT_DIR/test_report_generator.py" "${report_args[@]}"; then
        log_success "詳細レポートの生成が完了しました"
        
        # 生成されたファイルの一覧表示
        log_info "生成されたレポートファイル:"
        find "$report_dir" -name "*.md" -o -name "*.csv" -o -name "*.png" -newer "$json_report" 2>/dev/null | while read -r file; do
            log_info "  - $file"
        done
        
        return 0
    else
        log_warning "詳細レポートの生成でエラーが発生しましたが、処理を継続します"
        return 0
    fi
}

# 包括的エンドツーエンドテストの実行
run_comprehensive_test() {
    log_e2e "包括的エンドツーエンドテストを実行中..."
    
    local comprehensive_args=()
    comprehensive_args+=("--region" "$AWS_REGION")
    comprehensive_args+=("--timeout" "$TEST_TIMEOUT")
    
    if $CLEANUP_AFTER_TEST; then
        comprehensive_args+=("--cleanup")
    fi
    
    if $FORCE_EXECUTION; then
        comprehensive_args+=("--force")
    fi
    
    if $VERBOSE; then
        comprehensive_args+=("--verbose")
    fi
    
    if $SKIP_DEPLOYMENT; then
        comprehensive_args+=("--test-only")
    fi
    
    log_info "実行コマンド: $SCRIPT_DIR/comprehensive_e2e_test.sh ${comprehensive_args[*]}"
    
    if "$SCRIPT_DIR/comprehensive_e2e_test.sh" "${comprehensive_args[@]}"; then
        log_success "包括的エンドツーエンドテストが正常に完了しました"
        return 0
    else
        local exit_code=$?
        log_error "包括的エンドツーエンドテストでエラーが発生しました (終了コード: $exit_code)"
        return $exit_code
    fi
}

# 自動クリーンアップの実行
run_auto_cleanup() {
    log_e2e "自動クリーンアップを実行中..."
    
    local cleanup_args=()
    cleanup_args+=("--logs")
    cleanup_args+=("--cache")
    cleanup_args+=("--days" "7")
    
    if $FORCE_EXECUTION; then
        cleanup_args+=("--force")
    fi
    
    if $VERBOSE; then
        cleanup_args+=("--verbose")
    fi
    
    # Terraformクリーンアップは既にマスターテストで実行されている場合はスキップ
    if ! $CLEANUP_AFTER_TEST; then
        cleanup_args+=("--terraform")
    fi
    
    log_info "実行コマンド: $SCRIPT_DIR/auto_cleanup_reset.sh ${cleanup_args[*]}"
    
    if "$SCRIPT_DIR/auto_cleanup_reset.sh" "${cleanup_args[@]}"; then
        log_success "自動クリーンアップが正常に完了しました"
        return 0
    else
        log_warning "自動クリーンアップでエラーが発生しましたが、処理を継続します"
        return 0
    fi
}

# 実行サマリーの表示
display_execution_summary() {
    log_e2e "実行サマリー:"
    
    local report_dir="$SCRIPT_DIR/reports"
    
    # 生成されたファイルの確認
    if [[ -d "$report_dir" ]]; then
        local html_files=$(find "$report_dir" -name "*.html" 2>/dev/null | wc -l)
        local json_files=$(find "$report_dir" -name "*.json" 2>/dev/null | wc -l)
        local csv_files=$(find "$report_dir" -name "*.csv" 2>/dev/null | wc -l)
        local chart_files=$(find "$report_dir" -name "*.png" 2>/dev/null | wc -l)
        local md_files=$(find "$report_dir" -name "*.md" 2>/dev/null | wc -l)
        
        log_info "生成されたレポートファイル:"
        log_info "  - HTMLレポート: ${html_files}個"
        log_info "  - JSONレポート: ${json_files}個"
        log_info "  - CSVレポート: ${csv_files}個"
        log_info "  - チャート: ${chart_files}個"
        log_info "  - Markdownレポート: ${md_files}個"
        
        # 主要なレポートファイルのパス表示
        local main_html="$report_dir/master_security_test_report.html"
        local main_json="$report_dir/master_security_test_report.json"
        local comprehensive_md="$report_dir/comprehensive_test_report.md"
        
        echo ""
        log_success "主要なレポートファイル:"
        
        if [[ -f "$main_html" ]]; then
            log_success "  📊 HTMLレポート: $main_html"
        fi
        
        if [[ -f "$main_json" ]]; then
            log_success "  📋 JSONレポート: $main_json"
        fi
        
        if [[ -f "$comprehensive_md" ]]; then
            log_success "  📝 包括レポート: $comprehensive_md"
        fi
    fi
    
    # 次のステップの提案
    echo ""
    log_info "次のステップ:"
    log_info "1. HTMLレポートをブラウザで開いて結果を確認"
    log_info "2. 失敗したテストがある場合は詳細ログを確認"
    log_info "3. 必要に応じてインフラストラクチャ設定を調整"
    log_info "4. 修正後に再テストを実行"
}

# メイン実行関数
main() {
    local start_time=$(date +%s)
    
    log_e2e "エンドツーエンドセキュリティテストを開始します"
    
    # 初期化
    > "$LOG_FILE"
    
    # 実行モードの表示
    if $COMPREHENSIVE_MODE; then
        log_info "モード: 包括的エンドツーエンドテスト"
    elif $REPORT_ONLY; then
        log_info "モード: レポート生成のみ"
    elif $CLEANUP_ONLY; then
        log_info "モード: クリーンアップのみ"
    else
        log_info "モード: 完全なエンドツーエンドテスト"
        log_info "セキュリティレベル: $SECURITY_LEVELS"
        log_info "AWSリージョン: $AWS_REGION"
        log_info "並列実行: $PARALLEL_EXECUTION"
        log_info "クリーンアップ: $CLEANUP_AFTER_TEST"
    fi
    
    # 必要なスクリプトの確認
    check_scripts
    
    # Python依存関係の確認
    check_python_dependencies
    
    local overall_success=true
    
    # 実行フェーズ
    if $COMPREHENSIVE_MODE; then
        # 包括的エンドツーエンドテスト実行
        if ! run_comprehensive_test; then
            overall_success=false
        fi
    elif $CLEANUP_ONLY; then
        # クリーンアップのみ実行
        if ! run_auto_cleanup; then
            overall_success=false
        fi
    elif $REPORT_ONLY; then
        # レポート生成のみ実行
        if ! generate_detailed_reports; then
            overall_success=false
        fi
    else
        # 完全なエンドツーエンドテスト実行
        
        # 1. マスターセキュリティテストの実行
        if ! run_master_security_test; then
            overall_success=false
            log_error "マスターテストが失敗しましたが、レポート生成を試行します"
        fi
        
        # 2. 詳細レポートの生成
        if ! generate_detailed_reports; then
            overall_success=false
        fi
        
        # 3. 追加クリーンアップ（マスターテストでクリーンアップされていない場合）
        if ! $CLEANUP_AFTER_TEST; then
            if ! run_auto_cleanup; then
                overall_success=false
            fi
        fi
    fi
    
    # 実行サマリーの表示
    display_execution_summary
    
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    # 最終結果
    if $overall_success; then
        log_success "エンドツーエンドセキュリティテストが正常に完了しました (${total_duration}秒)"
        exit 0
    else
        log_warning "エンドツーエンドセキュリティテストで一部エラーが発生しました (${total_duration}秒)"
        exit 1
    fi
}

# トラップでクリーンアップを確実に実行
trap 'log_error "スクリプトが中断されました"' INT TERM

# スクリプトの実行
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi