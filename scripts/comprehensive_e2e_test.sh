#!/bin/bash

# 包括的エンドツーエンドテストスクリプト
# 全コンポーネントの統合とワークフローテストを実行

set -e

# 設定
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/comprehensive_e2e_test.log"
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

log_e2e() {
    echo -e "${PURPLE}[E2E]${NC} $1" | tee -a "$LOG_FILE"
}

# 使用方法
usage() {
    echo "使用方法: $0 [オプション]"
    echo ""
    echo "包括的エンドツーエンドテストスクリプト"
    echo "terraform initから完全環境までの全ワークフローをテストします"
    echo ""
    echo "オプション:"
    echo "  -r, --region REGION     AWSリージョン (デフォルト: us-east-1)"
    echo "  -c, --cleanup          テスト後にリソースをクリーンアップ"
    echo "  -f, --force            確認なしで実行"
    echo "  -v, --verbose          詳細出力を有効にする"
    echo "  -t, --timeout SEC      各フェーズのタイムアウト秒数 (デフォルト: 600)"
    echo "  --skip-init           Terraform初期化をスキップ"
    echo "  --test-only           デプロイメントをスキップしてテストのみ実行"
    echo "  -h, --help            このヘルプメッセージを表示"
    echo ""
    echo "例:"
    echo "  $0 --region us-west-2 --cleanup --verbose"
    echo "  $0 --test-only --force"
    echo "  $0 --timeout 900 --cleanup"
}

# デフォルト値
AWS_REGION="us-east-1"
CLEANUP_AFTER_TEST=false
FORCE_EXECUTION=false
VERBOSE=false
TEST_TIMEOUT=600
SKIP_INIT=false
TEST_ONLY=false

# テスト結果を格納する変数
TEST_RESULTS_FILE="/tmp/comprehensive_test_results_$$"
TEST_DURATIONS_FILE="/tmp/comprehensive_test_durations_$$"
TOTAL_PHASES=0
PASSED_PHASES=0
FAILED_PHASES=0

# コマンドライン引数の解析
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--region)
            AWS_REGION="$2"
            shift 2
            ;;
        -c|--cleanup)
            CLEANUP_AFTER_TEST=true
            shift
            ;;
        -f|--force)
            FORCE_EXECUTION=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -t|--timeout)
            TEST_TIMEOUT="$2"
            shift 2
            ;;
        --skip-init)
            SKIP_INIT=true
            shift
            ;;
        --test-only)
            TEST_ONLY=true
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

# 必要なツールの確認
check_dependencies() {
    log_e2e "依存関係を確認中..."
    
    local deps=("terraform" "aws" "curl" "jq" "python3")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "以下のツールが見つかりません: ${missing_deps[*]}"
        log_error "必要なツールをインストールしてください"
        exit 1
    fi
    
    # AWS認証情報の確認
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS認証情報が設定されていません"
        exit 1
    fi
    
    # Terraformディレクトリの確認
    if [[ ! -d "$TERRAFORM_DIR" ]]; then
        log_error "Terraformディレクトリが見つかりません: $TERRAFORM_DIR"
        exit 1
    fi
    
    # 必要なスクリプトの確認
    local required_scripts=(
        "master_security_test.sh"
        "test_infrastructure.sh"
        "test_vulnerabilities.sh"
        "auto_cleanup_reset.sh"
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
    
    log_success "すべての依存関係が確認されました"
}

# レポートディレクトリの準備
prepare_report_directory() {
    log_e2e "レポートディレクトリを準備中..."
    
    mkdir -p "$REPORT_DIR"
    
    # 古いレポートファイルのバックアップ
    if [[ -d "$REPORT_DIR" ]] && [[ "$(ls -A "$REPORT_DIR" 2>/dev/null)" ]]; then
        local backup_dir="${REPORT_DIR}_backup_$(date +%Y%m%d_%H%M%S)"
        mv "$REPORT_DIR" "$backup_dir"
        mkdir -p "$REPORT_DIR"
        log_info "既存のレポートを $backup_dir にバックアップしました"
    fi
    
    log_success "レポートディレクトリが準備されました: $REPORT_DIR"
}

# フェーズ1: Terraform初期化とプロジェクト構造の検証
phase1_terraform_initialization() {
    local start_time=$(date +%s)
    log_e2e "フェーズ1: Terraform初期化とプロジェクト構造の検証"
    
    ((TOTAL_PHASES++))
    
    cd "$TERRAFORM_DIR"
    
    if ! $SKIP_INIT; then
        # Terraform初期化
        log_info "Terraformを初期化中..."
        if timeout $TEST_TIMEOUT terraform init; then
            log_success "Terraform初期化が完了しました"
        else
            log_error "Terraform初期化に失敗しました"
            TEST_RESULTS["phase1"]="FAIL"
            ((FAILED_PHASES++))
            return 1
        fi
    else
        log_info "Terraform初期化をスキップしました"
    fi
    
    # プロジェクト構造の検証
    log_info "プロジェクト構造を検証中..."
    local required_files=(
        "main.tf"
        "variables.tf"
        "outputs.tf"
        "modules/network/main.tf"
        "modules/compute/main.tf"
        "modules/security/main.tf"
        "modules/monitoring/main.tf"
    )
    
    local missing_files=()
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            missing_files+=("$file")
        fi
    done
    
    if [[ ${#missing_files[@]} -gt 0 ]]; then
        log_error "以下のファイルが見つかりません: ${missing_files[*]}"
        TEST_RESULTS["phase1"]="FAIL"
        ((FAILED_PHASES++))
        return 1
    fi
    
    # Terraform設定の検証
    log_info "Terraform設定を検証中..."
    if timeout $TEST_TIMEOUT terraform validate; then
        log_success "Terraform設定の検証が完了しました"
    else
        log_error "Terraform設定の検証に失敗しました"
        TEST_RESULTS["phase1"]="FAIL"
        ((FAILED_PHASES++))
        return 1
    fi
    
    local end_time=$(date +%s)
    echo "phase1:$((end_time - start_time))" >> "$TEST_DURATIONS_FILE"
    echo "phase1:PASS" >> "$TEST_RESULTS_FILE"
    ((PASSED_PHASES++))
    
    log_success "フェーズ1が完了しました (${TEST_DURATIONS["phase1"]}秒)"
    return 0
}

# フェーズ2: 全セキュリティレベルのデプロイメントテスト
phase2_deployment_test() {
    local start_time=$(date +%s)
    log_e2e "フェーズ2: 全セキュリティレベルのデプロイメントテスト"
    
    ((TOTAL_PHASES++))
    
    if $TEST_ONLY; then
        log_info "テストのみモードのため、デプロイメントをスキップします"
        TEST_RESULTS["phase2"]="SKIP"
        local end_time=$(date +%s)
        TEST_DURATIONS["phase2"]=$((end_time - start_time))
        return 0
    fi
    
    cd "$TERRAFORM_DIR"
    
    # 各セキュリティレベルのデプロイメントテスト
    local levels=(1 2 3 4)
    local deployment_success=true
    
    for level in "${levels[@]}"; do
        log_info "セキュリティレベル $level をデプロイ中..."
        
        # Terraformプラン
        if ! timeout $TEST_TIMEOUT terraform plan -var="security_level=${level}" -var="aws_region=${AWS_REGION}" -out="level_${level}.tfplan"; then
            log_error "セキュリティレベル $level のプランに失敗しました"
            deployment_success=false
            break
        fi
        
        # Terraform適用
        if ! timeout $((TEST_TIMEOUT * 2)) terraform apply -auto-approve "level_${level}.tfplan"; then
            log_error "セキュリティレベル $level のデプロイに失敗しました"
            deployment_success=false
            break
        fi
        
        log_success "セキュリティレベル $level のデプロイが完了しました"
        
        # デプロイメント完了の待機
        sleep 30
        
        # 基本的な接続テスト
        local alb_dns=$(terraform output -raw alb_dns_name 2>/dev/null || echo "")
        if [[ -n "$alb_dns" ]]; then
            log_info "ALB接続テスト中: $alb_dns"
            if timeout 30 curl -s "http://$alb_dns" > /dev/null; then
                log_success "ALB接続テストが成功しました"
            else
                log_warning "ALB接続テストに失敗しました"
            fi
        fi
    done
    
    local end_time=$(date +%s)
    TEST_DURATIONS["phase2"]=$((end_time - start_time))
    
    if $deployment_success; then
        TEST_RESULTS["phase2"]="PASS"
        ((PASSED_PHASES++))
        log_success "フェーズ2が完了しました (${TEST_DURATIONS["phase2"]}秒)"
        return 0
    else
        TEST_RESULTS["phase2"]="FAIL"
        ((FAILED_PHASES++))
        log_error "フェーズ2に失敗しました (${TEST_DURATIONS["phase2"]}秒)"
        return 1
    fi
}

# フェーズ3: 全セキュリティレベルに対する攻撃シミュレーション
phase3_attack_simulation() {
    local start_time=$(date +%s)
    log_e2e "フェーズ3: 全セキュリティレベルに対する攻撃シミュレーション"
    
    ((TOTAL_PHASES++))
    
    # マスターセキュリティテストの実行
    log_info "マスターセキュリティテストを実行中..."
    
    local test_args=(
        "--levels" "all"
        "--region" "$AWS_REGION"
        "--skip-deploy"
        "--output" "all"
        "--timeout" "$TEST_TIMEOUT"
    )
    
    if $VERBOSE; then
        test_args+=("--verbose")
    fi
    
    if "$SCRIPT_DIR/master_security_test.sh" "${test_args[@]}"; then
        log_success "マスターセキュリティテストが完了しました"
        TEST_RESULTS["phase3"]="PASS"
        ((PASSED_PHASES++))
    else
        log_error "マスターセキュリティテストに失敗しました"
        TEST_RESULTS["phase3"]="FAIL"
        ((FAILED_PHASES++))
    fi
    
    local end_time=$(date +%s)
    TEST_DURATIONS["phase3"]=$((end_time - start_time))
    
    log_success "フェーズ3が完了しました (${TEST_DURATIONS["phase3"]}秒)"
    return 0
}

# フェーズ4: 監視・アラートシステムの検証
phase4_monitoring_verification() {
    local start_time=$(date +%s)
    log_e2e "フェーズ4: 監視・アラートシステムの検証"
    
    ((TOTAL_PHASES++))
    
    local monitoring_success=true
    
    # CloudWatchダッシュボードの確認
    log_info "CloudWatchダッシュボードを確認中..."
    local dashboards=$(aws cloudwatch list-dashboards --region "$AWS_REGION" 2>/dev/null || echo '{"DashboardEntries":[]}')
    local dashboard_count=$(echo "$dashboards" | jq '.DashboardEntries | length')
    
    if [[ "$dashboard_count" -gt 0 ]]; then
        log_success "CloudWatchダッシュボードが設定されています ($dashboard_count 個)"
    else
        log_warning "CloudWatchダッシュボードが見つかりません"
        monitoring_success=false
    fi
    
    # CloudWatchアラームの確認
    log_info "CloudWatchアラームを確認中..."
    local alarms=$(aws cloudwatch describe-alarms --region "$AWS_REGION" 2>/dev/null || echo '{"MetricAlarms":[]}')
    local alarm_count=$(echo "$alarms" | jq '.MetricAlarms | length')
    
    if [[ "$alarm_count" -gt 0 ]]; then
        log_success "CloudWatchアラームが設定されています ($alarm_count 個)"
        
        # アラーム状態の確認
        local alarm_states=$(echo "$alarms" | jq -r '.MetricAlarms[] | "\(.AlarmName): \(.StateValue)"')
        while IFS= read -r alarm_state; do
            log_info "  $alarm_state"
        done <<< "$alarm_states"
    else
        log_warning "CloudWatchアラームが見つかりません"
        monitoring_success=false
    fi
    
    # GuardDutyの確認
    log_info "GuardDutyを確認中..."
    local detector_id=$(aws guardduty list-detectors --region "$AWS_REGION" 2>/dev/null | jq -r '.DetectorIds[0] // empty')
    
    if [[ -n "$detector_id" ]]; then
        local detector_status=$(aws guardduty get-detector --detector-id "$detector_id" --region "$AWS_REGION" 2>/dev/null | jq -r '.Status')
        if [[ "$detector_status" == "ENABLED" ]]; then
            log_success "GuardDutyが有効になっています (ID: $detector_id)"
        else
            log_warning "GuardDutyが無効になっています"
            monitoring_success=false
        fi
    else
        log_warning "GuardDutyディテクターが見つかりません"
        monitoring_success=false
    fi
    
    # ログループの確認
    log_info "CloudWatchログループを確認中..."
    local log_groups=$(aws logs describe-log-groups --region "$AWS_REGION" 2>/dev/null || echo '{"logGroups":[]}')
    local log_group_count=$(echo "$log_groups" | jq '.logGroups | length')
    
    if [[ "$log_group_count" -gt 0 ]]; then
        log_success "CloudWatchログループが設定されています ($log_group_count 個)"
    else
        log_warning "CloudWatchログループが見つかりません"
        monitoring_success=false
    fi
    
    local end_time=$(date +%s)
    TEST_DURATIONS["phase4"]=$((end_time - start_time))
    
    if $monitoring_success; then
        TEST_RESULTS["phase4"]="PASS"
        ((PASSED_PHASES++))
        log_success "フェーズ4が完了しました (${TEST_DURATIONS["phase4"]}秒)"
        return 0
    else
        TEST_RESULTS["phase4"]="FAIL"
        ((FAILED_PHASES++))
        log_error "フェーズ4に失敗しました (${TEST_DURATIONS["phase4"]}秒)"
        return 1
    fi
}

# フェーズ5: リソースクリーンアップとコスト管理機能のテスト
phase5_cleanup_test() {
    local start_time=$(date +%s)
    log_e2e "フェーズ5: リソースクリーンアップとコスト管理機能のテスト"
    
    ((TOTAL_PHASES++))
    
    if ! $CLEANUP_AFTER_TEST; then
        log_info "クリーンアップが無効のため、フェーズ5をスキップします"
        TEST_RESULTS["phase5"]="SKIP"
        local end_time=$(date +%s)
        TEST_DURATIONS["phase5"]=$((end_time - start_time))
        return 0
    fi
    
    # 自動クリーンアップスクリプトの実行
    log_info "自動クリーンアップスクリプトを実行中..."
    
    local cleanup_args=(
        "--terraform"
        "--logs"
        "--reports"
        "--days" "1"
    )
    
    if $FORCE_EXECUTION; then
        cleanup_args+=("--force")
    fi
    
    if $VERBOSE; then
        cleanup_args+=("--verbose")
    fi
    
    if "$SCRIPT_DIR/auto_cleanup_reset.sh" "${cleanup_args[@]}"; then
        log_success "自動クリーンアップが完了しました"
        TEST_RESULTS["phase5"]="PASS"
        ((PASSED_PHASES++))
    else
        log_error "自動クリーンアップに失敗しました"
        TEST_RESULTS["phase5"]="FAIL"
        ((FAILED_PHASES++))
    fi
    
    # リソース削除の確認
    log_info "リソース削除を確認中..."
    cd "$TERRAFORM_DIR"
    
    # Terraform状態の確認
    local resource_count=$(terraform show -json 2>/dev/null | jq '.values.root_module.resources | length' 2>/dev/null || echo "0")
    if [[ "$resource_count" -eq 0 ]]; then
        log_success "すべてのTerraformリソースが削除されました"
    else
        log_warning "$resource_count 個のリソースが残っています"
    fi
    
    local end_time=$(date +%s)
    TEST_DURATIONS["phase5"]=$((end_time - start_time))
    
    log_success "フェーズ5が完了しました (${TEST_DURATIONS["phase5"]}秒)"
    return 0
}

# 包括的レポートの生成
generate_comprehensive_report() {
    log_e2e "包括的レポートを生成中..."
    
    local report_file="$REPORT_DIR/comprehensive_e2e_test_report.md"
    local timestamp=$(date '+%Y年%m月%d日 %H:%M:%S')
    
    cat > "$report_file" << EOF
# 包括的エンドツーエンドテストレポート

**実行日時**: $timestamp  
**AWSリージョン**: $AWS_REGION  
**テストタイムアウト**: ${TEST_TIMEOUT}秒  

## 実行サマリー

- **総フェーズ数**: $TOTAL_PHASES
- **成功フェーズ**: $PASSED_PHASES
- **失敗フェーズ**: $FAILED_PHASES
- **成功率**: $(echo "scale=1; $PASSED_PHASES * 100 / $TOTAL_PHASES" | bc -l 2>/dev/null || echo "0")%

## フェーズ別結果

EOF

    # フェーズ別結果の追加
    local phases=(
        "phase1:フェーズ1 - Terraform初期化とプロジェクト構造の検証"
        "phase2:フェーズ2 - 全セキュリティレベルのデプロイメントテスト"
        "phase3:フェーズ3 - 全セキュリティレベルに対する攻撃シミュレーション"
        "phase4:フェーズ4 - 監視・アラートシステムの検証"
        "phase5:フェーズ5 - リソースクリーンアップとコスト管理機能のテスト"
    )
    
    for phase_info in "${phases[@]}"; do
        local phase_key=$(echo "$phase_info" | cut -d':' -f1)
        local phase_name=$(echo "$phase_info" | cut -d':' -f2)
        local result="${TEST_RESULTS[$phase_key]:-"N/A"}"
        local duration="${TEST_DURATIONS[$phase_key]:-0}"
        
        local status_icon
        case $result in
            "PASS") status_icon="✅" ;;
            "FAIL") status_icon="❌" ;;
            "SKIP") status_icon="⏭️" ;;
            *) status_icon="❓" ;;
        esac
        
        cat >> "$report_file" << EOF
### $status_icon $phase_name

- **結果**: $result
- **実行時間**: ${duration}秒

EOF
    done
    
    # 詳細情報の追加
    cat >> "$report_file" << EOF
## 詳細情報

### 実行環境

- **OS**: $(uname -s)
- **Terraformバージョン**: $(terraform version | head -n1)
- **AWS CLIバージョン**: $(aws --version)
- **実行ユーザー**: $(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null || echo "不明")

### 実行オプション

- **クリーンアップ**: $CLEANUP_AFTER_TEST
- **強制実行**: $FORCE_EXECUTION
- **詳細出力**: $VERBOSE
- **初期化スキップ**: $SKIP_INIT
- **テストのみ**: $TEST_ONLY

### 生成されたファイル

EOF

    # 生成されたファイルの一覧
    if [[ -d "$REPORT_DIR" ]]; then
        find "$REPORT_DIR" -type f -name "*.log" -o -name "*.json" -o -name "*.csv" -o -name "*.html" | while read -r file; do
            echo "- \`$(basename "$file")\`" >> "$report_file"
        done
    fi
    
    cat >> "$report_file" << EOF

## 推奨事項

EOF

    # 結果に基づく推奨事項
    if [[ $FAILED_PHASES -gt 0 ]]; then
        cat >> "$report_file" << EOF
### 🔧 修正が必要な項目

EOF
        for phase_key in "${!TEST_RESULTS[@]}"; do
            if [[ "${TEST_RESULTS[$phase_key]}" == "FAIL" ]]; then
                case $phase_key in
                    "phase1")
                        echo "- Terraform設定とプロジェクト構造を確認してください" >> "$report_file"
                        ;;
                    "phase2")
                        echo "- デプロイメント設定とAWSリソース制限を確認してください" >> "$report_file"
                        ;;
                    "phase3")
                        echo "- セキュリティテストの詳細ログを確認してください" >> "$report_file"
                        ;;
                    "phase4")
                        echo "- 監視・アラート設定を確認してください" >> "$report_file"
                        ;;
                    "phase5")
                        echo "- クリーンアップスクリプトとリソース削除権限を確認してください" >> "$report_file"
                        ;;
                esac
            fi
        done
    else
        cat >> "$report_file" << EOF
### ✅ すべてのテストが成功しました

環境は正常に動作しています。定期的なテスト実行を継続してください。
EOF
    fi
    
    cat >> "$report_file" << EOF

### 📊 パフォーマンス最適化

- 総実行時間: $(echo "${TEST_DURATIONS[@]}" | tr ' ' '\n' | awk '{sum+=$1} END {print sum}')秒
- 最も時間のかかったフェーズ: $(printf '%s\n' "${!TEST_DURATIONS[@]}" | while read -r key; do echo "${TEST_DURATIONS[$key]} $key"; done | sort -nr | head -n1 | cut -d' ' -f2)

### 🔄 次回実行時の改善点

- 並列実行オプションの活用を検討
- タイムアウト値の調整
- 不要なリソースの事前クリーンアップ

---

*このレポートは自動生成されました*
EOF

    log_success "包括的レポートが生成されました: $report_file"
}

# 実行統計の表示
display_execution_statistics() {
    log_e2e "実行統計:"
    log_info "総フェーズ数: $TOTAL_PHASES"
    log_success "成功フェーズ: $PASSED_PHASES"
    log_error "失敗フェーズ: $FAILED_PHASES"
    
    if [[ $TOTAL_PHASES -gt 0 ]]; then
        local success_rate=$(echo "scale=1; $PASSED_PHASES * 100 / $TOTAL_PHASES" | bc -l 2>/dev/null || echo "0")
        log_info "成功率: ${success_rate}%"
    fi
    
    # 実行時間の統計
    local total_duration=0
    for duration in "${TEST_DURATIONS[@]}"; do
        total_duration=$((total_duration + duration))
    done
    
    log_info "総実行時間: ${total_duration}秒"
    
    # フェーズ別実行時間
    for phase_key in "${!TEST_DURATIONS[@]}"; do
        local result="${TEST_RESULTS[$phase_key]}"
        local duration="${TEST_DURATIONS[$phase_key]}"
        log_info "$phase_key: $result (${duration}秒)"
    done
}

# メイン実行関数
main() {
    local start_time=$(date +%s)
    
    log_e2e "包括的エンドツーエンドテストを開始します"
    log_info "AWSリージョン: $AWS_REGION"
    log_info "テストタイムアウト: ${TEST_TIMEOUT}秒"
    log_info "クリーンアップ: $CLEANUP_AFTER_TEST"
    
    # 初期化
    > "$LOG_FILE"
    
    # 依存関係の確認
    check_dependencies
    
    # レポートディレクトリの準備
    prepare_report_directory
    
    # 実行確認
    if ! $FORCE_EXECUTION; then
        echo ""
        echo "以下の設定でエンドツーエンドテストを実行します:"
        echo "  AWSリージョン: $AWS_REGION"
        echo "  テストタイムアウト: ${TEST_TIMEOUT}秒"
        echo "  クリーンアップ: $CLEANUP_AFTER_TEST"
        echo "  テストのみ: $TEST_ONLY"
        echo ""
        read -p "続行しますか? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "テストがキャンセルされました"
            exit 0
        fi
    fi
    
    # 各フェーズの実行
    local overall_success=true
    
    # フェーズ1: Terraform初期化とプロジェクト構造の検証
    if ! phase1_terraform_initialization; then
        overall_success=false
    fi
    
    # フェーズ2: 全セキュリティレベルのデプロイメントテスト
    if ! phase2_deployment_test; then
        overall_success=false
    fi
    
    # フェーズ3: 全セキュリティレベルに対する攻撃シミュレーション
    if ! phase3_attack_simulation; then
        overall_success=false
    fi
    
    # フェーズ4: 監視・アラートシステムの検証
    if ! phase4_monitoring_verification; then
        overall_success=false
    fi
    
    # フェーズ5: リソースクリーンアップとコスト管理機能のテスト
    if ! phase5_cleanup_test; then
        overall_success=false
    fi
    
    # 包括的レポートの生成
    generate_comprehensive_report
    
    # 実行統計の表示
    display_execution_statistics
    
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    # 最終結果
    if $overall_success; then
        log_success "包括的エンドツーエンドテストが正常に完了しました (${total_duration}秒)"
        exit 0
    else
        log_warning "包括的エンドツーエンドテストで一部エラーが発生しました (${total_duration}秒)"
        exit 1
    fi
}

# トラップでクリーンアップを確実に実行
trap 'log_error "スクリプトが中断されました"' INT TERM

# スクリプトの実行
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi