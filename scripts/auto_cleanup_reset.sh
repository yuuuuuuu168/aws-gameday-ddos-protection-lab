#!/bin/bash

# 自動クリーンアップとリセット機能
# テストサイクル用の自動クリーンアップ、リソース管理、環境リセット

set -e

# 設定
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/auto_cleanup.log"
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform"
REPORT_DIR="${SCRIPT_DIR}/reports"

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

log_cleanup() {
    echo -e "${PURPLE}[CLEANUP]${NC} $1" | tee -a "$LOG_FILE"
}

# 使用方法
usage() {
    echo "使用方法: $0 [オプション]"
    echo "オプション:"
    echo "  -a, --all            すべてのクリーンアップを実行"
    echo "  -t, --terraform      Terraformリソースのクリーンアップ"
    echo "  -l, --logs          古いログファイルのクリーンアップ"
    echo "  -r, --reports       古いレポートファイルのクリーンアップ"
    echo "  -c, --cache         キャッシュファイルのクリーンアップ"
    echo "  -f, --force         確認なしで実行"
    echo "  -d, --days DAYS     保持日数 (デフォルト: 7)"
    echo "  -s, --size SIZE     最大ディスク使用量 (MB, デフォルト: 1000)"
    echo "  --dry-run           実際の削除は行わず、対象ファイルのみ表示"
    echo "  -v, --verbose       詳細出力を有効にする"
    echo "  -h, --help          このヘルプメッセージを表示"
    echo ""
    echo "例:"
    echo "  $0 --all --force"
    echo "  $0 --terraform --logs --days 3"
    echo "  $0 --dry-run --verbose"
}

# デフォルト値
CLEANUP_ALL=false
CLEANUP_TERRAFORM=false
CLEANUP_LOGS=false
CLEANUP_REPORTS=false
CLEANUP_CACHE=false
FORCE_CLEANUP=false
RETENTION_DAYS=7
MAX_SIZE_MB=1000
DRY_RUN=false
VERBOSE=false

# コマンドライン引数の解析
while [[ $# -gt 0 ]]; do
    case $1 in
        -a|--all)
            CLEANUP_ALL=true
            shift
            ;;
        -t|--terraform)
            CLEANUP_TERRAFORM=true
            shift
            ;;
        -l|--logs)
            CLEANUP_LOGS=true
            shift
            ;;
        -r|--reports)
            CLEANUP_REPORTS=true
            shift
            ;;
        -c|--cache)
            CLEANUP_CACHE=true
            shift
            ;;
        -f|--force)
            FORCE_CLEANUP=true
            shift
            ;;
        -d|--days)
            RETENTION_DAYS="$2"
            shift 2
            ;;
        -s|--size)
            MAX_SIZE_MB="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
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

# 全クリーンアップが指定された場合
if $CLEANUP_ALL; then
    CLEANUP_TERRAFORM=true
    CLEANUP_LOGS=true
    CLEANUP_REPORTS=true
    CLEANUP_CACHE=true
fi

# 何もクリーンアップが指定されていない場合
if ! $CLEANUP_TERRAFORM && ! $CLEANUP_LOGS && ! $CLEANUP_REPORTS && ! $CLEANUP_CACHE; then
    log_error "クリーンアップ対象が指定されていません。--help でヘルプを確認してください。"
    exit 1
fi

# 必要なツールの確認
check_dependencies() {
    log_cleanup "依存関係を確認中..."
    
    local deps=("find" "du" "bc")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "$dep が見つかりません。インストールしてください。"
            exit 1
        fi
    done
    
    # Terraformクリーンアップが指定されている場合
    if $CLEANUP_TERRAFORM; then
        if ! command -v terraform &> /dev/null; then
            log_error "terraform が見つかりません。Terraformクリーンアップをスキップします。"
            CLEANUP_TERRAFORM=false
        fi
        
        if ! command -v aws &> /dev/null; then
            log_error "aws CLI が見つかりません。Terraformクリーンアップをスキップします。"
            CLEANUP_TERRAFORM=false
        fi
    fi
    
    log_success "依存関係の確認が完了しました"
}

# ディスク使用量の確認
check_disk_usage() {
    log_cleanup "ディスク使用量を確認中..."
    
    local current_usage_kb=$(du -sk "$SCRIPT_DIR" 2>/dev/null | cut -f1 || echo "0")
    local current_usage_mb=$((current_usage_kb / 1024))
    
    log_info "現在のディスク使用量: ${current_usage_mb}MB"
    
    if [[ $current_usage_mb -gt $MAX_SIZE_MB ]]; then
        log_warning "ディスク使用量が制限を超えています (${current_usage_mb}MB > ${MAX_SIZE_MB}MB)"
        return 1
    else
        log_success "ディスク使用量は制限内です (${current_usage_mb}MB <= ${MAX_SIZE_MB}MB)"
        return 0
    fi
}

# 確認プロンプト
confirm_cleanup() {
    if $FORCE_CLEANUP || $DRY_RUN; then
        return 0
    fi
    
    echo ""
    log_warning "以下のクリーンアップを実行します:"
    
    if $CLEANUP_TERRAFORM; then
        echo "  - Terraformリソースの削除"
    fi
    if $CLEANUP_LOGS; then
        echo "  - ${RETENTION_DAYS}日以上古いログファイルの削除"
    fi
    if $CLEANUP_REPORTS; then
        echo "  - ${RETENTION_DAYS}日以上古いレポートファイルの削除"
    fi
    if $CLEANUP_CACHE; then
        echo "  - キャッシュファイルの削除"
    fi
    
    echo ""
    read -p "続行しますか? (y/N): " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "クリーンアップがキャンセルされました"
        exit 0
    fi
}

# Terraformリソースのクリーンアップ
cleanup_terraform_resources() {
    log_cleanup "Terraformリソースをクリーンアップ中..."
    
    if [[ ! -d "$TERRAFORM_DIR" ]]; then
        log_warning "Terraformディレクトリが見つかりません: $TERRAFORM_DIR"
        return 0
    fi
    
    cd "$TERRAFORM_DIR"
    
    # Terraform状態の確認
    if [[ ! -f "terraform.tfstate" ]] && [[ ! -f ".terraform/terraform.tfstate" ]]; then
        log_info "Terraformの状態ファイルが見つかりません。リソースは既に削除されている可能性があります。"
    else
        # AWS認証情報の確認
        if ! aws sts get-caller-identity &> /dev/null; then
            log_error "AWS認証情報が設定されていません。Terraformクリーンアップをスキップします。"
            return 1
        fi
        
        # 現在のリソース一覧を取得
        log_info "現在のTerraformリソースを確認中..."
        if $VERBOSE; then
            terraform show 2>/dev/null || log_warning "Terraform状態の表示に失敗しました"
        fi
        
        # リソースの削除
        if ! $DRY_RUN; then
            log_info "Terraformリソースを削除中..."
            if timeout 600 terraform destroy -auto-approve; then
                log_success "Terraformリソースの削除が完了しました"
            else
                log_error "Terraformリソースの削除に失敗しました"
                return 1
            fi
        else
            log_info "[DRY RUN] Terraformリソースが削除される予定です"
        fi
    fi
    
    # Terraform一時ファイルのクリーンアップ
    log_info "Terraform一時ファイルをクリーンアップ中..."
    
    local temp_files=(
        "*.tfplan"
        ".terraform.lock.hcl"
        "terraform.tfstate.backup"
        "crash.log"
    )
    
    for pattern in "${temp_files[@]}"; do
        if $DRY_RUN; then
            find . -name "$pattern" -type f 2>/dev/null | while read -r file; do
                log_info "[DRY RUN] 削除予定: $file"
            done
        else
            find . -name "$pattern" -type f -delete 2>/dev/null || true
        fi
    done
    
    # .terraformディレクトリのクリーンアップ（プロバイダーキャッシュなど）
    if [[ -d ".terraform" ]]; then
        if ! $DRY_RUN; then
            rm -rf .terraform/providers 2>/dev/null || true
            log_success "Terraformプロバイダーキャッシュを削除しました"
        else
            log_info "[DRY RUN] .terraform/providers ディレクトリが削除される予定です"
        fi
    fi
    
    return 0
}

# ログファイルのクリーンアップ
cleanup_log_files() {
    log_cleanup "古いログファイルをクリーンアップ中..."
    
    local log_patterns=(
        "*.log"
        "*.log.*"
        "nohup.out"
    )
    
    local deleted_count=0
    local total_size=0
    
    for pattern in "${log_patterns[@]}"; do
        while IFS= read -r -d '' file; do
            if [[ -f "$file" ]]; then
                local file_size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
                total_size=$((total_size + file_size))
                
                if $VERBOSE; then
                    local file_age=$(find "$file" -mtime +$RETENTION_DAYS 2>/dev/null | wc -l)
                    if [[ $file_age -gt 0 ]]; then
                        log_info "削除対象: $file ($(($file_size / 1024))KB)"
                    fi
                fi
                
                if ! $DRY_RUN; then
                    rm -f "$file"
                    ((deleted_count++))
                else
                    log_info "[DRY RUN] 削除予定: $file"
                    ((deleted_count++))
                fi
            fi
        done < <(find "$SCRIPT_DIR" -name "$pattern" -type f -mtime +$RETENTION_DAYS -print0 2>/dev/null)
    done
    
    if [[ $deleted_count -gt 0 ]]; then
        log_success "ログファイル ${deleted_count}個を削除しました (合計: $((total_size / 1024))KB)"
    else
        log_info "削除対象のログファイルはありませんでした"
    fi
    
    return 0
}

# レポートファイルのクリーンアップ
cleanup_report_files() {
    log_cleanup "古いレポートファイルをクリーンアップ中..."
    
    if [[ ! -d "$REPORT_DIR" ]]; then
        log_info "レポートディレクトリが存在しません: $REPORT_DIR"
        return 0
    fi
    
    local report_patterns=(
        "*.html"
        "*.json"
        "*.csv"
        "*.png"
        "*.jpg"
        "*.pdf"
        "*.md"
    )
    
    local deleted_count=0
    local total_size=0
    
    for pattern in "${report_patterns[@]}"; do
        while IFS= read -r -d '' file; do
            if [[ -f "$file" ]]; then
                local file_size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
                total_size=$((total_size + file_size))
                
                if $VERBOSE; then
                    log_info "削除対象: $file ($(($file_size / 1024))KB)"
                fi
                
                if ! $DRY_RUN; then
                    rm -f "$file"
                    ((deleted_count++))
                else
                    log_info "[DRY RUN] 削除予定: $file"
                    ((deleted_count++))
                fi
            fi
        done < <(find "$REPORT_DIR" -name "$pattern" -type f -mtime +$RETENTION_DAYS -print0 2>/dev/null)
    done
    
    # 空のディレクトリも削除
    if ! $DRY_RUN; then
        find "$REPORT_DIR" -type d -empty -delete 2>/dev/null || true
    fi
    
    if [[ $deleted_count -gt 0 ]]; then
        log_success "レポートファイル ${deleted_count}個を削除しました (合計: $((total_size / 1024))KB)"
    else
        log_info "削除対象のレポートファイルはありませんでした"
    fi
    
    return 0
}

# キャッシュファイルのクリーンアップ
cleanup_cache_files() {
    log_cleanup "キャッシュファイルをクリーンアップ中..."
    
    local cache_patterns=(
        "/tmp/terraform_outputs.json"
        "/tmp/gameday_*"
        "*.tmp"
        "*.cache"
        ".DS_Store"
        "Thumbs.db"
    )
    
    local deleted_count=0
    local total_size=0
    
    # プロジェクト内のキャッシュファイル
    for pattern in "${cache_patterns[@]}"; do
        if [[ "$pattern" == "/tmp/"* ]]; then
            # /tmpディレクトリ内のファイル
            while IFS= read -r -d '' file; do
                if [[ -f "$file" ]]; then
                    local file_size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
                    total_size=$((total_size + file_size))
                    
                    if $VERBOSE; then
                        log_info "削除対象: $file ($(($file_size / 1024))KB)"
                    fi
                    
                    if ! $DRY_RUN; then
                        rm -f "$file"
                        ((deleted_count++))
                    else
                        log_info "[DRY RUN] 削除予定: $file"
                        ((deleted_count++))
                    fi
                fi
            done < <(find /tmp -name "$(basename "$pattern")" -type f -user "$(whoami)" -print0 2>/dev/null)
        else
            # プロジェクト内のファイル
            while IFS= read -r -d '' file; do
                if [[ -f "$file" ]]; then
                    local file_size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
                    total_size=$((total_size + file_size))
                    
                    if $VERBOSE; then
                        log_info "削除対象: $file ($(($file_size / 1024))KB)"
                    fi
                    
                    if ! $DRY_RUN; then
                        rm -f "$file"
                        ((deleted_count++))
                    else
                        log_info "[DRY RUN] 削除予定: $file"
                        ((deleted_count++))
                    fi
                fi
            done < <(find "$SCRIPT_DIR/.." -name "$pattern" -type f -print0 2>/dev/null)
        fi
    done
    
    # Pythonキャッシュディレクトリ
    while IFS= read -r -d '' dir; do
        if [[ -d "$dir" ]]; then
            if $VERBOSE; then
                local dir_size=$(du -sk "$dir" 2>/dev/null | cut -f1 || echo "0")
                log_info "削除対象ディレクトリ: $dir (${dir_size}KB)"
            fi
            
            if ! $DRY_RUN; then
                rm -rf "$dir"
                ((deleted_count++))
            else
                log_info "[DRY RUN] 削除予定ディレクトリ: $dir"
                ((deleted_count++))
            fi
        fi
    done < <(find "$SCRIPT_DIR/.." -name "__pycache__" -type d -print0 2>/dev/null)
    
    if [[ $deleted_count -gt 0 ]]; then
        log_success "キャッシュファイル ${deleted_count}個を削除しました (合計: $((total_size / 1024))KB)"
    else
        log_info "削除対象のキャッシュファイルはありませんでした"
    fi
    
    return 0
}

# 環境リセット
reset_environment() {
    log_cleanup "環境をリセット中..."
    
    # 環境変数のクリア
    unset TF_VAR_security_level
    unset TF_VAR_aws_region
    
    # 作業ディレクトリのリセット
    cd "$SCRIPT_DIR"
    
    # レポートディレクトリの再作成
    if [[ ! -d "$REPORT_DIR" ]]; then
        mkdir -p "$REPORT_DIR"
        log_success "レポートディレクトリを再作成しました: $REPORT_DIR"
    fi
    
    log_success "環境のリセットが完了しました"
}

# クリーンアップサマリーの表示
display_cleanup_summary() {
    log_cleanup "クリーンアップサマリー:"
    
    # 現在のディスク使用量を再確認
    local current_usage_kb=$(du -sk "$SCRIPT_DIR" 2>/dev/null | cut -f1 || echo "0")
    local current_usage_mb=$((current_usage_kb / 1024))
    
    log_info "クリーンアップ後のディスク使用量: ${current_usage_mb}MB"
    
    # 実行されたクリーンアップの一覧
    local cleanup_actions=()
    
    if $CLEANUP_TERRAFORM; then
        cleanup_actions+=("Terraformリソース")
    fi
    if $CLEANUP_LOGS; then
        cleanup_actions+=("ログファイル")
    fi
    if $CLEANUP_REPORTS; then
        cleanup_actions+=("レポートファイル")
    fi
    if $CLEANUP_CACHE; then
        cleanup_actions+=("キャッシュファイル")
    fi
    
    if [[ ${#cleanup_actions[@]} -gt 0 ]]; then
        log_success "実行されたクリーンアップ: $(IFS=', '; echo "${cleanup_actions[*]}")"
    fi
    
    if $DRY_RUN; then
        log_info "これはドライランでした。実際のファイル削除は行われていません。"
    fi
}

# メイン実行関数
main() {
    local start_time=$(date +%s)
    
    log_cleanup "自動クリーンアップとリセットを開始します"
    log_info "保持日数: ${RETENTION_DAYS}日"
    log_info "最大サイズ: ${MAX_SIZE_MB}MB"
    
    if $DRY_RUN; then
        log_info "ドライランモード: 実際の削除は行いません"
    fi
    
    # 初期化
    > "$LOG_FILE"
    
    # 依存関係の確認
    check_dependencies
    
    # ディスク使用量の確認
    check_disk_usage
    
    # 確認プロンプト
    confirm_cleanup
    
    # 各クリーンアップの実行
    local cleanup_success=true
    
    if $CLEANUP_TERRAFORM; then
        if ! cleanup_terraform_resources; then
            cleanup_success=false
        fi
    fi
    
    if $CLEANUP_LOGS; then
        if ! cleanup_log_files; then
            cleanup_success=false
        fi
    fi
    
    if $CLEANUP_REPORTS; then
        if ! cleanup_report_files; then
            cleanup_success=false
        fi
    fi
    
    if $CLEANUP_CACHE; then
        if ! cleanup_cache_files; then
            cleanup_success=false
        fi
    fi
    
    # 環境リセット
    reset_environment
    
    # サマリーの表示
    display_cleanup_summary
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    if $cleanup_success; then
        log_success "クリーンアップが正常に完了しました (${duration}秒)"
        exit 0
    else
        log_warning "一部のクリーンアップでエラーが発生しました (${duration}秒)"
        exit 1
    fi
}

# スクリプトの実行
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi