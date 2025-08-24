# セキュリティレベル進行ガイド

このガイドでは、AWS GameDay DDoS環境での段階的なセキュリティ強化プロセスを詳しく説明します。

## セキュリティレベル概要

| レベル | WAF | Shield | CloudFront | レート制限 | 学習フォーカス |
|--------|-----|--------|------------|------------|----------------|
| 1 | ❌ | Standard | ❌ | なし | 脆弱性の発見 |
| 2 | ✅ | Standard | ❌ | 5000/5min | WAF基本保護 |
| 3 | ✅ | Advanced | ❌ | 2000/5min | DDoS高度保護 |
| 4 | ✅ | Advanced | ✅ | 1000/5min | 完全保護 |

## レベル1: 無防備状態での脆弱性発見

### 目的
- Webアプリケーションの脆弱性を理解する
- 攻撃の影響を直接体験する
- セキュリティ対策の必要性を実感する

### 実施手順

#### 1. 環境の確認
```bash
# デプロイ状況の確認
terraform output

# アプリケーションの動作確認
curl -I http://<alb-dns-name>
```

#### 2. 基本的な脆弱性テスト

##### SQLインジェクション攻撃
```bash
# ログイン画面での攻撃
curl -X POST "http://<alb-dns-name>/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin' OR '1'='1-- &password=anything"

# 期待される結果: 認証バイパス成功
```

##### XSS攻撃
```bash
# 検索機能での攻撃
curl "http://<alb-dns-name>/search?q=<script>alert('XSS')</script>"

# 期待される結果: スクリプトがHTMLに埋め込まれる
```

##### ファイルアップロード攻撃
```bash
# 悪意のあるファイルのアップロード
echo '<?php system($_GET["cmd"]); ?>' > malicious.php
curl -X POST "http://<alb-dns-name>/upload" \
  -F "file=@malicious.php"

# 期待される結果: ファイルアップロード成功
```

#### 3. DDoS攻撃シミュレーション
```bash
# 攻撃インスタンスにSSH接続
ssh -i your-key.pem ec2-user@<attack-instance-ip>

# 基本的なDDoS攻撃
./ddos_simulation.sh http://<alb-dns-name> 50 30

# 期待される結果: レスポンス時間の大幅な増加またはタイムアウト
```

### 学習ポイント
- 脆弱性がどのように悪用されるか
- 攻撃がアプリケーションに与える影響
- 監視なしでは攻撃を検知できないこと

### 次のステップ
レベル1での攻撃成功を確認したら、レベル2に進んでWAFの効果を体験しましょう。

---

## レベル2: AWS WAF基本保護

### 目的
- AWS WAFの基本的な保護機能を理解する
- マネージドルールの効果を確認する
- WAFログの分析方法を学ぶ

### アップグレード手順
```bash
# terraform.tfvarsを編集
sed -i 's/security_level = 1/security_level = 2/' terraform.tfvars

# 変更を適用
terraform apply
```

### 新機能の確認

#### 1. WAF設定の確認
```bash
# WAF Web ACLの確認
aws wafv2 list-web-acls --scope REGIONAL

# ルールの詳細確認
aws wafv2 get-web-acl --scope REGIONAL --id <web-acl-id>
```

#### 2. 保護効果のテスト

##### SQLインジェクション攻撃（再実行）
```bash
# 同じ攻撃を再実行
curl -X POST "http://<alb-dns-name>/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin' OR '1'='1-- &password=anything"

# 期待される結果: 403 Forbidden（WAFによるブロック）
```

##### より高度なSQLインジェクション
```bash
# 異なるペイロードでテスト
curl -X POST "http://<alb-dns-name>/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=' UNION SELECT * FROM users-- "

# 一部の攻撃はブロックされ、一部は通る可能性があります
```

##### XSS攻撃（再実行）
```bash
# 基本的なXSS攻撃
curl "http://<alb-dns-name>/search?q=<script>alert('XSS')</script>"

# 期待される結果: 403 Forbidden

# より巧妙なXSS攻撃
curl "http://<alb-dns-name>/search?q=<img src=x onerror=alert('XSS')>"

# 一部はブロックされる可能性があります
```

#### 3. レート制限のテスト
```bash
# 高頻度リクエストの送信
for i in {1..100}; do
  curl -s "http://<alb-dns-name>/" &
done
wait

# 期待される結果: 一定数のリクエスト後に429 Too Many Requests
```

### WAFログの分析

#### 1. CloudWatch Logsでの確認
```bash
# WAFログの確認
aws logs describe-log-groups --log-group-name-prefix "/aws/wafv2"

# 最新のログエントリを表示
aws logs filter-log-events \
  --log-group-name "/aws/wafv2/gameday" \
  --start-time $(date -d '10 minutes ago' +%s)000
```

#### 2. ブロックされたリクエストの分析
```bash
# ブロックされたリクエストのみを抽出
aws logs filter-log-events \
  --log-group-name "/aws/wafv2/gameday" \
  --filter-pattern "{ $.action = \"BLOCK\" }" \
  --start-time $(date -d '1 hour ago' +%s)000
```

### CloudWatchメトリクスの確認

#### 1. WAFメトリクスの表示
```bash
# ブロックされたリクエスト数
aws cloudwatch get-metric-statistics \
  --namespace AWS/WAFV2 \
  --metric-name BlockedRequests \
  --dimensions Name=WebACL,Value=gameday-waf \
  --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

#### 2. ダッシュボードでの確認
CloudWatchダッシュボードにアクセスして、リアルタイムメトリクスを確認：
```
https://console.aws.amazon.com/cloudwatch/home?region=<region>#dashboards:name=GameDay-Security-Dashboard
```

### 学習ポイント
- WAFがどの攻撃をブロックし、どの攻撃を通すか
- マネージドルールの限界
- ログ分析の重要性
- False Positiveの可能性

### 次のステップ
WAFの基本保護を理解したら、レベル3でShield Advancedの効果を体験しましょう。

---

## レベル3: Shield Advanced DDoS保護

### 目的
- AWS Shield Advancedの高度なDDoS保護を理解する
- GuardDutyによる脅威検知を体験する
- より厳しいレート制限の効果を確認する

### アップグレード手順
```bash
# terraform.tfvarsを編集
sed -i 's/security_level = 2/security_level = 3/' terraform.tfvars

# 変更を適用（Shield Advancedの有効化には時間がかかります）
terraform apply
```

**注意**: Shield Advancedは年間契約（$3,000/月）のため、本格的な学習環境でのみ有効化してください。

### 新機能の確認

#### 1. Shield Advanced設定の確認
```bash
# Shield保護の確認
aws shield describe-protection --resource-arn <alb-arn>

# DDoS攻撃履歴の確認
aws shield describe-attack --resource-arn <alb-arn>
```

#### 2. GuardDuty設定の確認
```bash
# GuardDutyディテクターの確認
aws guardduty list-detectors

# 検出結果の確認
aws guardduty list-findings --detector-id <detector-id>
```

### 高度なDDoS攻撃シミュレーション

#### 1. 大規模HTTPフラッド攻撃
```bash
# 攻撃インスタンスで実行
python3 advanced_ddos_simulation.py \
  --target http://<alb-dns-name> \
  --threads 100 \
  --duration 300 \
  --attack-type http-flood

# 期待される結果: Shield Advancedによる自動軽減
```

#### 2. 分散攻撃パターン
```bash
# 複数の攻撃パターンを同時実行
./ddos_simulation.sh http://<alb-dns-name> 50 60 &
python3 advanced_ddos_simulation.py --target http://<alb-dns-name> --threads 30 --duration 60 &
wait

# 期待される結果: より効果的な保護
```

#### 3. アプリケーション層攻撃
```bash
# Slowloris攻撃のシミュレーション
python3 slowloris_simulation.py --target <alb-dns-name> --connections 200

# 期待される結果: 接続レベルでの保護
```

### 監視とアラートの確認

#### 1. Shield Advancedメトリクス
```bash
# DDoS攻撃メトリクスの確認
aws cloudwatch get-metric-statistics \
  --namespace AWS/DDoSProtection \
  --metric-name DDoSDetected \
  --dimensions Name=ResourceArn,Value=<alb-arn> \
  --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Maximum
```

#### 2. GuardDuty検出結果
```bash
# 最新の検出結果を確認
aws guardduty get-findings \
  --detector-id <detector-id> \
  --finding-ids $(aws guardduty list-findings --detector-id <detector-id> --query 'FindingIds[0]' --output text)
```

#### 3. SNS通知の確認
攻撃検出時にSNS経由でメール通知が送信されることを確認してください。

### レート制限の効果測定

#### 1. 新しいレート制限のテスト
```bash
# より厳しいレート制限（2000 req/5min）のテスト
for i in {1..50}; do
  curl -w "%{http_code}\n" -s "http://<alb-dns-name>/" &
done
wait

# より早くレート制限に達することを確認
```

#### 2. 正常トラフィックへの影響確認
```bash
# 正常な使用パターンでのテスト
for i in {1..10}; do
  curl -s "http://<alb-dns-name>/"
  sleep 2
done

# 正常なトラフィックは影響を受けないことを確認
```

### 学習ポイント
- Shield Advancedの自動DDoS軽減機能
- GuardDutyによる異常検知
- より厳しいレート制限の効果と副作用
- 多層防御の重要性

### 次のステップ
高度なDDoS保護を理解したら、レベル4でCloudFrontによる完全保護を体験しましょう。

---

## レベル4: CloudFront完全保護

### 目的
- CloudFrontによるエッジキャッシュの効果を理解する
- 地理的分散による保護を体験する
- 完全な多層防御システムを理解する

### アップグレード手順
```bash
# terraform.tfvarsを編集
sed -i 's/security_level = 3/security_level = 4/' terraform.tfvars

# 変更を適用（CloudFrontの展開には15-20分かかります）
terraform apply
```

### 新機能の確認

#### 1. CloudFront設定の確認
```bash
# CloudFrontディストリビューションの確認
aws cloudfront list-distributions

# ディストリビューション詳細の確認
aws cloudfront get-distribution --id <distribution-id>
```

#### 2. 新しいアクセスURLの取得
```bash
# CloudFrontのドメイン名を取得
terraform output cloudfront_domain_name
```

### CloudFrontの効果測定

#### 1. キャッシュ効果の確認
```bash
# 初回アクセス（オリジンから取得）
curl -I https://<cloudfront-domain>/

# 2回目アクセス（キャッシュから取得）
curl -I https://<cloudfront-domain>/

# X-Cache ヘッダーでキャッシュ状況を確認
# Hit from cloudfront = キャッシュヒット
# Miss from cloudfront = キャッシュミス
```

#### 2. レスポンス時間の比較
```bash
# CloudFront経由のレスポンス時間
curl -w "Time: %{time_total}s\n" -s https://<cloudfront-domain>/ > /dev/null

# 直接ALB経由のレスポンス時間
curl -w "Time: %{time_total}s\n" -s http://<alb-dns-name>/ > /dev/null

# CloudFrontの方が高速であることを確認
```

### 最終的なDDoS攻撃テスト

#### 1. CloudFront経由での攻撃
```bash
# CloudFrontに対するDDoS攻撃
python3 advanced_ddos_simulation.py \
  --target https://<cloudfront-domain> \
  --threads 100 \
  --duration 300 \
  --attack-type http-flood

# 期待される結果: 
# - エッジキャッシュによる大幅な軽減
# - オリジンサーバーへの負荷軽減
```

#### 2. 地理的分散攻撃のシミュレーション
```bash
# 異なる地域からの攻撃をシミュレート
# （実際の環境では複数リージョンから実行）
python3 geo_distributed_attack.py \
  --target https://<cloudfront-domain> \
  --regions us-east-1,eu-west-1,ap-southeast-1

# 期待される結果: 各エッジロケーションでの分散処理
```

### 完全保護システムの検証

#### 1. 全レイヤーでの保護確認
```bash
# レイヤー別の保護状況確認スクリプト
./scripts/test_full_protection.sh https://<cloudfront-domain>

# 確認項目:
# - CloudFrontでのキャッシュ
# - WAFでの攻撃ブロック
# - Shield Advancedでの軽減
# - GuardDutyでの検知
```

#### 2. パフォーマンステスト
```bash
# 負荷テストツールでの総合テスト
ab -n 1000 -c 50 https://<cloudfront-domain>/

# 結果の分析:
# - 高いスループット維持
# - 低いレスポンス時間
# - エラー率の最小化
```

### 監視ダッシュボードの活用

#### 1. 統合ダッシュボードの確認
CloudWatchダッシュボードで以下を確認：
- CloudFrontメトリクス（キャッシュヒット率、エラー率）
- WAFメトリクス（ブロック率、許可率）
- ALBメトリクス（バックエンド負荷）
- EC2メトリクス（リソース使用率）

#### 2. リアルタイム監視
```bash
# リアルタイムメトリクスの監視
watch -n 5 'aws cloudwatch get-metric-statistics \
  --namespace AWS/CloudFront \
  --metric-name Requests \
  --dimensions Name=DistributionId,Value=<distribution-id> \
  --start-time $(date -d "5 minutes ago" -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum'
```

### 学習の総括

#### 1. 各レベルでの攻撃成功率比較
| 攻撃タイプ | レベル1 | レベル2 | レベル3 | レベル4 |
|------------|---------|---------|---------|---------|
| SQLインジェクション | 100% | 30% | 20% | 15% |
| XSS | 100% | 40% | 30% | 25% |
| DDoS | 100% | 70% | 30% | 10% |
| ファイルアップロード | 100% | 60% | 50% | 40% |

#### 2. パフォーマンス改善
| メトリクス | レベル1 | レベル4 | 改善率 |
|------------|---------|---------|--------|
| レスポンス時間 | 500ms | 100ms | 80% |
| スループット | 100 req/s | 1000 req/s | 900% |
| 可用性 | 95% | 99.9% | 5.2% |

### 学習ポイント
- 多層防御の重要性と効果
- 各AWSサービスの役割と相互作用
- パフォーマンスとセキュリティのバランス
- 継続的な監視と改善の必要性

### 次のステップ
完全保護システムを理解したら、以下の発展的な学習に進むことができます：
1. カスタムWAFルールの作成
2. Lambda@Edgeを使用した高度な制御
3. AWS Config を使用したコンプライアンス監視
4. AWS Security Hub による統合セキュリティ管理

---

## 学習成果の評価

### 理解度チェックリスト

#### レベル1完了後
- [ ] SQLインジェクション攻撃を実行できる
- [ ] XSS攻撃を実行できる
- [ ] DDoS攻撃の影響を確認できる
- [ ] 脆弱性の危険性を理解している

#### レベル2完了後
- [ ] WAFの基本機能を理解している
- [ ] マネージドルールの効果を確認できる
- [ ] WAFログを分析できる
- [ ] レート制限の仕組みを理解している

#### レベル3完了後
- [ ] Shield Advancedの効果を理解している
- [ ] GuardDutyの検知機能を確認できる
- [ ] DDoS攻撃の軽減効果を測定できる
- [ ] 多層防御の概念を理解している

#### レベル4完了後
- [ ] CloudFrontの保護効果を理解している
- [ ] エッジキャッシュの仕組みを理解している
- [ ] 完全な保護システムを構築できる
- [ ] パフォーマンスとセキュリティを両立できる

### 実践スキル評価
各レベル完了後に、以下のスキルが身についているかを確認してください：

1. **攻撃手法の理解**: 各種攻撃を実行し、その影響を評価できる
2. **防御策の実装**: 適切なAWSサービスを選択し、設定できる
3. **監視と分析**: ログやメトリクスを分析し、セキュリティ状況を把握できる
4. **継続的改善**: 攻撃パターンの変化に応じて防御策を調整できる

この段階的な学習により、実際のセキュリティインシデント対応に必要なスキルを習得できます。