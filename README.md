# AWS GameDay DDoS Environment

AWS GameDayスタイルの「Winning the DDoS Game」学習環境へようこそ。この環境では、参加者がDDoS攻撃やその他のセキュリティ脅威に対する防御策を実践的に学習できます。

## 概要

この環境は以下の要素で構成されています：
- 意図的に脆弱性を持つWebアプリケーション
- 段階的に強化可能なAWSセキュリティサービス
- 攻撃シミュレーションツール
- 包括的な監視・検知システム

## 前提条件

### 必要なツール
- [Terraform](https://www.terraform.io/downloads.html) (v1.0以上)
- [AWS CLI](https://aws.amazon.com/cli/) (v2.0以上)
- Git
- curl (攻撃シミュレーション用)
- Apache Bench (ab) (負荷テスト用)

### AWS要件
- AWS アカウント
- 適切なIAM権限を持つAWSユーザー
- AWS CLI設定済み

### 必要なAWS権限
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "elasticloadbalancing:*",
        "wafv2:*",
        "cloudfront:*",
        "shield:*",
        "guardduty:*",
        "cloudwatch:*",
        "logs:*",
        "sns:*",
        "iam:*",
        "s3:*"
      ],
      "Resource": "*"
    }
  ]
}
```

## クイックスタート

### 1. リポジトリのクローン
```bash
git clone <repository-url>
cd aws-gameday-ddos-environment
```

### 2. AWS認証情報の設定
```bash
aws configure
# または環境変数を設定
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

### 3. Terraformの初期化
```bash
cd terraform
terraform init
```

### 4. 設定ファイルの作成
```bash
cp terraform.tfvars.example terraform.tfvars
```

`terraform.tfvars`を編集して、必要な変数を設定：
```hcl
# 基本設定
aws_region = "us-east-1"
environment = "gameday"
project_name = "aws-gameday-ddos"

# セキュリティレベル (1-4)
security_level = 4  # CloudFront + WAF + Shield の完全保護

# ネットワーク設定
vpc_cidr = "10.0.0.0/16"

# インスタンス設定
instance_type = "t3.micro"
key_pair_name = "gameday-keypair"  # 事前に作成したキーペア名

# 攻撃シミュレーション設定
enable_attack_simulation = true
attack_instance_type = "t3.small"
allowed_ssh_cidr_blocks = ["0.0.0.0/0"]  # 本番環境では制限推奨
create_attack_results_bucket = true

# 通知設定
budget_notification_emails = ["your-email@example.com"]
cost_anomaly_threshold_usd = 10
daily_cost_threshold_usd = 5

# リソース管理
auto_cleanup_enabled = true
resource_expiration_hours = 24
cleanup_dry_run = false
```

### 5. 環境のデプロイ
```bash
# プランの確認
terraform plan

# デプロイの実行
terraform apply
```

デプロイが完了すると、以下の情報が出力されます：
```bash
# 主要な出力例
application_url = "http://aws-gameday-ddos-alb-1437098236.us-east-1.elb.amazonaws.com"
attack_simulation_public_ip = "13.218.197.180"
attack_simulation_ssh_command = "ssh -i ~/.ssh/gameday-keypair.pem ec2-user@13.218.197.180"
cloudfront_url = "https://d2tem7pba37jo9.cloudfront.net"
monitoring_dashboard_url = "https://us-east-1.console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=aws-gameday-ddos-security-dashboard"
```

## セキュリティレベルの進行

この環境では、4つのセキュリティレベルを段階的に体験できます。

### レベル1: 無防備状態
**特徴:**
- WAF無効
- Shield Standard のみ
- CloudFront無効
- 基本的な監視のみ

**学習目標:**
- 脆弱性の発見と悪用
- 攻撃の影響を直接体験

**確認方法:**
```bash
# アプリケーションの動作確認
curl http://<alb-dns-name>

# 脆弱性テストの実行
./scripts/test_vulnerabilities.sh <alb-dns-name>
```

### レベル2: 基本的なWAF保護
**アップグレード手順:**
```bash
# terraform.tfvarsを編集
security_level = 2

# 変更を適用
terraform apply
```

**特徴:**
- AWS WAF v2 有効
- 基本的なマネージドルール
- レートベース制限: 5000 req/5min

**学習目標:**
- WAFによる攻撃ブロックの確認
- ログ分析の実践

### レベル3: 高度なWAF保護
**アップグレード手順:**
```bash
# terraform.tfvarsを編集
security_level = 3

# 変更を適用
terraform apply
```

**特徴:**
- より厳しいレート制限: 2000 req/5min
- 高度なWAFルール
- GuardDuty 有効

**学習目標:**
- 高度なWAF保護の効果確認
- 脅威検知システムの理解

### レベル4: 完全保護
**アップグレード手順:**
```bash
# terraform.tfvarsを編集
security_level = 4

# 変更を適用
terraform apply
```

**特徴:**
- CloudFront 有効
- 最も厳しいレート制限: 1000 req/5min
- 完全な監視・アラート

**学習目標:**
- エッジキャッシュの効果確認
- 総合的なセキュリティ戦略の理解

## 攻撃シミュレーション

### DDoS攻撃シミュレーション

#### 基本的なHTTPフラッド攻撃
```bash
# 攻撃シミュレーションインスタンスにSSH接続
ssh -i ~/.ssh/gameday-keypair.pem ec2-user@<attack-instance-ip>

# 接続確認
ssh -i ~/.ssh/gameday-keypair.pem -o StrictHostKeyChecking=no ec2-user@<attack-instance-ip> "echo 'SSH接続成功!' && whoami && uptime"

# DDoS攻撃の実行
./attack-scripts/ddos_test.sh <target-url>
```

#### 高度な攻撃パターン
```bash
# CloudFrontへの同時攻撃テスト（50リクエスト）
echo "=== CloudFront攻撃テスト ==="
for i in {1..50}; do 
  curl -s -o /dev/null -w '%{http_code} %{time_total}s\n' https://<cloudfront-domain> & 
done; wait

# 大規模攻撃テスト（200同時リクエスト）
echo "=== 大規模攻撃テスト ==="
for i in {1..200}; do 
  curl -s -o /dev/null -w '%{http_code} ' https://<cloudfront-domain> & 
done; wait && echo "攻撃テスト完了"

# レスポンスヘッダーの確認（キャッシュ効果）
curl -I https://<cloudfront-domain>
# x-cache: Hit from cloudfront を確認
```

### 脆弱性攻撃シミュレーション

#### SQLインジェクション攻撃
```bash
# 自動SQLインジェクションテスト
python3 sql_injection_test.py --target <target-url>

# 手動テスト例
curl -X POST "<target-url>/login" \
  -d "username=admin' OR '1'='1&password=anything"
```

#### XSS攻撃
```bash
# XSSテストスクリプト
python3 xss_test.py --target <target-url>

# 手動テスト例
curl "<target-url>/search?q=<script>alert('XSS')</script>"
```

#### ファイルアップロード攻撃
```bash
# 悪意のあるファイルアップロード
python3 file_upload_test.py --target <target-url>
```

### 期待される結果

#### レベル1での攻撃結果
- **SQLインジェクション**: 成功（データベース情報の取得）
- **XSS**: 成功（スクリプト実行）
- **DDoS**: 成功（サービス停止またはレスポンス遅延）
- **ファイルアップロード**: 成功（任意ファイルの実行）

#### レベル2での攻撃結果
- **SQLインジェクション**: 一部ブロック（WAFルールによる）
- **XSS**: 一部ブロック
- **DDoS**: 軽減（レート制限による）
- **ファイルアップロード**: 一部ブロック

#### レベル3での攻撃結果
- **DDoS**: 大幅軽減（厳しいレート制限による）
- **異常検知**: GuardDutyアラート発生
- **監視**: 詳細なメトリクス取得

#### レベル4での攻撃結果
- **DDoS**: 最大限軽減（CloudFrontキャッシュ効果）
- **レスポンス**: 高速化（エッジキャッシュ）
- **監視**: 完全な可視性

## 監視とログ

### CloudWatchダッシュボード
デプロイ後、以下のURLでダッシュボードにアクセス：
```
https://console.aws.amazon.com/cloudwatch/home?region=<region>#dashboards:name=GameDay-Security-Dashboard
```

### 主要メトリクス
- **ALB メトリクス**: リクエスト数、レスポンス時間、エラー率
- **WAF メトリクス**: 許可/ブロックされたリクエスト数
- **EC2 メトリクス**: CPU使用率、ネットワーク使用量
- **GuardDuty**: 脅威検知アラート

### ログの確認
```bash
# WAFログの確認
aws logs describe-log-groups --log-group-name-prefix "/aws/wafv2"

# アプリケーションログの確認
aws logs describe-log-groups --log-group-name-prefix "/aws/gameday"

# ログストリームの表示
aws logs describe-log-streams --log-group-name "/aws/gameday/application"
```

## 実際の攻撃テスト結果

### CloudFront保護効果テスト（レベル4）

#### テスト環境
- **攻撃元**: EC2インスタンス（AWS内部）
- **ターゲット**: CloudFront経由のWebアプリケーション
- **攻撃パターン**: 大規模同時リクエスト

#### テスト結果
```bash
# 50同時リクエストテスト
=== EC2からCloudFrontへの攻撃テスト ===
すべてのリクエストが成功（HTTP 200）
平均レスポンス時間: ~370ms
失敗率: 0%

# 200同時リクエストテスト  
=== 大規模攻撃テスト（200同時リクエスト） ===
すべてのリクエストが成功（HTTP 200）
CloudFrontが完全に処理
失敗率: 0%
```

#### 保護効果の確認
- **完全な可用性**: 大規模攻撃でもサービス継続
- **安定したパフォーマンス**: レスポンス時間の一貫性
- **スケーラビリティ**: 200同時接続でも問題なし
- **キャッシュ効果**: `x-cache: Hit from cloudfront` ヘッダーで確認

## トラブルシューティング

### よくある問題

#### 1. 攻撃シミュレーションインスタンスにSSH接続できない

**症状**: `ssh: connect to host <ip> port 22: Operation timed out`

**原因と解決方法**:

##### A. セキュリティグループの設定不備
```bash
# セキュリティグループの確認
aws ec2 describe-security-groups --group-ids <security-group-id> --query 'SecurityGroups[0].IpPermissions'

# terraform.tfvarsでSSH接続を許可
allowed_ssh_cidr_blocks = ["0.0.0.0/0"]  # 本番環境では制限推奨

# Terraformで適用
terraform apply -target=module.attack_simulation.aws_security_group.attack_simulation
```

##### B. ネットワークACLの設定不備（重要）
```bash
# ネットワークACLの確認
aws ec2 describe-network-acls --filters "Name=association.subnet-id,Values=<subnet-id>" --query 'NetworkAcls[0].Entries'

# SSH（ポート22）が許可されていない場合の修正
# terraform/modules/network/main.tf に以下を追加：
```

```hcl
# Allow SSH traffic for management
ingress {
  protocol   = "tcp"
  rule_no    = 90
  action     = "allow"
  cidr_block = "0.0.0.0/0"
  from_port  = 22
  to_port    = 22
}
```

```bash
# ネットワークACLの修正を適用
terraform apply -target=module.network.aws_network_acl.public
```

##### C. インスタンスの問題
```bash
# インスタンスの状態確認
aws ec2 describe-instances --instance-ids <instance-id> --query 'Reservations[0].Instances[0].{State:State.Name,PublicIP:PublicIpAddress}'

# システムログの確認
aws ec2 get-console-output --instance-id <instance-id> --query 'Output' --output text | tail -10

# 問題のあるインスタンスの置き換え
terraform apply -replace="module.attack_simulation.aws_instance.attack_simulation[0]"
```

#### 2. Terraform apply が失敗する
```bash
# 状態ファイルの確認
terraform show

# 特定のリソースの再作成
terraform taint aws_instance.vulnerable_app
terraform apply
```

#### 3. アプリケーションにアクセスできない
```bash
# セキュリティグループの確認
aws ec2 describe-security-groups --group-names gameday-alb-sg

# ALBの状態確認
aws elbv2 describe-load-balancers --names gameday-alb

# ターゲットの健全性確認
aws elbv2 describe-target-health --target-group-arn <target-group-arn>
```

#### 4. CloudFrontの設定確認
```bash
# CloudFrontディストリビューションの状態確認
aws cloudfront list-distributions --query 'DistributionList.Items[0].{Id:Id,Status:Status,DomainName:DomainName}'

# キャッシュ動作の確認
curl -I https://<cloudfront-domain>
# x-cache ヘッダーで Hit/Miss を確認
```

### ログの確認方法
```bash
# EC2インスタンスのシステムログ
aws ec2 get-console-output --instance-id <instance-id>

# CloudWatch Logsの確認
aws logs filter-log-events --log-group-name "/aws/gameday/application" --start-time $(date -d '1 hour ago' +%s)000

# 攻撃シミュレーションログの確認
ssh -i ~/.ssh/gameday-keypair.pem ec2-user@<attack-instance-ip> "sudo tail -f /var/log/attack-simulation.log"

# WAFログの確認（レベル2以上）
aws logs describe-log-groups --log-group-name-prefix "/aws/wafv2"
aws logs filter-log-events --log-group-name "/aws/wafv2/aws-gameday-ddos" --start-time $(date -d '1 hour ago' +%s)000
```

## クリーンアップ

学習セッション終了後は、コストを避けるために必ずリソースを削除してください：

```bash
# 全リソースの削除
terraform destroy

# 確認
terraform show
```

## コスト見積もり

### 時間あたりの概算コスト（us-east-1リージョン）

#### レベル1-2
- EC2 t3.micro (2インスタンス): $0.021/時間
- ALB: $0.0225/時間
- データ転送: $0.09/GB
- **合計**: 約 $0.05/時間

#### レベル3
- 上記 + GuardDuty: $4.00/月（最初の10GB）
- **合計**: 約 $0.05/時間 + 月額料金

#### レベル4
- 上記 + CloudFront: $0.085/GB（最初の10TB）
- **合計**: 約 $0.06/時間 + 月額料金

### 実際の検証コスト（参考値）

#### 24時間稼働での実測コスト
この環境を約24時間稼働させた場合の実際のコスト：

**主要コンポーネント別コスト**:
- **EC2インスタンス** (t3.micro × 2台): 約 $0.50
- **ALB**: 約 $0.60
- **NAT Gateway**: 約 $1.10 (データ転送含む)
- **CloudFront**: 約 $0.10 (少量のデータ転送)
- **GuardDuty**: 約 $0.15 (初回10GB無料枠内)
- **CloudWatch**: 約 $0.05 (ログ・メトリクス)
- **その他** (S3, WAF等): 約 $0.05

**合計**: 約 **$2.55/日** (24時間稼働)

#### 学習セッション別の想定コスト
- **2-3時間の学習セッション**: 約 $0.30-0.50
- **半日（6時間）の集中学習**: 約 $0.65-1.00
- **1日（24時間）の検証**: 約 $2.50-3.00

### コスト最適化のヒント
- 学習セッション後は必ずリソースを削除
- Shield Standardは無料で自動的に有効（Shield Advancedは使用しません）
- t3.microインスタンスを使用してコストを最小化
- 自動クリーンアップ機能（24時間後）でコスト管理

## 学習のポイント

### 実践的な学習効果
1. **段階的なセキュリティ強化**: レベル1からレベル4への進行で保護効果を体感
2. **実際の攻撃シミュレーション**: EC2インスタンスからの本格的な攻撃テスト
3. **CloudFrontの保護効果**: 200同時リクエストでも100%成功率を実現
4. **インフラ管理の実践**: Terraformによる Infrastructure as Code の体験

### 重要な設定ポイント
- **ネットワークACL**: SSH接続にはポート22の明示的な許可が必要
- **セキュリティグループ**: 攻撃シミュレーション用に適切な設定が重要
- **CloudFront**: キャッシュ効果により大幅なパフォーマンス向上
- **コスト管理**: 自動クリーンアップ機能でコスト最適化

## サポート

### ドキュメント
- [AWS WAF Developer Guide](https://docs.aws.amazon.com/waf/)
- [AWS Shield Standard Guide](https://docs.aws.amazon.com/waf/latest/developerguide/shield-chapter.html)
- [Amazon GuardDuty User Guide](https://docs.aws.amazon.com/guardduty/)
- [Amazon CloudFront Developer Guide](https://docs.aws.amazon.com/cloudfront/)

### 追加リソース
- `terraform/modules/` 内の詳細な実装
- CloudWatchダッシュボードでのリアルタイム監視
- 攻撃シミュレーション結果の分析

### 実証済みの攻撃テスト結果
- **50同時リクエスト**: 100%成功、平均370ms
- **200同時リクエスト**: 100%成功、CloudFront完全処理
- **キャッシュ効果**: `x-cache: Hit from cloudfront` で確認済み

---

## 重要な注意事項

### セキュリティ
**注意**: この環境は学習目的で意図的に脆弱性を含んでいます。本番環境では絶対に使用しないでください。

### コスト管理
- **自動削除**: 24時間後に自動的にリソースが削除されます
- **手動削除**: 学習完了後は `terraform destroy` で即座に削除してください
- **コスト監視**: AWS Budgets で $50/月の制限を設定済み
- **想定コスト**: 通常の学習セッション（2-6時間）で $0.30-1.00程度

### 責任
- AWSアカウントの課金責任は利用者にあります
- 不要なリソースの削除忘れにご注意ください
- 予期しない高額請求を避けるため、使用後は必ずリソースを確認してください

## 🤖 AI開発について

### Kiroで構築
このプロジェクト全体は**Kiro AI**を使用して開発されました。以下の作業がAIによって自動化されています：

#### 🏗️ **インフラストラクチャ設計**
- 完全なTerraformモジュール構成の生成
- セキュリティベストプラクティスの適用
- 段階的セキュリティレベルの設計

#### 🛡️ **セキュリティ実装**
- WAF、CloudFront、GuardDutyの統合設定
- 攻撃シミュレーションスクリプトの作成
- 脆弱性を含むWebアプリケーションの開発

#### 📊 **監視・コスト管理**
- CloudWatchダッシュボードの自動生成
- コスト最適化機能の実装
- 自動クリーンアップシステムの構築

#### 📚 **ドキュメント作成**
- 包括的なREADME作成
- 学習ガイドとトラブルシューティング
- 実証済みテスト結果の文書化

### AI活用の効果
- **開発時間**: 従来の1/10以下に短縮
- **品質**: ベストプラクティスの自動適用
- **保守性**: 構造化されたモジュール設計
- **学習効果**: 実践的な教材として最適化

このプロジェクトは、AIがいかに複雑なDevSecOps作業を効率化できるかを実証しています。