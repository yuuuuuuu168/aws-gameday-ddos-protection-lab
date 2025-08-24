# AWS GameDay DDoS Environment

AWS GameDayスタイルの「Winning the DDoS Game」環境を構築するTerraformプロジェクトです。

## プロジェクト構造

```
terraform/
├── main.tf                    # メイン設定
├── variables.tf               # 変数定義
├── outputs.tf                 # 出力定義
├── versions.tf                # Terraformバージョン制約
├── terraform.tfvars.example   # 変数設定例
├── backend.tf.example         # バックエンド設定例
├── .gitignore                 # Git除外設定
└── modules/
    ├── network/               # ネットワークモジュール
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── security/              # セキュリティモジュール
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── compute/               # コンピュートモジュール
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    └── monitoring/            # 監視モジュール
        ├── main.tf
        ├── variables.tf
        └── outputs.tf
```

## セットアップ手順

### 1. 前提条件

- Terraform >= 1.0
- AWS CLI設定済み
- 適切なAWS権限

### 2. 初期設定

```bash
# リポジトリをクローン
cd terraform

# 変数ファイルをコピーして編集
cp terraform.tfvars.example terraform.tfvars
# terraform.tfvarsを編集して環境に合わせて設定

# バックエンド設定をコピーして編集（オプション）
cp backend.tf.example backend.tf
# backend.tfを編集してS3バケット情報を設定
```

### 3. デプロイ

```bash
# Terraform初期化
terraform init

# プランの確認
terraform plan

# 適用
terraform apply
```

### 4. セキュリティレベルの変更

```bash
# セキュリティレベルを変更（1-4）
terraform apply -var="security_level=2"
```

## セキュリティレベル

| レベル | WAF | Shield Advanced | CloudFront | レート制限 |
|--------|-----|----------------|------------|------------|
| 1      | ❌  | ❌             | ❌         | 10,000     |
| 2      | ✅  | ❌             | ❌         | 5,000      |
| 3      | ✅  | ✅             | ❌         | 2,000      |
| 4      | ✅  | ✅             | ✅         | 1,000      |

## モジュール概要

### Network Module
- VPC、サブネット、ルーティングの設定
- パブリック/プライベートサブネット構成
- NAT Gateway、Internet Gateway

### Security Module
- セキュリティグループ
- AWS WAF v2設定
- AWS Shield設定
- CloudFront設定（条件付き）

### Compute Module
- EC2インスタンス（脆弱なWebアプリケーション）
- Application Load Balancer
- 攻撃シミュレーションインスタンス

### Monitoring Module
- CloudWatch監視
- GuardDuty設定
- ログ設定
- コスト監視

## 注意事項

- このプロジェクトは学習目的で意図的に脆弱性を含みます
- 本番環境では使用しないでください
- 使用後は必ずリソースを削除してください

```bash
terraform destroy
```