# AWS GameDay DDoS Protection Lab

AWSでのDDoS攻撃対策とWebアプリケーションセキュリティを実践的に学習するための包括的なハンズオン環境です。このプロジェクトでは、攻撃をシミュレートし、段階的なセキュリティ対策を実装するリアルなGameDay体験を提供します。

**🤖 Kiro AIで構築** - このプロジェクト全体はKiro（AI支援開発アシスタント）を使用して開発され、AI支援によるインフラ・セキュリティエンジニアリングの可能性を実証しています。

## 🎯 学習できること
- 段階的なDDoS保護戦略（4つのセキュリティレベル）
- AWS WAFの設定とルール管理
- セキュリティレイヤーとしてのCloudFront活用
- GuardDutyによる脅威検知
- TerraformによるInfrastructure as Code
- 実際の攻撃シミュレーションと対策
- AI支援開発ワークフロー

## 🏗️ アーキテクチャ
- 意図的に脆弱性を含むWebアプリケーション
- 攻撃シミュレーション用EC2インスタンス
- 段階的セキュリティ制御（WAF → GuardDuty → CloudFront）
- 包括的な監視・アラート機能
- 自動コスト管理システム

## 💰 コスト効率
- 通常の学習セッション：$0.30-1.00（2-6時間）
- 24時間後の自動クリーンアップ
- t3.microインスタンス使用で最小コスト

## 🤖 AI開発ストーリー
このプロジェクトは、AIが複雑なインフラ開発をいかに加速できるかを示しています：
- **完全なTerraformモジュール**の生成とテスト
- **セキュリティ設定**のベストプラクティス設計
- **攻撃シミュレーションスクリプト**のリアルなテスト作成
- **包括的なドキュメント**の自動生成
- **コスト最適化**の最初からの組み込み

DevSecOpsにおけるAI-人間協働の完璧な実例です！

## 🚀 クイックスタート

### 前提条件
- AWSアカウント
- Terraform v1.0以上
- AWS CLI v2.0以上

### デプロイ手順
```bash
# リポジトリのクローン
git clone https://github.com/your-username/aws-gameday-ddos-protection-lab.git
cd aws-gameday-ddos-protection-lab

# 設定ファイルのコピー
cp terraform/terraform.tfvars.example terraform/terraform.tfvars

# 設定の編集（メールアドレスなど）
vim terraform/terraform.tfvars

# デプロイ実行
cd terraform
terraform init
terraform apply
