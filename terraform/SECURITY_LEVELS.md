# AWS GameDay DDoS Environment - Security Levels

このドキュメントでは、AWS GameDay DDoS環境の段階的セキュリティ強化システムについて説明します。

## セキュリティレベル概要

環境は4つのセキュリティレベルで構成されており、各レベルで異なる保護機能が有効になります。

### Level 1: Baseline (No Protection)
**目的**: 攻撃の影響を直接体験する

**有効な機能**:
- 脆弱なWebアプリケーション
- 基本的な監視（CloudWatch）
- セキュリティグループによる最小限のネットワーク制御

**無効な機能**:
- AWS WAF
- AWS Shield Advanced
- CloudFront

**設定値**:
- Rate Limit: 10,000 requests/5min per IP
- WAF Mode: 無効

**学習目標**:
- 無防備な状態でのDDoS攻撃の影響を理解
- 脆弱性の悪用方法を学習
- ベースライン性能の測定

### Level 2: Basic WAF Protection
**目的**: 基本的なWeb Application Firewallの効果を学習

**有効な機能**:
- AWS WAF v2 with managed rule groups
  - AWSManagedRulesCommonRuleSet
  - AWSManagedRulesKnownBadInputsRuleSet
  - AWSManagedRulesSQLiRuleSet
- Rate-based rules for DDoS protection
- Custom rules for common attack patterns

**設定値**:
- Rate Limit: 5,000 requests/5min per IP
- WAF Mode: BLOCK
- SQL Injection Protection: 有効
- XSS Protection: 有効

**学習目標**:
- WAFによる攻撃ブロックの効果を確認
- False Positiveの理解
- WAFログの分析方法を学習

### Level 3: Advanced Protection (WAF + Shield)
**目的**: 高度なDDoS保護の効果を体験

**有効な機能**:
- Level 2の全機能
- AWS Shield Advanced
- 強化されたDDoS保護
- より厳しいRate Limiting

**設定値**:
- Rate Limit: 2,000 requests/5min per IP
- Shield Advanced: 有効
- DDoS Response Team (DRT) access: 設定可能

**学習目標**:
- Shield Advancedの自動DDoS軽減機能を理解
- 大規模攻撃に対する保護効果を確認
- コスト保護機能の理解

### Level 4: Full Protection (CloudFront + WAF + Shield)
**目的**: 完全な保護スタックの効果を体験

**有効な機能**:
- Level 3の全機能
- CloudFront CDN
- Global edge locations
- Origin Access Control (OAC)
- CloudFront-specific WAF rules

**設定値**:
- Rate Limit: 1,000 requests/5min per IP
- CloudFront: 有効
- Edge Caching: 有効
- Origin Protection: 有効

**学習目標**:
- CDNによる攻撃分散効果を理解
- キャッシュによる性能向上を確認
- グローバル保護の効果を体験

## セキュリティレベルの変更方法

### 1. 手動でTerraform変数を変更

```bash
# terraform.tfvarsファイルを編集
echo "security_level = 2" > terraform.tfvars

# 変更を適用
terraform plan -var="security_level=2"
terraform apply -var="security_level=2"
```

### 2. セキュリティレベル管理スクリプトを使用

```bash
# 利用可能なセキュリティレベルを表示
./scripts/security-level-manager.sh show

# 現在のステータスを確認
./scripts/security-level-manager.sh status

# セキュリティレベルを変更
./scripts/security-level-manager.sh set 2

# セキュリティテストを実行
./scripts/security-level-manager.sh test
```

## 各レベルでのリソース構成

| リソース | Level 1 | Level 2 | Level 3 | Level 4 |
|---------|---------|---------|---------|---------|
| EC2 Instance | ✓ | ✓ | ✓ | ✓ |
| ALB | ✓ | ✓ | ✓ | ✓ |
| WAF v2 | ✗ | ✓ | ✓ | ✓ |
| Shield Advanced | ✗ | ✗ | ✓ | ✓ |
| CloudFront | ✗ | ✗ | ✗ | ✓ |
| CloudFront WAF | ✗ | ✗ | ✗ | ✓ |

## コスト考慮事項

### Level 1
- 最小コスト
- EC2 t3.micro + ALB + 基本監視

### Level 2
- WAF料金追加
- 約 $1-5/月 追加（リクエスト量による）

### Level 3
- Shield Advanced料金追加
- 約 $3,000/月 追加（本格運用時）
- 学習環境では短期間のみ使用推奨

### Level 4
- CloudFront料金追加
- データ転送料金
- 約 $1-10/月 追加（使用量による）

## 推奨学習パス

1. **Level 1で開始**: ベースライン攻撃の影響を確認
2. **Level 2に移行**: WAFの基本保護効果を学習
3. **Level 3で体験**: 高度なDDoS保護を短時間テスト
4. **Level 4で完了**: 完全保護スタックの効果を確認

## トラブルシューティング

### よくある問題

1. **CloudFrontの展開に時間がかかる**
   - CloudFrontの展開には15-20分かかる場合があります
   - `terraform apply`の完了を待ってからテストしてください

2. **WAFルールが期待通りに動作しない**
   - WAFルールの適用には数分かかる場合があります
   - CloudWatchメトリクスでルールの動作を確認してください

3. **Shield Advancedのコスト**
   - Shield Advancedは高額なサービスです
   - 学習目的では短時間のみ有効にしてください
   - 使用後は必ずLevel 2以下に戻してください

### ログとメトリクス

各レベルで以下のログとメトリクスが利用可能です:

- **CloudWatch Logs**: アプリケーション、ALB、WAFログ
- **CloudWatch Metrics**: ALB、WAF、CloudFrontメトリクス
- **GuardDuty**: 脅威検知アラート
- **WAF Sampled Requests**: ブロックされたリクエストの詳細

## セキュリティテスト

各レベルで以下のテストを実行できます:

```bash
# 基本接続テスト
curl -I http://your-alb-url

# SQL Injectionテスト
curl -X POST "http://your-alb-url/login" \
  -d "username=admin' OR '1'='1&password=test"

# XSSテスト
curl "http://your-alb-url/search?q=<script>alert('xss')</script>"

# Rate Limitテスト
for i in {1..100}; do curl -s http://your-alb-url & done
```

## 次のステップ

セキュリティレベルの理解ができたら、以下の高度なトピックに進んでください:

1. カスタムWAFルールの作成
2. GuardDutyアラートの設定
3. 自動応答システムの構築
4. コスト最適化戦略の実装