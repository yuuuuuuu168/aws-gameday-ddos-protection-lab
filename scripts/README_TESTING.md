# AWS GameDay セキュリティテストフレームワーク

このディレクトリには、AWS GameDay「Winning the DDoS Game」環境の自動テストと検証を行うためのスクリプトが含まれています。

## テストスクリプト概要

### 1. インフラストラクチャテスト (`test_infrastructure.sh`)

各セキュリティレベルの設定を検証し、WAFルール効果とCloudWatchメトリクスを確認します。

**機能:**
- セキュリティレベル設定の検証
- WAFルール効果のテスト
- CloudWatchメトリクスの確認
- GuardDutyの動作確認

**使用例:**
```bash
# 全セキュリティレベルのテスト
./test_infrastructure.sh --level all

# 特定のセキュリティレベルのテスト
./test_infrastructure.sh --level 2 --region us-west-2

# ヘルプの表示
./test_infrastructure.sh --help
```

### 2. 脆弱性テスト (`test_vulnerabilities.sh`)

アプリケーションの意図的な脆弱性が正しく動作することを確認します。

**テスト対象:**
- SQLインジェクション脆弱性
- XSS脆弱性
- ファイルアップロード脆弱性
- 認証弱点

**使用例:**
```bash
# 全脆弱性テストの実行
./test_vulnerabilities.sh --test all

# 特定の脆弱性テスト
./test_vulnerabilities.sh --test sqli --verbose

# カスタムURLでのテスト
./test_vulnerabilities.sh --url http://example.com --test xss
```

### 3. エンドツーエンドテストパイプライン (`test_security_pipeline.sh`)

全セキュリティレベルの包括的なテストを自動実行し、詳細なレポートを生成します。

**機能:**
- 自動デプロイメント
- 全セキュリティレベルのテスト
- DDoS攻撃シミュレーション
- HTMLおよびJSONレポート生成
- 自動クリーンアップ

**使用例:**
```bash
# 全セキュリティレベルの完全テスト
./test_security_pipeline.sh --levels all --output both

# 特定レベルのテスト（クリーンアップ付き）
./test_security_pipeline.sh --levels 1,2,3 --cleanup

# 既存環境でのテスト（デプロイスキップ）
./test_security_pipeline.sh --skip-deploy --output html
```

## テスト結果の解釈

### 期待される結果

#### セキュリティレベル1（基本設定）
- **インフラ**: WAF無効、CloudFront無効
- **脆弱性**: 全ての脆弱性が検出される（PASS）
- **DDoS**: 攻撃が効果的（パフォーマンス劣化）

#### セキュリティレベル2（WAF有効）
- **インフラ**: WAF有効、CloudFront無効
- **脆弱性**: 一部の攻撃がブロックされる
- **DDoS**: 基本的な保護効果

#### セキュリティレベル3（Shield Advanced）
- **インフラ**: WAF + Shield Advanced有効
- **脆弱性**: より多くの攻撃がブロックされる
- **DDoS**: 高度な保護効果

#### セキュリティレベル4（完全保護）
- **インフラ**: 全保護機能有効
- **脆弱性**: 最大限の保護
- **DDoS**: 最高レベルの保護効果

### レポートファイル

テスト実行後、以下のファイルが生成されます：

- `security_test_report.html`: 視覚的なHTMLレポート
- `security_test_report.json`: 機械可読なJSONレポート
- `security_pipeline.log`: 詳細な実行ログ
- `infrastructure_test.log`: インフラテストログ
- `vulnerability_test.log`: 脆弱性テストログ

## 前提条件

### 必要なツール
- AWS CLI（設定済み）
- Terraform
- curl
- jq
- bc（計算用）

### AWS権限
以下のAWSサービスへのアクセス権限が必要です：
- EC2
- ALB
- WAF v2
- CloudFront
- Shield
- GuardDuty
- CloudWatch
- CloudWatch Logs

### 環境設定
```bash
# AWS認証情報の設定
aws configure

# 必要なツールのインストール（macOS）
brew install jq bc

# スクリプトの実行権限付与
chmod +x *.sh
```

## トラブルシューティング

### よくある問題

1. **Terraform出力が取得できない**
   ```bash
   cd ../terraform
   terraform output
   ```

2. **AWS認証エラー**
   ```bash
   aws sts get-caller-identity
   ```

3. **アプリケーションにアクセスできない**
   - セキュリティグループの設定確認
   - ALBのヘルスチェック状態確認

4. **WAFテストが失敗する**
   - WAFルールの設定確認
   - ログでブロック状況を確認

### ログの確認

詳細なログは各テストスクリプトが生成するログファイルで確認できます：

```bash
# 最新のテスト結果を確認
tail -f security_pipeline.log

# エラーのみを抽出
grep ERROR *.log

# 成功したテストを確認
grep SUCCESS *.log
```

## カスタマイズ

### テストの追加

新しいテストを追加する場合：

1. 個別テストスクリプトに新しいテスト関数を追加
2. `test_security_pipeline.sh`に統合
3. レポート生成部分を更新

### 設定の変更

テスト設定を変更する場合：

- タイムアウト値の調整
- 攻撃パラメータの変更
- レポート形式のカスタマイズ

## セキュリティ注意事項

- このテストフレームワークは学習環境専用です
- 本番環境では使用しないでください
- テスト後は必ずリソースをクリーンアップしてください
- 攻撃シミュレーションは隔離された環境でのみ実行してください

## サポート

問題が発生した場合：

1. ログファイルを確認
2. AWS CloudWatchでメトリクスを確認
3. Terraformの状態を確認
4. 必要に応じてリソースを手動でクリーンアップ