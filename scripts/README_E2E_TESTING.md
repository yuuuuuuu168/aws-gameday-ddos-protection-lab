# エンドツーエンドセキュリティテストパイプライン

AWS GameDay "Winning the DDoS Game" 環境用の包括的なセキュリティテストパイプラインです。

## 概要

このテストパイプラインは以下の機能を提供します：

1. **マスターセキュリティテスト**: 全セキュリティレベルの包括的な検証
2. **テストレポートシステム**: 詳細な分析レポートとビジュアライゼーション
3. **自動クリーンアップ**: テストサイクル後のリソース管理とリセット

## ファイル構成

```
scripts/
├── master_security_test.sh          # マスターテストスクリプト
├── test_report_generator.py         # レポート生成ツール
├── auto_cleanup_reset.sh            # 自動クリーンアップスクリプト
├── run_end_to_end_tests.sh          # 統合実行スクリプト
├── test_infrastructure.sh           # インフラストラクチャテスト
├── test_vulnerabilities.sh          # 脆弱性テスト
├── test_security_pipeline.sh        # セキュリティパイプラインテスト
└── README_E2E_TESTING.md           # このファイル
```

## 前提条件

### 必須ツール

- **AWS CLI**: AWS認証情報が設定済み
- **Terraform**: バージョン 1.0以上
- **bash**: バージョン 4.0以上
- **curl**: HTTPリクエスト用
- **jq**: JSON処理用

### オプションツール（高度なレポート生成用）

- **Python 3.7+**
- **matplotlib**: チャート生成用
- **pandas**: データ分析用

```bash
# Python依存関係のインストール
pip3 install matplotlib pandas
```

## 基本的な使用方法

### 1. 完全なエンドツーエンドテスト

```bash
# 全セキュリティレベルのテストを実行
./scripts/run_end_to_end_tests.sh

# 特定のセキュリティレベルのみテスト
./scripts/run_end_to_end_tests.sh --levels 1,2,3

# 並列実行でテスト時間を短縮
./scripts/run_end_to_end_tests.sh --parallel

# テスト後に自動クリーンアップ
./scripts/run_end_to_end_tests.sh --cleanup
```

### 2. 個別コンポーネントの実行

#### マスターセキュリティテスト

```bash
# 基本実行
./scripts/master_security_test.sh

# 詳細オプション付き実行
./scripts/master_security_test.sh \
  --levels 1,2,3,4 \
  --region us-east-1 \
  --parallel \
  --verbose \
  --output all \
  --cleanup
```

#### レポート生成

```bash
# JSONレポートから詳細レポートを生成
python3 scripts/test_report_generator.py \
  scripts/reports/master_security_test_report.json \
  --output reports \
  --format all
```

#### 自動クリーンアップ

```bash
# 全リソースのクリーンアップ
./scripts/auto_cleanup_reset.sh --all --force

# 特定リソースのみクリーンアップ
./scripts/auto_cleanup_reset.sh --logs --reports --days 3
```

## 高度な使用方法

### セキュリティレベル別テスト

各セキュリティレベルの設定：

- **レベル 1**: 基本設定のみ（WAF無効、CloudFront無効）
- **レベル 2**: WAF有効（基本的なWeb攻撃保護）
- **レベル 3**: WAF + Shield Advanced（高度なDDoS保護）
- **レベル 4**: 完全保護（CloudFront + WAF + Shield Advanced）

```bash
# レベル1から3まで段階的にテスト
./scripts/master_security_test.sh --levels 1,2,3 --verbose

# レベル4のみテスト（既存環境を使用）
./scripts/master_security_test.sh --levels 4 --skip-deploy
```

### 並列実行とパフォーマンス最適化

```bash
# 並列実行でテスト時間を短縮
./scripts/master_security_test.sh --parallel --timeout 600

# 既存環境を使用してテスト時間を短縮
./scripts/master_security_test.sh --skip-deploy --parallel
```

### カスタムレポート生成

```bash
# HTMLレポートのみ生成
./scripts/run_end_to_end_tests.sh --report-only --output html

# CSVデータのみ生成
./scripts/run_end_to_end_tests.sh --report-only --output csv

# チャート付き包括レポート
python3 scripts/test_report_generator.py \
  scripts/reports/master_security_test_report.json \
  --format all
```

## テスト結果の解釈

### 成功基準

1. **インフラストラクチャテスト**: 
   - セキュリティレベル設定が正しく適用されている
   - WAF、CloudFront、Shieldが期待通りに動作

2. **脆弱性テスト**: 
   - 学習環境として適切な脆弱性が存在する
   - SQLインジェクション、XSS、ファイルアップロード脆弱性が確認できる

3. **DDoS攻撃シミュレーション**: 
   - レベル1-2: 攻撃によるパフォーマンス劣化が確認できる
   - レベル3-4: 攻撃が適切に軽減される

### レポートファイル

テスト実行後、以下のレポートが生成されます：

```
scripts/reports/
├── master_security_test_report.html     # メインHTMLレポート
├── master_security_test_report.json     # 詳細JSONデータ
├── master_security_test_report.csv      # CSV形式データ
├── comprehensive_test_report.md         # 包括的Markdownレポート
├── detailed_test_results.csv           # 詳細テスト結果
├── success_rate_by_level.png           # セキュリティレベル別成功率
├── duration_by_test_type.png           # テストタイプ別実行時間
└── test_result_distribution.png        # テスト結果分布
```

## トラブルシューティング

### よくある問題と解決方法

#### 1. AWS認証エラー

```bash
# AWS認証情報の確認
aws sts get-caller-identity

# 認証情報の設定
aws configure
```

#### 2. Terraformエラー

```bash
# Terraform状態の確認
cd terraform && terraform show

# 状態ファイルの初期化
terraform init -reconfigure
```

#### 3. テストタイムアウト

```bash
# タイムアウト時間を延長
./scripts/master_security_test.sh --timeout 900

# 個別テストの実行
./scripts/test_infrastructure.sh --level 1
```

#### 4. Python依存関係エラー

```bash
# 仮想環境の作成と依存関係インストール
python3 -m venv venv
source venv/bin/activate
pip install matplotlib pandas
```

### ログファイルの確認

```bash
# メインログファイル
tail -f scripts/master_security_test.log

# 個別テストログ
ls scripts/reports/*.log

# エラーログの検索
grep -i error scripts/*.log
```

## 継続的インテグレーション

### GitHub Actions での自動実行

```yaml
name: Security Test Pipeline
on:
  schedule:
    - cron: '0 2 * * 1'  # 毎週月曜日 2:00 AM
  workflow_dispatch:

jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Run E2E Security Tests
        run: |
          chmod +x scripts/run_end_to_end_tests.sh
          ./scripts/run_end_to_end_tests.sh --cleanup --force
      
      - name: Upload Test Reports
        uses: actions/upload-artifact@v3
        with:
          name: security-test-reports
          path: scripts/reports/
```

### Jenkins パイプライン

```groovy
pipeline {
    agent any
    
    triggers {
        cron('H 2 * * 1')  // 毎週月曜日
    }
    
    stages {
        stage('Security Tests') {
            steps {
                sh '''
                    chmod +x scripts/run_end_to_end_tests.sh
                    ./scripts/run_end_to_end_tests.sh --cleanup --force
                '''
            }
        }
        
        stage('Publish Reports') {
            steps {
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'scripts/reports',
                    reportFiles: 'master_security_test_report.html',
                    reportName: 'Security Test Report'
                ])
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'scripts/reports/**/*', fingerprint: true
        }
    }
}
```

## ベストプラクティス

### 1. 定期実行

- 週次または月次でテストを実行
- 環境の健全性を継続的に監視
- 結果の傾向を追跡

### 2. テスト結果の活用

- 失敗したテストの詳細を確認
- インフラストラクチャ設定の改善
- セキュリティ設定の最適化

### 3. チーム共有

- テスト結果をチーム全体で共有
- 知見の蓄積と文書化
- 改善プロセスの標準化

### 4. リソース管理

- テスト後の適切なクリーンアップ
- コスト最適化の実施
- 不要なリソースの定期削除

## サポートとコントリビューション

### 問題報告

問題や改善提案がある場合は、以下の情報を含めてIssueを作成してください：

- 実行環境（OS、ツールバージョン）
- 実行したコマンド
- エラーメッセージ
- ログファイルの関連部分

### 機能拡張

新しい機能やテストケースの追加は、以下のガイドラインに従ってください：

1. 既存のコード構造に従う
2. 適切なエラーハンドリングを実装
3. ログ出力を統一形式で実装
4. ドキュメントを更新

## ライセンス

このプロジェクトはMITライセンスの下で公開されています。