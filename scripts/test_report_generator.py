#!/usr/bin/env python3
"""
テストレポート生成ユーティリティ
JSONテスト結果から詳細な分析レポートを生成
"""

import json
import sys
import os
import argparse
from datetime import datetime
from typing import Dict, List, Any
import matplotlib.pyplot as plt
import pandas as pd
from pathlib import Path

class SecurityTestReportGenerator:
    """セキュリティテストレポート生成クラス"""
    
    def __init__(self, json_file: str, output_dir: str = "reports"):
        self.json_file = json_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.data = self._load_json_data()
        
    def _load_json_data(self) -> Dict[str, Any]:
        """JSONデータの読み込み"""
        try:
            with open(self.json_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"エラー: JSONファイルが見つかりません: {self.json_file}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"エラー: JSONファイルの解析に失敗しました: {e}")
            sys.exit(1)
    
    def generate_summary_report(self) -> str:
        """サマリーレポートの生成"""
        summary = self.data.get('summary', {})
        execution = self.data.get('test_execution', {})
        
        report = f"""
# AWS GameDay セキュリティテスト サマリーレポート

## 実行情報
- **実行日時**: {execution.get('timestamp', 'N/A')}
- **AWSリージョン**: {execution.get('aws_region', 'N/A')}
- **テスト対象レベル**: {', '.join(map(str, execution.get('security_levels_tested', [])))}
- **並列実行**: {'有効' if execution.get('parallel_execution', False) else '無効'}
- **タイムアウト**: {execution.get('test_timeout', 'N/A')}秒

## テスト結果サマリー
- **総テスト数**: {summary.get('total_tests', 0)}
- **成功**: {summary.get('passed_tests', 0)}
- **失敗**: {summary.get('failed_tests', 0)}
- **スキップ**: {summary.get('skipped_tests', 0)}
- **成功率**: {summary.get('success_rate', 0):.1f}%

## セキュリティレベル別分析
"""
        
        # セキュリティレベル別の詳細分析
        test_results = self.data.get('test_results', {})
        security_configs = self.data.get('security_configurations', {})
        
        levels = execution.get('security_levels_tested', [])
        for level in levels:
            level_key = f"level_{level}"
            config = security_configs.get(level_key, "設定情報なし")
            
            report += f"\n### レベル {level}: {config}\n\n"
            
            # レベル別テスト結果
            level_tests = {k: v for k, v in test_results.items() if f"_level_{level}" in k}
            
            for test_key, test_data in level_tests.items():
                test_type = test_key.split('_')[0]
                test_name = {
                    'infra': 'インフラストラクチャテスト',
                    'vuln': '脆弱性テスト',
                    'ddos': 'DDoS攻撃シミュレーション'
                }.get(test_type, test_type)
                
                status = test_data.get('status', 'N/A')
                duration = test_data.get('duration_seconds', 0)
                
                status_emoji = {
                    'PASS': '✅',
                    'FAIL': '❌',
                    'TIMEOUT': '⏰',
                    'SKIPPED': '⏭️'
                }.get(status, '❓')
                
                report += f"- **{test_name}**: {status_emoji} {status} ({duration}秒)\n"
        
        return report
    
    def generate_detailed_analysis(self) -> str:
        """詳細分析レポートの生成"""
        test_results = self.data.get('test_results', {})
        
        analysis = """
# 詳細テスト分析レポート

## テストタイプ別パフォーマンス分析

"""
        
        # テストタイプ別の統計
        test_types = ['infra', 'vuln', 'ddos']
        type_names = {
            'infra': 'インフラストラクチャテスト',
            'vuln': '脆弱性テスト',
            'ddos': 'DDoS攻撃シミュレーション'
        }
        
        for test_type in test_types:
            type_tests = {k: v for k, v in test_results.items() if k.startswith(test_type)}
            
            if not type_tests:
                continue
                
            analysis += f"\n### {type_names[test_type]}\n\n"
            
            # 統計計算
            total_count = len(type_tests)
            pass_count = sum(1 for v in type_tests.values() if v.get('status') == 'PASS')
            fail_count = sum(1 for v in type_tests.values() if v.get('status') == 'FAIL')
            avg_duration = sum(v.get('duration_seconds', 0) for v in type_tests.values()) / total_count if total_count > 0 else 0
            
            analysis += f"- **実行回数**: {total_count}\n"
            analysis += f"- **成功回数**: {pass_count}\n"
            analysis += f"- **失敗回数**: {fail_count}\n"
            analysis += f"- **成功率**: {(pass_count / total_count * 100):.1f}%\n"
            analysis += f"- **平均実行時間**: {avg_duration:.1f}秒\n\n"
            
            # 個別結果
            analysis += "#### 個別テスト結果\n\n"
            for test_key, test_data in sorted(type_tests.items()):
                level = test_key.split('_')[-1]
                status = test_data.get('status', 'N/A')
                duration = test_data.get('duration_seconds', 0)
                details = test_data.get('details', '')[:200] + ('...' if len(test_data.get('details', '')) > 200 else '')
                
                analysis += f"**レベル {level}**\n"
                analysis += f"- ステータス: {status}\n"
                analysis += f"- 実行時間: {duration}秒\n"
                analysis += f"- 詳細: {details}\n\n"
        
        return analysis
    
    def generate_performance_charts(self) -> List[str]:
        """パフォーマンスチャートの生成"""
        test_results = self.data.get('test_results', {})
        chart_files = []
        
        try:
            import matplotlib.pyplot as plt
            import matplotlib
            matplotlib.use('Agg')  # GUI不要のバックエンド
            
            # 日本語フォント設定
            plt.rcParams['font.family'] = ['DejaVu Sans', 'Hiragino Sans', 'Yu Gothic', 'Meiryo', 'Takao', 'IPAexGothic', 'IPAPGothic', 'VL PGothic', 'Noto Sans CJK JP']
            
        except ImportError:
            print("警告: matplotlibが利用できません。チャート生成をスキップします。")
            return chart_files
        
        # 1. セキュリティレベル別成功率チャート
        levels = self.data.get('test_execution', {}).get('security_levels_tested', [])
        level_success_rates = []
        
        for level in levels:
            level_tests = {k: v for k, v in test_results.items() if f"_level_{level}" in k}
            if level_tests:
                pass_count = sum(1 for v in level_tests.values() if v.get('status') == 'PASS')
                total_count = len(level_tests)
                success_rate = (pass_count / total_count * 100) if total_count > 0 else 0
                level_success_rates.append(success_rate)
            else:
                level_success_rates.append(0)
        
        if levels and level_success_rates:
            plt.figure(figsize=(10, 6))
            bars = plt.bar([f"Level {l}" for l in levels], level_success_rates, 
                          color=['#28a745' if rate >= 80 else '#ffc107' if rate >= 60 else '#dc3545' for rate in level_success_rates])
            plt.title('セキュリティレベル別テスト成功率')
            plt.ylabel('成功率 (%)')
            plt.ylim(0, 100)
            
            # バーの上に数値を表示
            for bar, rate in zip(bars, level_success_rates):
                plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, 
                        f'{rate:.1f}%', ha='center', va='bottom')
            
            chart_file = self.output_dir / "success_rate_by_level.png"
            plt.tight_layout()
            plt.savefig(chart_file, dpi=300, bbox_inches='tight')
            plt.close()
            chart_files.append(str(chart_file))
        
        # 2. テストタイプ別実行時間チャート
        test_types = ['infra', 'vuln', 'ddos']
        type_names = ['Infrastructure', 'Vulnerability', 'DDoS Simulation']
        type_durations = []
        
        for test_type in test_types:
            type_tests = {k: v for k, v in test_results.items() if k.startswith(test_type)}
            if type_tests:
                avg_duration = sum(v.get('duration_seconds', 0) for v in type_tests.values()) / len(type_tests)
                type_durations.append(avg_duration)
            else:
                type_durations.append(0)
        
        if type_durations:
            plt.figure(figsize=(10, 6))
            bars = plt.bar(type_names, type_durations, color=['#007bff', '#28a745', '#dc3545'])
            plt.title('テストタイプ別平均実行時間')
            plt.ylabel('実行時間 (秒)')
            
            # バーの上に数値を表示
            for bar, duration in zip(bars, type_durations):
                plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, 
                        f'{duration:.1f}s', ha='center', va='bottom')
            
            chart_file = self.output_dir / "duration_by_test_type.png"
            plt.tight_layout()
            plt.savefig(chart_file, dpi=300, bbox_inches='tight')
            plt.close()
            chart_files.append(str(chart_file))
        
        # 3. 全体的なテスト結果分布
        summary = self.data.get('summary', {})
        labels = ['成功', '失敗', 'スキップ']
        sizes = [summary.get('passed_tests', 0), summary.get('failed_tests', 0), summary.get('skipped_tests', 0)]
        colors = ['#28a745', '#dc3545', '#6c757d']
        
        if sum(sizes) > 0:
            plt.figure(figsize=(8, 8))
            wedges, texts, autotexts = plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            plt.title('テスト結果分布')
            
            chart_file = self.output_dir / "test_result_distribution.png"
            plt.tight_layout()
            plt.savefig(chart_file, dpi=300, bbox_inches='tight')
            plt.close()
            chart_files.append(str(chart_file))
        
        return chart_files
    
    def export_to_csv(self) -> str:
        """CSV形式でのデータエクスポート"""
        test_results = self.data.get('test_results', {})
        
        # データフレーム用のデータ準備
        rows = []
        for test_key, test_data in test_results.items():
            parts = test_key.split('_')
            test_type = parts[0]
            security_level = parts[-1]
            
            row = {
                'Test_Type': test_type,
                'Security_Level': security_level,
                'Status': test_data.get('status', 'N/A'),
                'Duration_Seconds': test_data.get('duration_seconds', 0),
                'Details': test_data.get('details', '')[:500]  # 詳細は500文字まで
            }
            rows.append(row)
        
        try:
            df = pd.DataFrame(rows)
            csv_file = self.output_dir / "detailed_test_results.csv"
            df.to_csv(csv_file, index=False, encoding='utf-8')
            return str(csv_file)
        except ImportError:
            print("警告: pandasが利用できません。CSV出力をスキップします。")
            return ""
    
    def generate_comprehensive_report(self) -> str:
        """包括的なレポートの生成"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = f"""# AWS GameDay セキュリティテスト 包括レポート

生成日時: {timestamp}

"""
        
        # サマリーレポートを追加
        report += self.generate_summary_report()
        
        # 詳細分析を追加
        report += "\n---\n"
        report += self.generate_detailed_analysis()
        
        # 推奨事項を追加
        report += self._generate_recommendations()
        
        return report
    
    def _generate_recommendations(self) -> str:
        """推奨事項の生成"""
        test_results = self.data.get('test_results', {})
        summary = self.data.get('summary', {})
        
        recommendations = """
# 推奨事項と改善点

## 全般的な推奨事項

"""
        
        success_rate = summary.get('success_rate', 0)
        
        if success_rate < 70:
            recommendations += """
### 🔴 緊急対応が必要
- テスト成功率が70%を下回っています
- インフラストラクチャ設定を見直してください
- デプロイメントプロセスを確認してください
"""
        elif success_rate < 90:
            recommendations += """
### 🟡 改善の余地があります
- テスト成功率を90%以上に向上させることを推奨します
- 失敗したテストの詳細を確認し、設定を調整してください
"""
        else:
            recommendations += """
### 🟢 良好な状態です
- テスト成功率が90%以上で、システムは適切に動作しています
- 継続的な監視を続けてください
"""
        
        # テストタイプ別の推奨事項
        test_types = ['infra', 'vuln', 'ddos']
        type_names = {
            'infra': 'インフラストラクチャテスト',
            'vuln': '脆弱性テスト',
            'ddos': 'DDoS攻撃シミュレーション'
        }
        
        for test_type in test_types:
            type_tests = {k: v for k, v in test_results.items() if k.startswith(test_type)}
            if not type_tests:
                continue
            
            fail_count = sum(1 for v in type_tests.values() if v.get('status') == 'FAIL')
            total_count = len(type_tests)
            
            if fail_count > 0:
                recommendations += f"\n### {type_names[test_type]}の改善点\n"
                
                if test_type == 'infra':
                    recommendations += """
- Terraformの設定ファイルを確認してください
- AWSリソースの作成状況を確認してください
- セキュリティグループとネットワーク設定を見直してください
"""
                elif test_type == 'vuln':
                    recommendations += """
- アプリケーションの脆弱性設定を確認してください
- 学習環境として適切な脆弱性が実装されているか確認してください
- テストスクリプトのペイロードを見直してください
"""
                elif test_type == 'ddos':
                    recommendations += """
- WAFとShieldの設定を確認してください
- CloudFrontの設定を見直してください
- レート制限の設定を調整してください
"""
        
        recommendations += """
## 継続的改善のための提案

1. **定期的なテスト実行**: 週次または月次でテストを実行し、環境の健全性を確認
2. **テスト結果の追跡**: 過去のテスト結果と比較して、パフォーマンスの傾向を把握
3. **アラート設定**: テスト失敗時の自動通知システムの構築
4. **ドキュメント更新**: テスト結果に基づいて運用ドキュメントを更新
5. **チーム共有**: テスト結果をチーム全体で共有し、知見を蓄積

## 次のステップ

1. 失敗したテストの詳細ログを確認
2. 必要に応じてインフラストラクチャ設定を調整
3. 修正後に再テストを実行
4. 結果を記録し、改善プロセスを文書化
"""
        
        return recommendations

def main():
    parser = argparse.ArgumentParser(description='セキュリティテストレポート生成ツール')
    parser.add_argument('json_file', help='入力JSONファイルパス')
    parser.add_argument('-o', '--output', default='reports', help='出力ディレクトリ (デフォルト: reports)')
    parser.add_argument('-f', '--format', choices=['markdown', 'csv', 'charts', 'all'], 
                       default='all', help='出力形式 (デフォルト: all)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.json_file):
        print(f"エラー: JSONファイルが見つかりません: {args.json_file}")
        sys.exit(1)
    
    generator = SecurityTestReportGenerator(args.json_file, args.output)
    
    print(f"テストレポートを生成中... (出力先: {args.output})")
    
    if args.format in ['markdown', 'all']:
        # Markdownレポートの生成
        report_content = generator.generate_comprehensive_report()
        report_file = generator.output_dir / "comprehensive_test_report.md"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"✅ Markdownレポートが生成されました: {report_file}")
    
    if args.format in ['csv', 'all']:
        # CSVエクスポート
        csv_file = generator.export_to_csv()
        if csv_file:
            print(f"✅ CSVファイルが生成されました: {csv_file}")
    
    if args.format in ['charts', 'all']:
        # チャート生成
        chart_files = generator.generate_performance_charts()
        for chart_file in chart_files:
            print(f"✅ チャートが生成されました: {chart_file}")
    
    print("🎉 レポート生成が完了しました!")

if __name__ == "__main__":
    main()