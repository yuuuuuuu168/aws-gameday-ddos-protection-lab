# セキュリティ軽減実装ガイド

このガイドでは、発見された脆弱性に対する具体的な軽減策の実装方法を段階的に説明します。

## 軽減策の優先順位

### 優先度レベル
- **緊急 (P0)**: 即座に実装が必要な重大な脆弱性
- **高 (P1)**: 1週間以内に実装すべき重要な脆弱性
- **中 (P2)**: 1ヶ月以内に実装すべき脆弱性
- **低 (P3)**: 長期的に改善すべき項目

## 1. SQLインジェクション脆弱性の軽減

### 優先度: 緊急 (P0)

#### 即効性対策: AWS WAF実装
```hcl
resource "aws_wafv2_web_acl" "sql_injection_protection" {
  name  = "gameday-sql-injection-protection"
  scope = "REGIONAL"
  
  default_action {
    allow {}
  }
  
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 1
    
    action {
      block {}
    }
    
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLiRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }
}
```

#### アプリケーション修正: パラメータ化クエリ
```javascript
// セキュアなクエリ実装
function authenticateUser(username, password) {
    const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
    return new Promise((resolve, reject) => {
        db.get(query, [username, password], (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

// 入力値検証
function validateInput(input, type) {
    switch(type) {
        case 'username':
            return /^[a-zA-Z0-9_]{3,20}$/.test(input);
        case 'password':
            return /^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/.test(input);
        default:
            return false;
    }
}
```

## 2. XSS脆弱性の軽減

### 優先度: 緊急 (P0)

#### WAF XSS保護
```hcl
rule {
  name     = "AWSManagedRulesKnownBadInputsRuleSet"
  priority = 1
  
  action {
    block {}
  }
  
  statement {
    managed_rule_group_statement {
      name        = "AWSManagedRulesKnownBadInputsRuleSet"
      vendor_name = "AWS"
    }
  }
}
```

#### 出力エスケープの実装
```javascript
const he = require('he');

function escapeHtml(unsafe) {
    return he.encode(unsafe, {
        'useNamedReferences': true,
        'decimal': false
    });
}

// CSP ヘッダー設定
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', 
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    next();
});
```

## 3. ファイルアップロード脆弱性の軽減

### 優先度: 高 (P1)

#### ファイル検証の実装
```javascript
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.txt', '.pdf'];
const DANGEROUS_EXTENSIONS = ['.php', '.asp', '.jsp', '.js', '.exe'];

function validateFile(file) {
    const errors = [];
    
    // ファイルサイズチェック
    if (file.size > 1024 * 1024) {
        errors.push('File size exceeds 1MB limit');
    }
    
    // 拡張子チェック
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
        errors.push(`File extension ${ext} is not allowed`);
    }
    
    if (DANGEROUS_EXTENSIONS.includes(ext)) {
        errors.push(`Dangerous file extension ${ext} detected`);
    }
    
    return {
        isValid: errors.length === 0,
        errors: errors
    };
}
```

## 4. DDoS攻撃の軽減

### 優先度: 高 (P1)

#### レート制限の実装
```hcl
rule {
  name     = "BasicRateLimit"
  priority = 1
  
  action {
    block {}
  }
  
  statement {
    rate_based_statement {
      limit              = 2000
      aggregate_key_type = "IP"
    }
  }
}
```

#### CloudFront設定
```hcl
resource "aws_cloudfront_distribution" "main" {
  origin {
    domain_name = aws_lb.main.dns_name
    origin_id   = "ALB-${aws_lb.main.name}"
  }
  
  default_cache_behavior {
    target_origin_id       = "ALB-${aws_lb.main.name}"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true
    
    min_ttl     = 0
    default_ttl = 300
    max_ttl     = 86400
  }
}
```

## 5. 監視とアラート

### CloudWatch アラーム
```hcl
resource "aws_cloudwatch_metric_alarm" "high_attack_rate" {
  alarm_name          = "gameday-high-attack-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "AttackAttempts"
  threshold           = "50"
  
  alarm_actions = [aws_sns_topic.security_alerts.arn]
}
```

### 自動対応システム
```python
def lambda_handler(event, context):
    message = json.loads(event['Records'][0]['Sns']['Message'])
    alarm_name = message['AlarmName']
    
    if 'high-attack-rate' in alarm_name:
        update_waf_rate_limit(500)
        send_notification("High attack rate detected")
    
    return {'statusCode': 200}
```

## 実装検証

### 検証スクリプト
```bash
#!/bin/bash
echo "=== Security Validation ==="

# SQLインジェクション保護テスト
response=$(curl -s -w "%{http_code}" -X POST "http://<target>/login" \
  -d "username=admin' OR '1'='1-- &password=test")
  
if [ "$response" = "403" ]; then
    echo "✓ SQL Injection protection: PASS"
else
    echo "✗ SQL Injection protection: FAIL"
fi

# XSS保護テスト
response=$(curl -s -w "%{http_code}" "http://<target>/search?q=<script>alert('test')</script>")

if [ "$response" = "403" ]; then
    echo "✓ XSS protection: PASS"
else
    echo "✗ XSS protection: FAIL"
fi
```

この軽減実装ガイドに従って段階的にセキュリティを強化することで、堅牢なセキュリティシステムを構築できます。