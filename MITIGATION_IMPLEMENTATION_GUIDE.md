# セキュリティ軽減実装ガイド

このガイドでは、発見された脆弱性に対する具体的な軽減策の実装方法を段階的に説明します。各軽減策は実装の難易度と効果に応じて優先順位付けされています。

## 軽減策の優先順位

### 優先度レベル
- **緊急 (P0)**: 即座に実装が必要な重大な脆弱性
- **高 (P1)**: 1週間以内に実装すべき重要な脆弱性
- **中 (P2)**: 1ヶ月以内に実装すべき脆弱性
- **低 (P3)**: 長期的に改善すべき項目

### 実装アプローチ
1. **即効性対策**: 既存のAWSサービスを活用した迅速な保護
2. **アプリケーション修正**: ソースコードレベルでの根本的な修正
3. **インフラ強化**: インフラストラクチャレベルでの防御強化
4. **運用改善**: 監視・対応プロセスの改善

## 1. SQLインジェクション脆弱性の軽減

### 優先度: 緊急 (P0)

### 1.1 即効性対策: AWS WAF実装

#### ステップ1: WAF Web ACLの作成
```hcl
# terraform/modules/security/waf.tf
resource "aws_wafv2_web_acl" "sql_injection_protection" {
  name  = "gameday-sql-injection-protection"
  scope = "REGIONAL"
  
  default_action {
    allow {}
  }
  
  # SQLインジェクション保護ルール
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
  
  # カスタムSQLインジェクションルール
  rule {
    name     = "CustomSQLiRule"
    priority = 2
    
    action {
      block {}
    }
    
    statement {
      sqli_match_statement {
        field_to_match {
          all_query_arguments {}
        }
        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CustomSQLiMetric"
      sampled_requests_enabled   = true
    }
  }
}
```

#### ステップ2: WAFの関連付け
```hcl
# ALBとWAFの関連付け
resource "aws_wafv2_web_acl_association" "alb_association" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.sql_injection_protection.arn
}
```

#### ステップ3: 実装と検証
```bash
# 1. Terraformでの実装
cd terraform
terraform plan -target=aws_wafv2_web_acl.sql_injection_protection
terraform apply -target=aws_wafv2_web_acl.sql_injection_protection

# 2. WAF設定の確認
aws wafv2 get-web-acl --scope REGIONAL --id <web-acl-id>

# 3. 保護効果のテスト
curl -X POST "http://<target-url>/login" \
  -d "username=admin' OR '1'='1-- &password=test"
# 期待される結果: 403 Forbidden
```

### 1.2 アプリケーション修正: パラメータ化クエリの実装

#### ステップ1: 脆弱なコードの特定
```javascript
// vulnerable-app/database/vulnerable_queries.js (修正前)
const sqlite3 = require('sqlite3').verbose();

// 脆弱なクエリ実装
function authenticateUser(username, password) {
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    // 直接文字列結合 - SQLインジェクション脆弱性
    return new Promise((resolve, reject) => {
        db.get(query, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}
```

#### ステップ2: セキュアなコードへの修正
```javascript
// vulnerable-app/database/secure_queries.js (修正後)
const sqlite3 = require('sqlite3').verbose();

// セキュアなクエリ実装
function authenticateUser(username, password) {
    const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
    // パラメータ化クエリ使用
    return new Promise((resolve, reject) => {
        db.get(query, [username, password], (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

// 検索機能のセキュア実装
function searchUsers(searchTerm) {
    const query = `SELECT id, username, email FROM users WHERE username LIKE ? OR email LIKE ?`;
    const searchPattern = `%${searchTerm}%`;
    
    return new Promise((resolve, reject) => {
        db.all(query, [searchPattern, searchPattern], (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

// 入力値検証の追加
function validateInput(input, type) {
    switch(type) {
        case 'username':
            // 英数字とアンダースコアのみ許可
            return /^[a-zA-Z0-9_]{3,20}$/.test(input);
        case 'email':
            // 基本的なメール形式チェック
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
        case 'password':
            // 最低8文字、英数字を含む
            return /^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/.test(input);
        default:
            return false;
    }
}

module.exports = {
    authenticateUser,
    searchUsers,
    validateInput
};
```

#### ステップ3: アプリケーションの更新
```javascript
// vulnerable-app/app.js (修正部分)
const secureQueries = require('./database/secure_queries');

// ログイン処理の修正
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    // 入力値検証
    if (!secureQueries.validateInput(username, 'username')) {
        return res.status(400).json({ error: 'Invalid username format' });
    }
    
    if (!secureQueries.validateInput(password, 'password')) {
        return res.status(400).json({ error: 'Invalid password format' });
    }
    
    try {
        // パスワードハッシュ化（本来は登録時に実装）
        const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
        
        const user = await secureQueries.authenticateUser(username, hashedPassword);
        if (user) {
            req.session.userId = user.id;
            res.json({ success: true, message: 'Login successful' });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
```

#### ステップ4: デプロイと検証
```bash
# 1. アプリケーションの更新
cd vulnerable-app
npm install bcrypt  # より安全なパスワードハッシュ化
pm2 restart gameday-app

# 2. 修正効果の確認
curl -X POST "http://<target-url>/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin' OR '1'='1-- &password=test"
# 期待される結果: 400 Bad Request (入力値検証エラー)

# 3. 正常な動作確認
curl -X POST "http://<target-url>/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=validpass123"
# 期待される結果: 正常なレスポンス
```

## 2. XSS脆弱性の軽減

### 優先度: 緊急 (P0)

### 2.1 即効性対策: WAF XSS保護

#### ステップ1: XSS保護ルールの追加
```hcl
# terraform/modules/security/waf_xss.tf
resource "aws_wafv2_web_acl" "xss_protection" {
  name  = "gameday-xss-protection"
  scope = "REGIONAL"
  
  default_action {
    allow {}
  }
  
  # XSS保護ルール
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
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputsMetric"
      sampled_requests_enabled   = true
    }
  }
  
  # カスタムXSSルール
  rule {
    name     = "CustomXSSRule"
    priority = 2
    
    action {
      block {}
    }
    
    statement {
      xss_match_statement {
        field_to_match {
          all_query_arguments {}
        }
        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CustomXSSMetric"
      sampled_requests_enabled   = true
    }
  }
}
```

### 2.2 アプリケーション修正: 出力エスケープの実装

#### ステップ1: セキュアなテンプレート実装
```javascript
// vulnerable-app/utils/security.js
const he = require('he'); // HTML entities ライブラリ

// HTMLエスケープ関数
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') {
        return unsafe;
    }
    
    return he.encode(unsafe, {
        'useNamedReferences': true,
        'decimal': false
    });
}

// JavaScriptエスケープ関数
function escapeJs(unsafe) {
    if (typeof unsafe !== 'string') {
        return unsafe;
    }
    
    return unsafe
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/\t/g, '\\t');
}

// URLエスケープ関数
function escapeUrl(unsafe) {
    if (typeof unsafe !== 'string') {
        return unsafe;
    }
    
    return encodeURIComponent(unsafe);
}

// CSP (Content Security Policy) ヘッダー生成
function generateCSPHeader() {
    return "de築できます。ティシステムを構キュリ境でも適用可能な堅牢なセ本番環を強化することで、実際のにセキュリティて段階的装ガイドに従っ軽減実・訓練の実施

この新
- 教育キュリティポリシーの更サービスの評価
- セ 新しいAWS強化
-リティ## 3. 四半期セキュト効果の分析

##直し
- コスキュリティ設定の見ャン
- セ脆弱性スキ括的な価
- 包 月次セキュリティ評 2.の対応

####
- 新しい脅威へ析
- 防御効果の評価撃パターンの分- 攻キュリティレビュー
#### 1. 週次セ改善のプロセス

続的

### 継one
```  # 5分間隔
d   sleep 300    
 
ax-items 10  --m\
    ) e=$(date +%s+%s),EndTimnutes ago'  -d '5 miTime=$(datew Starte-windo     --tim
 REGIONAL \    --scope " \
  triciRuleSetMe "SQLric-name--rule-met\
      rn> acl-arn <web-eb-acl-a  --w   quests \
 d-remple get-sa   aws wafv2
 の確認    # WAF効果 
Sum
   ics tist --sta   \
   eriod 300
      --p) \M:%ST%H:%Y-%m-%d +% $(date -u-end-time
      -%M:%S) \%dT%H:%Y-%m-u +es ago' -ut -d '5 minme $(datestart-ti--    pts" \
  ckAttem"Attac-name tri
      --me" \Security"GameDay/pace  --namess \
     ticic-statistch get-metr cloudwa    awsメトリクスの確認
ティュリ  # セキ   do
rue;
while tィチェック 定期的なセキュリテ.sh

#_monitoringuousntin cosh
#/bin/ba
#!設定
```bash続的監視の

#### 2. 継=="
```plete =ation ComValidho "=== php
ecrm -f test.

iponse)"
fTP $resustment (HTneed adjMay iting: te limho "? Ralse
    ecS"
eASg: PRate limitin  echo "✓ hen
  "429" ]; tonse" = [ "$resp)
if l>/"//<target-urtp:"htde}" {http_co"%null -w  -s -o /dev/e=$(curlespons
wait

rdoneev/null &
 > /d>/"rltarget-u/<s "http:/ -rlcu}; do
    in {1..10
for i .." limiting.g rateho "Testinート制限の検証
ec
fi

# レe)"onsP $respFAIL (HTTtection: pload pro"✗ File u 
    echoASS"
elsetection: Pe upload pro"✓ Fil
    echo nthe]; 03"  = "4"$response" || [  = "400" ]$response"f [ "
iest.php")
@t"file=-F   \
pload" et-url>/u//<targp: "htt -X POSTcode}" "%{http_/null -w-o /dev=$(curl -s p
response test.ph; ?>' >cho "test"o '<?php e.."
echon. protectie uploadg filcho "Testinロード保護の検証
eアップ
# ファイルi
ponse)"
f$resP TT: FAIL (Htion✗ XSS protec   echo "se
 "
elPASStection:  XSS pro "✓n
    echo]; the403" nse" = "f [ "$respo

iipt>")est')</scr('t>alertch?q=<scriptseartarget-url>/p://<}" "htttp_codel -w "%{ht-o /dev/nule=$(curl -s esponsion..."
rrotectSS p"Testing Xho ecの検証
# XSS保護

"
firesponse)IL (HTTP $on: FAon protectitiQL Injec"✗ Scho    e"
else
  PASS protection:Injection"✓ SQL echo 
    n" ]; the403" = "onse"$respif [ )

test"password=1-- &' OR '1'='rname=admin  -d "use" \
rl>/login-ugetarhttp://<tST "" -X PO}dettp_coll -w "%{hdev/nu-o /rl -s e=$(cuespons..."
rtionecction proting SQL Injeho "Testン保護の検証
ecジェクショQLイン
# S"
ation ===gation Valid Mitiecurity=== S

echo "ript.shlidation_sc
# va/bin/bashh
#!``bas減策の効果測定
`#### 1. 各軽 検証手順


###
 実装の検証と継続的改善##`


``    )
sponse' Reecurity AutoameDay SSubject='G
        sage,essage=mes M,
       n=topic_arnicAr     Toplish(
   s.pub    sn
   y-alerts'
 rity-secu:gamedan:accountws:sns:regio'arn:apic_arn = s')
    to3.client('snto    sns = bo  """
知の送信
   通""
   ge):
    "essatification(mend_no)

def smit}"o {new_lit tlimig WAF rate (f"Updatin.infoger調整
    log環境に応じて# 実装は   """
  限の更新
    WAF レート制"
   
    ""new_limit):ate_limit(te_waf_rpda")

def u{str(e)}ror rate:  high erd to handle(f"Faileer.error logge:
        as ceptionept Ex  
    exc    th.")
  ation healiccheck appllease etected. Prate derror ("High ficationnoti       send_ 通知の送信
         #    
    ()
tion_healthica_applck che        #ルスチェックの実行

        # ヘ try:    
   rate")
r g high erro"Handlinlogger.info(    

    """エラー率への対応"
    高い   "":
 age)_rate(messe_high_error

def handl)}")(ettack: {strandle DDoS aled to h"Fair.error(f    loggeas e:
    on Excepti
    except        ed.")
 ting activatrate limicy rgencted. Emeattack deteS ial DDootentfication("Pnoti send_  送信
     通知の   #      
        tances()
_up_ins # scale
       調整（必要に応じて）o Scaling の    # Aut
    
        t(100)f_rate_limiwa     update_適用
   限の# 緊急レート制      ry:
    
    t
   attack")tial DDoSg potenandlininfo("Hlogger.
    """   の対応
 DoS攻撃へ
    D """):
   essage_attack(mddosdle_ef han}")

dte: {str(e)ck ra high attad to handleaile(f"Frrorlogger.e        on as e:
tiExcep
    except     d.")
    tighteneave been  WAF rules hdetected.rate h attack igation("Hnd_notificse
         # 通知の送信           
  500に削減
  から000)  # 通常の20_limit(50te_waf_rate  upda
      ート制限の適用# より厳しいレy:
        
    tr ルールの一時的な強化# WAF
    
    ck rate")attah andling hig"Hnfo(  logger.i"
    ""
  い攻撃率への対応"
    高:
    ""essage)tack_rate(mndle_high_at
def ha     }

    {str(e)}')mps(f'Error:: json.du'body'          500,
  tatusCode':      's{
          return     )
  {str(e)}"to response:r in auf"Erro.error(   logger e:
     ception asxcept Ex    
    e
           }eted')
 nse compl respo'Autoon.dumps(  'body': js         
 ode': 200,atusC         'st   n {
      retur 
  e)
       (messagh_error_ratele_hig     hand          arm_name:
 n al' iatehigh-error-rf '        elissage)
    k(meacs_att  handle_ddo         name:
     arm_alection' in os-detlif 'dd        e   message)
 _rate(_high_attack    handle        name:
    in alarm_ack-rate' att 'high-    if        'ALARM':
  ==f new_state 
        i)
       "ate}: {new_sttatem_name}, Salarm: {alarsing f"Procesr.info(ge    log      
    alue']
  eVtatewS= message['N_state        newme']
 larmNage['Aessaname = mlarm_
        a'Message'])'Sns'][[0]['Records']ds(event[.loaage = jsonmess        メッセージの解析
    # SNS   try:
    "
   ""
   く自動対応h アラームに基づ  CloudWatc""
      "text):
 conr(event,a_handlelambd

def nt('ec2')= boto3.clie)
ec2 2'afvclient('wto3.= bo)

wafv2 ng.INFOvel(loggier.setLe
logger()ng.getLogg = loggig

loggerrt logginmpoboto3
ion
import rt jspy
impose_lambda.esponto_ronitoring/auules/mform/modhon
# terraの実装
```pytステム: 自動対応シップ2
#### ステ```
}
mail
fication_ear.notipoint  = vndil"
  e = "emaocol  protts.arn
 erurity_alopic.sec= aws_sns_t_arn  {
  topicerts"" "email_alnsubscriptio_topic_ce "aws_sns
resour

}erts"ity-alsecurday-game " {
  name =ity_alerts""securic" ns_top "aws_s
resourceNS トピックの設定
}

# Sarn]ts.ty_alercurins_topic.se_stions = [awsac  
  alarm_uffix
  }
n.arn_sws_lb.mai = aalancer LoadB   nsions = {
dime  acks"
  
attS l DDo potentiaonitors formetric m"This   = n iom_descript00"
  alar   = "10        holdm"
  thres    = "Su        statistic"60"
   =         eriod    
  pionELB"AWS/Applicat= "    space       t"
  nameestCoun"Requ    = ic_name      metr
   = "2"riodson_pe
  evaluatid"ThanThresholreater"Gperator = arison_o"
  compectionddos-det "gameday-        =me   alarm_na
  {_detection"arm" "ddostric_alloudwatch_meaws_csource "}

ren]
y_alerts.ar.securitpic [aws_sns_to =nsrm_actio}
  
  alaix
  n.arn_suffws_lb.mair = aalance
    LoadBs = {  dimension  
e"
rror ratplication eonitors ap metric mn   = "This_descriptio  alarm
 = "20"          
  thresholdum"    = "S         statistic
"     = "300      
  period   onELB"/Applicati"AWS         =   namespace"
  5XX_Countde_Target_ = "HTTPConame          metric_"
s  = "3ation_periodalu
  evld"shohanThre"GreaterTperator = comparison_o"
  -rateigh-errory-heda    = "game      _nam
  alarm_rate" {gh_error"hi arm"_altch_metriccloudwa"aws_resource rn]
}

ity_alerts.atopic.securs_sns_awns    = [tio
  ok_aclerts.arn]y_apic.securitns_to [aws_sons =alarm_acti 
  on"
  }
 jecti "SQL_Ine =tackTyp {
    Atons =
  dimensi
  tempt rate"ck ators attaic monit"This metrtion   = rm_descripala0"
         = "5    old  thresh"Sum"
   =           statistic00"
"3      =    iod     "
  percurityy/Se"GameDa=       pace     es
  namkAttempts" = "Attac       name ric_
  met"2"periods  = aluation_
  evhreshold"rThanT "Greater =n_operato comparisock-rate"
 ta-high-at"gameday     =     name 
  alarm_e" {_attack_rat"high" etric_alarmoudwatch_m "aws_clsources.tf
rearmty_alecurionitoring/sm/modules/m terrafor
#``hcl
`ムの設定Watch アラー1: Cloud ステップ実装

####ムの 自動アラートシステ

### 5.2);
```xt();
}   
    ne
     } }
ak;
        bre       });
            ent')
    -Agq.get('Usert: reerAgen       us       req.ip,
    ip:          name,
      user  username:           h', {
   Hig', 'mpt_Attenjection'SQL_IcurityEvent(cordSererics. await met    );
       ip, falseon', req.ctiSQL_Injempt('teckAtecordAtta.ricst metrawai           ord)) {
 sswpat(ttern.tesrname) || paest(usetern.tpat        if ({
ns) ectionPatterqlInjof sst pattern (con  for 
   ];
    \s)+/i
   nd)(\s|\|aor+(\s|\\s) /(     
  i,ute)/r|exec|exece|altecreatupdate|drop|ert|delete|nson|select|i/(uni        ))/i,
*|\\*)|(\)|(\\*)|(\\|\\;)|(;|\'  /('|(\       = [
tionPatternsecnjnst sqlI
    coン攻撃の検知ジェクショQLイン 
    // Sq.body;
   ord } = reasswrname, p const { use{
   next) =>  (req, res, ', asyncloginuse('/p.の強化
ap撃検知
// 攻();
});
  next  
       });
        }
  });
          e
 Codatusde: res.st  statusCo        
      .path,req  path:       {
        r', 'High', Server_ErrorityEvent('rdSecu.recotricsait me   aw
         500) { >= atusCoderes.st       if (      
      }
  
        });      
  ip: req.ip           ,
    athq.p path: re              ', {
 t', 'LowLimi'Rate_vent(curityEcs.recordSeait metri     aw     = 429) {
  sCode ==f (res.statu  i 
                }
  );
      }        Agent')
 User-get('Agent: req.er    us         p,
    ip: req.i           ,
    eq.path  path: r            , {
  'Medium'lock', vent('WAF_BurityEecrdScocs.remetriawait    
          === 403) {s.statusCodereif (        ティイベントの検知
 // セキュリ            
 ds');
  econlisime, 'MilesponseTnseTime', rpo('ResmanceMetricrdPerformetrics.reco  await 記録
      トリクスマンスメ // パフォー
       
        me;tartTi) - sDate.now(onseTime = onst resp
        c () => {, asyncon('finish' res.の処理
   ンス完了時    // レスポ();
    
 = Date.nowstartTimenst co{
    next) => ((req, res, pp.useウェア
aミドルの監視セキュリティイベント

// cs();ityMetricurnew Setrics =  meconstics');
ils/metr('./uts = requirericcurityMetst Se監視の統合)
conapp/app.js (erable-uln// vjavascript
ョンへの統合
```プリケーシ ステップ2: ア##```

##yMetrics;
ritports = Secuule.ex}
}

mod   }
    
     ror);', ere metric:mancperfor to record ('Failedle.error    conso
        error) {catch (    } 
    se();omiparams).prcData(riatch.putMetudw await clo          {
 ry  t   
       ;
      }      
   ]
             }           
  ()te Datamp: newTimes              it,
      it: un    Un        
        ue: value,         Val       Name,
    metrictricName:       Me                {
               [
etricData:   M       ,
  espace: this.namespace    Nam
         = {st params     con   
t) {uniue, ricName, valtric(metMeancePerformc record asyn
   ンスメトリクスの記録    // パフォーマ   }
    
        }
 r);
', erropt:attemord attack  recr('Failed tosole.erroon      c    error) {
     } catch (
     mise();rams).proata(paicDutMetr.pdwatchawait clou            {
      try   
    };
              ]
  }
                     
    new Date() Timestamp:                  ount',
 nit: 'C         U           alue: 1,
      V      
                ],      
        }                    
  e'falsrue' : '? 'tue: blocked  Val                           d',
locke Name: 'B                           {
                          },
               pe
       Ty attackValue:                      pe',
      ackTyame: 'Att  N                       
    {                     [
   mensions:       Di            tempts',
 kAte: 'AttacametricN    M        
               {    : [
     ricDataMet            amespace,
is.nthNamespace:           = {
   amsconst par     cked) {
   IP, bloType, sourcempt(attackdAttackAtteecor rsync
    a録   // 攻撃試行の記
    
 
    }
        }r);erroty event:', ord securiailed to recror('F console.er           or) {
rrch (e    } caty}`);
     - ${severite}yp: ${eventTt recordedventy eog(`Securiconsole.l            ise();
params).promata(h.putMetricDatct cloudw      awai    ry {
        t  
        
      };    ]
  
             }        
    new Date()amp:stTime                     'Count',
       Unit:          : 1,
       Value             ],
                     }
                     y
     verit seValue:                       
     rity',ame: 'Seve  N                         {
                          },
                       ntType
  Value: eve                   e',
        'EventTyp     Name:                    {
                           ons: [
mensi        Di  
          vents',rityEme: 'SecucNa    Metri                {
              [
  ata: MetricD         
   ace,mespnaspace: this.     Name      = {
  amsst par     con {
   etails)severity, dventType, vent(erdSecurityEync reco  asイベントの記録
  ティ// セキュリ
      
  
    }ity';y/SecurGameDaace = 'is.namesp    th
    tructor() {nss {
    courityMetric Secclasstch();

.CloudWa = new AWSloudwatch);
const cs-sdk' require('awonst AWS =.js
c/metricsilsp/uterable-ap vulnpt
//cri装
```javasの実ムメトリクスップ1: カスタ

#### ステムの実装視システ1 高度な監

### 5.(P2) 中 ## 優先度:強化

#ムのラートシステ5. 監視とア
```

## 
}););)
    }ng(tri).toISOSw Date(p: neestam tim       ns,
tioiveConnecs: actConnection    active   , 
 thy'atus: 'heal    st    
es.json({  {
    r=>, res) lth', (req/hea
app.get('（制限対象外）エンドポイント/ ヘルスチェック
});

/);next(   
     });
 --;
   nections activeCon  
     () => {finish', res.on('     
 
    }
      });' 
    in later.agary please td, derloa oveilyars temporr: 'Server iro       ern({ 
     tus(503).json res.statur
        rens--;tioiveConnec act      CTIONS) {
 MAX_CONNE > onsnnectif (activeCo   i;
    
 ns++tioConnec
    activeext) => {, res, nse((req0;

app.u100NNECTIONS = const MAX_CO = 0;
onstiveConnectiの監視
let ac

// 接続数);isttelr.ipWhiionLimitee(connect処理
app.us/ 信頼できるIPの;

/er)loginLimitimiter.ctionL', connese('/login
app.uントに厳しい制限ンエンドポイ
// ログイLimiter);
.speedctionLimiterp.use(conne);
apterLimir.basiconLimiteuse(connecti全体に適用
app.レート制限を/ 基本的な

/;n_limiter')tioils/connecequire('./ut= rLimiter ectiont connconsート制限の適用)
/app.js (レe-apperabl// vuln
vascript``ja
`の適用2: アプリケーションへ#### ステップ
```

ist
};itel
    ipWhmiter,dLi   speenLimiter,
     logimiter,
sicLi  bats = {
  expor

module.);
};next(制限を適用
      // 通常の}
    
  ;
    urn next()      retP)) {
  udes(clientInclstedIPs.i if (tru 
     ;
 Addressn.remoteionecteq.con| rip | = req.IPient   const clxt) => {
 , nereq, reselist = (hit

const ipW;
]レスを追加理者IPアド  // 管1',
   '::.1',
   127.0.0= [
    'IPs t trustedスト
cons ホワイトリ});

// IP
遅延秒の000, // 最大20yMs: 20Dela    max00ms の遅延
/ 5s: 500, /    delayMエスト後に遅延開始
0, // 50リク 5elayAfter:  d/ 15分
  * 1000, /0 Ms: 15 * 6 window({
   wDown sloLimiter =eednst spポンス遅延の実装
co);

// レスue,
}equests: trlRpSuccessfu,
    ski }'
   later.try again  IP, please s from thisattemptin  many logerror: 'Too {
        age:
    mess // 最大5回の試行max: 5, 15分
    000, // 15 * 60 * 1  windowMs:({
  teLimitrainLimiter =  logconst
行の制限グイン試;

// ロlse,
})Headers: fa  legacy  ers: true,
ndardHead },
    staer.'
   in late try agaass IP, ples from thirequestmany Too or: '
        erre: {   messag0リクエスト
  // 最大10x: 100,    ma 15分
0, // 10060 *Ms: 15 * 
    windowLimit({r = rateimitecLasist bonなレート制限
c

// 基本的n');ows-slow-d'expres require(n =wDow
const slo');ate-limit'express-re(= requirimit onst rateL.js
cion_limiters/connectle-app/utilerabvulncript
// ``javas続プール制限の実装
`1: 接### ステップ

#適化ションレベルの最アプリケー3 `

### 4.  }
}
``"
ngniearnment = "Lro    EnvioudFront"
Cly-"GameDa        =   Name {
    
  tags =n
ing.armit_rate_lincedcl.advaweb_a= aws_wafv2_b_acl_id け
  we連付AF との関  
  # W true
  }
cate =certifit_default_dfron
    cloute {ificaewer_cert
  
  vi    }
  } "none"
tion_type =icstr {
      re_restriction {
    geoonsrestricti
  
  "  # コスト最適化_100assriceCl"P = rice_class  }
  
  p     = 0
ttlax_ m  t_ttl = 0
   defaul     = 0
    min_ttl}
    
    }
    "
    ard = "all forw       kies {
    coo
    "*"]
      = [    headers  e
    ring = truuery_st     q
 alues {_v forwarded
    
   s"o-httpect-t"redirlicy = tocol_power_pro  vie
     = true          ress  
    comp"ain.name}b.m"ALB-${aws_l _id       =_origin
    target, "HEAD"]"GET"       = [s  thodhed_mecacUT"]
    "PPOST", ", "HNS", "PATC"OPTIO"HEAD", , "GET", DELETE"= ["       ed_methods llow
    a= "/api/*"    ern       h_patt    pator {
he_behavied_cac
  orderュ無効化ッシトのキャPI エンドポイン
  
  # A6000
  }53  = 31   max_ttl 6400
   ult_ttl = 800
    defa    = 864   min_ttl 
    
 
    }
      }e"onrward = "n   foies {
      cook  
     false
    = tring ry_s
      queed_values {rward  
    fo
  https"-to-"redirectolicy = tocol_per_pro viewe
      = tru          compress      name}"
s_lb.main.LB-${aw"A = _id      ginoriarget_
    t, "HEAD"]  = ["GET"       ched_methods   caEAD"]
 "GET", "H    = [s    thodme allowed_
   *""/static/   =         patternh_  pat {
  behaviorache_  ordered_cキャッシュ最適化
  # 静的コンテンツの
  
  }00
l     = 864    max_tt_ttl = 300
default
       = 0 min_ttl    
    
  }     }
   "
 all = "ard        forwcookies {
 
      
     "]"Refererr-Agent", ", "Use= ["Hostaders      ue
      hetring = tr    query_s
  values {rded_
    forwa
    to-https"ct-"redireicy = l_polewer_protoco
    vieru      = t       ess  
    comprain.name}"_lb.m"ALB-${aws  = id     t_origin_targeAD"]
    "HE", ET= ["G        ds ed_metho  cach  , "PUT"]
"POST"",  "PATCHOPTIONS", "", "HEAD","GETTE",   = ["DELEds      hoetlowed_m{
    alehavior he_b default_cacャッシュ動作
   # デフォルトキtrue
  
nabled = 
  
  e    }
  }"]
= ["TLSv1.2  cols l_protoin_ssig   or  -only"
  "httpl_policy =gin_protoco ori
     43       = 4     rt s_po  http     80
           =http_port   {
      fig n_conom_origi 
    cust}"
   in.namews_lb.maB-${a  = "AL  origin_id 
  ame_n.dns.main_lbme = aws  domain_na
  igin {n" {
  orion" "maiributt_distdfronlouurce "aws_ctf
resooudfront.urity/cl/modules/secrmterrafo
```hcl
# リビューションの設定t ディスト1: CloudFron#### ステップッシュ

る分散とキャdFront によ### 4.2 Clou
}
```


  }}e
       = trus_enabledequestsampled_r      "
ckingMetricBlo    = "Geo           ic_name etrrue
      med = tblnas_ericetloudwatch_m     cconfig {
 bility_
    visi    }
      }
  クセスをブロック
  例: 特定の国からのア"KP"]  #  "RU",  ["CN",ry_codes =     count{
   tatement eo_match_s
      gtement {sta   
    
    }
 k {}     bloction {
   ac     

 riority = 3  pocking"
     = "GeoBlname  
    ）
  rule { 地理的制限（オプション}
  
  #e
    }
     = truabled_requests_enpled  sam   Metric"
 imitptLginAttem      = "Lo      name    ric_     mete
 d = trunable_ericsdwatch_met
      clounfig {isibility_co  
    v  
    }
    }       }
   }
       LY"
    = "EXACTaintonstrl_c positiona     
             }"
     WERCASE    = "LO   type 
           riority = 1       p
       on {formatins text_tra                  }
    }
  uri_path {           {
   eld_to_match    fi        ogin"
ng = "/l search_stri       {
    ent h_statem_matc        byteent {
  n_statem   scope_dow     
     "
   = "IPtype gate_key_ aggre           = 10
         it    liment {
     ed_statemas     rate_b{
 tement     sta }
    
ck {}
   blo
      action { 
       2
ty = ori
    priLimit"AttemptginLo  = "   name     rule {
 行の制限
# ログイン試}
  
  
  
    }   = trueabledts_enuesled_reqamp
      simitMetric"ateL"BasicR=               me  ic_natrmee
      abled = trus_en_metriccloudwatch {
      ty_configili   visib
    
    }  }
       }

                }       }
}
            S"
        = "CONTAINraintconstsitional_   po         }
                   CASE"
   = "LOWER type                  1
    priority =            
     {ormation ansf text_tr                      }
         h {}
   uri_pat               tch {
ield_to_ma    f          heck"
   = "healthcrch_string        sea{
        ent emh_statyte_matc         b  ment {
     state
          ment {ot_state          nent {
_down_statem   scope    
     P"
    pe = "Iegate_key_ty aggr     0
  200    =     imit        l {
      ntased_stateme  rate_b{
      statement 
    
    }ock {}
  {
      blction   a   = 1
    
itypriort"
    LimicRate = "Basiname    le {
    ート制限
  ru  # 基本的なレ
  
low {}
  } {
    alfault_action
  
  deNAL"= "REGIO"
  scope mitingrate-lied-dvancy-a"gameda
  name  = ting" {ed_rate_limiancadv_acl" "s_wafv2_webaw
resource ".tfngate_limitiity/res/securaform/modulerr# t装
```hcl
度なレート制限の実ステップ2: 高## 
##
```
lb-arn>n <aar --resource-
 " \rotectionLB-P"GameDay-A-name  \
  -protectionield create-合）
aws sh環境の場d の有効化（本格ld Advance
# Shiearn>
e-arn <alb-esourc --rrotectionescribe-peld d
aws shird の状態確認tandaShield S
# `bash化
``ard の確認と最適ld Stand: Shieステップ1### 

#とレート制限S Shield 性対策: AW 即効# 4.1(P1)

## 高 ## 優先度:

#軽減. DDoS攻撃の
## 4
});
```
});   );
 (filePathileres.sendF             
  ');
 s', 'nosniff-OptionContent-Type('X-.setHeader        res"`);
ginal_name}{row.ori="$lenamechment; fi', `attationent-Disposider('Cont  res.setHea;
      w.mime_type)e', ront-Typeader('Conte    res.setHァイル提供
       // セキュアなフ
           
     }
     k' });disfound on  'File not ror:n({ er404).jsostatus(urn res. ret     ) {
      lePath)(fisSyncfs.exist (!
        ifァイルの存在確認   // フ     
        ame);
_n.secure, rowcure's_see, 'upload__dirnam.join(thath = past fileP        con
        
  }
      );found' }File not { error: 's(404).json(es.statu  return r          ) {
(!rowf    i    
        }
    );
     error' }: 'Database json({ error(500).res.status   return          ;
r)r:', erbase erro('Dataonsole.error   c         rr) {
     if (e  => {
 ) (err, rowd], fileI [.get(query,
    db= ?`;
    es WHERE id uploaded_filM * FROELECT  query = `S
    constァイル情報を取得/ データベースからフ
    
    /   }
 le ID' });'Invalid fior: on({ errtus(400).jsurn res.sta
        retfileId)) { if (isNaN(;
    
   ams.fileId)t(req.parInleId = parseconst fi) => {
     (req, resleId',fiet('/file/:イント
app.gァイル提供エンドポセキュアなフ
//  }
});
);
   .message }ror: error.json({ eratus(400)s.st        re      
  }
    
               };
 eleteError), dete file:'ed to delrror('Failsole.e   con             or) {
(deleteErrcatch    }       ;
   e.path)req.filc(s.unlinkSyn        f         try {
  
         th) {req.file.pa.file &&    if (reqを削除
     // エラー時はファイル               
error);
 d error:', r('Uploae.erroconsol        (error) {
  } catch     
      });
       });
      
       .file.size   size: req            me,
 inalna.orige: req.filealNamigin       or
         ,is.lastIDId: th  file          ully',
     successfedloadile upessage: 'F  m            
  ue,cess: tr   suc         n({
        res.jso                  
}
              });
 n'ormatioile inf to save fFailed 'r:roson({ ertus(500).jrn res.sta       retu    ;
     ath).file.pc(reqnlinkSyn    fs.u      ルを削除
       // ファイ           err);
     error:', seDatabaror('ere.onsol        c{
        f (err)    i        {
  err)n(unctio    ], fize
    req.file.s            mimetype,
req.file.       
     .filename,ile  req.f  ,
        iginalnamefile.orreq.           , [
 b.run(query
        d      '))`;
  time('now?, ?, date?,  VALUES (?, load_time)pe, size, upe, mime_tyecure_namme, sinal_nailes (origO uploaded_fERT INT = `INSst query        con報を記録
にファイル情ータベース デ
        //
            }
    message });tentError.r: con.json({ erro00)es.status(4  return r
          th);.file.paSync(reqnknli     fs.u       削除
ルを/ 無効なファイ       /or) {
     tErrtencatch (con} );
        peetyle.mimh, req.fiatt(req.file.pileConteny.validateFfileSecurit    await   
      try {
        ァイル内容の検証   // フ
     
        
        } });ded'uploa file { error: 'No.json(atus(400)eturn res.st          r
  file) { if (!req.       {
  try => {
   res)sync (req, e'), a('fiload.singleload', uplst('/upイント
app.poアップロードエンドポセキュアなファイル// 

});
 }み
    1 // 1ファイルのfiles:
        , // 1MB * 1024: 1024eSize        fil limits: {
Filter,
   ilter: file   fileFe,
 e: storag   storagter({
 ad = mullost up

con  }
};
  se);)), falrs.join(', '.errovalidationew Error(   cb(n {
      } elserue);
   ull, t cb(n   
    lid) {isVa(validation.   
    if file);
 teFile(urity.validaection = fileSalidat vcons => {
    e, cb)q, filreeFilter = (const fil
フィルター
// ファイル }
});
ename);
   Filll, secure      cb(nue);
  inalnamfile.origureFilename(Secgeneratecurity. = fileSeilenameecureF const s       なファイル名生成
  // セキュア      e, cb) {
eq, fil(rfunction  filename: 
   },dDir);
    , uploab(null       c   
 
            } });
 : true{ recursiveoadDir, rSync(upl  fs.mkdi      r)) {
    nc(uploadDiSyexists if (!fs.
       合は作成が存在しない場// ディレクトリ    
      e');
      loads_securme, 'up(__dirna.join pathploadDir = u    const定
    bルート外に設ロードディレクトリをWe      // アップ) {
   file, cbn (req,tio: funcnationsti dee({
   skStoragulter.di mage = storconst定
er設キュアなmult;

// セurity')ils/file_secire('./ut requity =Securilest f;
con')e('multerer = requir
const multプロード部分の修正)js (ファイルアッpp/app.erable-at
// vuln``javascripロード処理の実装
` セキュアなアップ# ステップ2:##
```

#IONS
};OWED_EXTENS   ALLE_TYPES,
 ALLOWED_MIM   nt,
 leConte  validateFilename,
  ureFiteSecenera
    gFile,validates = {
    le.exportodu
}

m
    });});               });
        }
         的な検証のみ
    // 基本rue);  resolve(t                   else {
           イプ
     ルタの他のファイ  // そ   
            }            }
                      
 gnature'));ile sivalid PNG f'InError(new      reject(                {
       } else               
  ve(true);    resol          
           {g)dPnisVali  if (                  
              );
      byteindex] === nature[fileSigx) => dete, invery((byre.etunapngSig= lidPng const isVa             
       x0A];0x1A, 0D, 0x0A, 7, 0x04E, 0x4, 0x50= [0x89, 0xature  pngSign     const         ) {
       'image/png'ype ===ectedMimeTelse if (exp              ネチャチェック
  ァイルシグ/ PNG フ   /        }
                              }
    
       ature')); signEG fileJPlid Invar('ew Erroject(n    re               e {
            } els   
          );uetr   resolve(                 {
    D8)  === 0xure[1]ileSignatxFF && fre[0] === 0leSignatu   if (fi              eg') {
   jp'image/Type === ectedMime (exp         ifェック
       イルシグネチャチJPEG ファ         //    
                    ead);
 bytesR.slice(0,e = buffergnaturconst fileSi             
              
     ect(err); return rejr)if (er               
 });=> {, () close(fdfs.     
           Read) => {bytes, 2, 0, (errr, 0, 51d, buffe  fs.read(f
                     (err);
 turn reject (err) re      if       => {
(err, fd),  'r'ilePath,n(fope      fs.         
2);
 er.alloc(51uffer = Buff b       constMEタイプを検証
 トでMIルの先頭バイ   // ファイ {
     ct) =>lve, rejeso((rePromiseew return n {
    Type)ectedMimelePath, exptent(fiFileConn validate
functioの検証ル内容 ファイ

//xt}`;
}omString}${e{randestamp}_$turn `${tim    
    re'hex');
g(8).toStrines(omBytpto.randg = cryrinandomSt rnst coow();
   Date.ntimestamp = 
    const werCase();.toLome)nalNaxtname(origi.ethpaxt =  const e
    {inalName)name(origleSecureFiion generatectァイル名生成
funキュアなフ// セ
}

rs
    };rors: erro     er,
   gth === 0rrors.lenid: eVal   is {
       return
    
  
    } filename');racters inlid chash('Invarors.pu   er
     \\')) {cludes('alname.in file.origin') ||ludes('/incalname. file.origins('..') ||ludeinalname.incile.orig (fック
    ifーサル攻撃チェストラバ  // ファイル名のパ    
  
    }
wed`);t allotype} is noimee ${file.mtypush(`MIME .prs   erro{
     mimetype)) ludes(file.TYPES.incOWED_MIME_  if (!ALLイプチェック
   // MIMEタ   
   
    }
 ;`)cteddetet} n ${exextensiogerous file rs.push(`Dan       erro
 (ext)) {S.includesXTENSIONROUS_E  if (DANGE
    }
    wed`);
   not allon ${ext} isile extensioors.push(`F    err  
  )) {ext.includes(ENSIONSXTLOWED_E
    if (!ALrCase();wealname).toLogine(file.orixtnam.e= path ext st    con拡張子チェック
/    
    /  }
 me');
  valid filena.push('In  errors     ) {
 ngth > 255inalname.le| file.orige |ginalnam.ori (!file if名チェック
   ファイル // 
    
   ;
    }B limit')1Mize exceeds h('File srors.pus        er 1024) {
e > 1024 *.sizf (file)
    i(1MB制限ァイルサイズチェック   
    // フ
  ors = [];   const errfile) {
 idateFile(ction valfun数
検証関ァイル
// フr'
];
war', '.ear', '.jab', '., '.pl', '.r', '.py'   '.shmd', 
  '.cat', '.exe', '.bs', '.jx', '.jsp',, '.asp.asp'', '
    '.phpNS = [S_EXTENSIODANGEROUconst なファイル拡張子


// 危険'];, '.pdfxt'.gif', '.t', '.png', '', '.jpegS = ['.jpgXTENSION_EWEDLO
const ALァイル拡張子可されたフ// 許];

n/pdf'
atioapplicin',
    't/pla   'tex',
   'image/gifpng',
  ge/   'ima',
 eg/jp   'imageES = [
 TYPWED_MIME_const ALLOルタイプ
許可されたファイ/ 'fs');

/uire(s = req);
const f'crypto'= require(nst crypto th');
core('parequionst path = s
c.jurityle_secpp/utils/finerable-a
// vulscript``javaイブラリの実装
`プ1: ファイル検証ラステッード

#### ップロキュアなファイルア修正: セプリケーション
### 3.2 ア```
  }
}
  }

  trueled   = enabquests__rempledsa
      ic"imitMetr"FileSizeL      =    e       ametric_n      mled = true
_enabmetricsatch_      cloudwnfig {
y_coitvisibil  
    
    }
  
      }     }NONE"
    = "    type  
        rity = 1    prioon {
      ransformati     text_t
    # 1MB8576  = 104                size   T"
     = "Gn_operator   compariso   }
     
      body {}{
         _to_match      field   ent {
raint_statemstize_con
      statement {
    
    s
    }    block {}ction {
  
    a     = 2
    priorityize"
tFileS"Limie     = 
    namle {ruズの制限
  サイ# 大きなファイル  
   }

     } = true
bled  equests_enampled_r     sa"
 tricxtensionMeFileEerousng= "Da            e    metric_nam
      = truenabled metrics_ech_dwatclou
      config {y_visibilit    
    

    }S"
      }AINCONT = "_constraintalposition }
        "
       ASE "LOWERC  =ype     t      
   = 1priority          tion {
forma  text_trans }
        
        }      
 TINUE""CONhandling = versize_      o  y {
       bod
        {_matcheld_tofi"
        phpg = ".rin  search_st{
      ment _match_state
      byteatement {  st
    
    }ock {}
  {
      bl    action 

    = 1ority    pri
 ons"nsileExtekDangerousFi    = "Bloc name 
   
  rule {子のブロック危険なファイル拡張
  
  #  } {}
 {
    allowion efault_act 
  dAL"
 EGION scope = "Rtion"
 pload-protecmeday-file-ume  = "gana
  {" ionload_protecte_up" "fil2_web_aclafv "aws_wceesourd.tf
r_file_uploarity/wafdules/secuerraform/mo
```hcl
# t限ルール ファイルアップロード制### ステップ1:護

#ード保アップロFファイル WA 即効性対策:.1
### 3 高 (P1)
先度:# 優減

##ード脆弱性の軽アップロ 3. ファイル``

##>
`/html</body>
<pt>
 </scri   }
      });
         ed');
 Search failert('  al            );
   error:',rorch eror('Sear.errnsole          co     => {
  tch(errorca          . })
        
     }               );
 (dataltsySearchResula disp                {
      } else      
        `);.error}r: ${data alert(`Erro                
   ) { (data.error       if         {
 en(data =>     .th)
       e.json()pons> ressponse =en(re     .th     ry}`)
  odedQuech?q=${enc(`/searfetch              
 query);
 nent(eURICompouery = encoddedQ  const encoィング
      // URLエンコーデ           
       }
   urn;
            ret
    long');oo query is t('Searchlert           a {
  100)length >if (query.        入力値検証
/      /) {
   ch(queryormSearion perf    funct実行
 セキュアな検索    //}
    
     }
 
      s);ild(noResultendChr.appneontai          cound.';
  results f = 'No .textContentesults    noR  
      t('p');ateElemencument.crelts = dot noResu        cons    lse {
       } e
 ild(list);.appendChntainer     co     
              );
 }          
 ld(item);Chilist.append            プ
    ntでエスケーte/ textConil})`; /${result.emae} (rnamt.uset = `${resulm.textConten        ite
        ('li');eateElementument.cr = docnst itemco            {
    ult => h(resacesults.forE.r     data                
');
   ulent('teElemcreament.st = docuonst li  c
          ngth > 0) {esults.lets && data.r (data.resul    if    
       );
 titled(pendChilcontainer.ap       tでエスケープ
  textConteny}`; //data.quer ${ts for:earch Resul= `Sent ntextCo   title.th2');
     ('teElementment.crea docut title =   cons
         
     クリアTML = ''; //er.innerHcontain   XSS防止
     DOM操作での  //  
      );
       sults''search-reentById(nt.getElemdocume =  container  const
      ) {dataarchResults(playSe disonfuncti   結果表示
 キュアな検索   // セ>
   <script  
  
  ></div>ts"arch-resul="se   <div id
<body>
 
</head>self';">t-src ' scripsrc 'self';lt-faudetent="licy" conecurity-Pontent-Suiv="Cota http-eq>
    <meクアップ） --メタタグ（バッ- CSP <!-itle>
    /table App<Day Vulnertle>Game <ti">
   scale=1.0initial-e-width, th=devic"widt=ten cont""viewpore=nam
    <meta -8">harset="UTF<meta cd>
    
<hea"ja">lang=html >
<TYPE html->
<!DOCml (修正部分) -ex.htindblic/pup/-aplnerable<!-- vu策
```html
側の対ップ3: フロントエンド#### ステ
```

;
});});
    })
        s.lastIDthi        id: ully',
    ssfcce saved sue: 'Comment    messag, 
        uess: tr succe           ({ 
res.json 
                }
    t' });
   commenave 'Failed to s({ error: .jsons(500)es.statuturn r          re);
  r:', errt save erro('Commenerror   console.     
    f (err) {{
        iion(err) functent], leanCommcleanName, c, [un(query    db.rw'))`;
'nome(dateti, ?, ALUES (?ated_at) Vre, ce, commentnts (nammmecoRT INTO INSE = `uery
    const qスケープ済み）ースに保存（エ // データベ       
/g, '');
[^>]*>.replace(/< = namecleanName   const 
 ]*>/g, '');(/<[^>eplace.rnt = commentanComme   const cle全除去
  // HTMLタグの完    
   

    }ngth' });d name le 'Invalir:erron({ 00).jsos(4statuturn res.   re
     > 50) {ength  || name.l (!name if
    
    });
    }t length'mennvalid comror: 'I0).json({ eres.status(40n r      retur  {
0) gth > 50nt.lenomment || commeif (!c
    // 入力値検証 
    dy;
   bo req.e } =nt, nammenst { comco => {
     res)t', (req,commenapp.post('/機能の修正

// コメント});
});
        
d' });Search faile: 'errorn({ ).jso00s.status(5         re);
   ror:', errorch err('Searole.errocons        r => {
    ch(erro     .cat })
   );
                  }ults
 lts: safeRes  resu         
     ery),(quHtmlcapety.es: securi    query            res.json({
    
                   
    }));  )
       (user.emailpeHtmlscaecurity.e    email: s          e),
  namusertml(user..escapeHitysecurname:     user            ,
: user.id      id     ({
     er => ap(us.msultss = reltesusafeRt     cons
        MLエスケープ// 出力時のHT         {
    esults =>  .then(r   
   ers(query)s.searchUsuerieeQ   securリ使用）
 キュアなクエデータベース検索（セ   //   
 
    }
        }y' });
  uerearch qlid serror: 'Invason({ 00).js(4tatu res.s return            {
query))st(n.teatter    if (pns) {
    terousPatngertern of dast patr (con fo
    
   ed/i
    ];  /<emb   ect/i,
          /<objame/i,
 /<ifr     
   w+\s*=/i,\        /oncript:/i,
/javas,
        /iptri   /<sc     rns = [
erousPatteconst dang文字の検出
      // 危険な }
    
  
   }); long' uery tooarch q'Sen({ error: us(400).json res.stat       retur> 100) {
 y.length  if (quer力値の検証
     
    // 入q || '';
  eq.query. rquery =const     es) => {
 rreq,arch', (('/se
app.get検索機能の修正

// });   next();

 lock');ode=b', '1; mtection-Proader('X-XSSHees.set  r;
  ')s', 'DENYme-Option'X-Frader(Heaset
    res.');iff, 'nosnns'pe-Optio-Content-TytHeader('Xres.se  ;
  ))eCSPHeader(eneraturity.gsecicy', rity-PolContent-Secu.setHeader(' res
   => {) res, next(req, 定
app.use(// CSPヘッダーの設);

s/security'til./uuire(' = requrityonst sec分)
capp.js (修正部app/nerable-ul
// vvascript```jaーションの修正
 ステップ2: アプリケ``

####;
`Header
}eCSP    generatUrl,

    escapecapeJs,  esHtml,
  
    escapes = {e.export
modul';";
}
s 'noneancestorframe-  "     " +
    ; 'self'-src nnect   "co        ; " +
rc 'self'    "font-s     +
   a:; "elf' dat-src 's"img           ine'; " +
 'unsafe-inlf'elyle-src 's     "st" +
      inline'; lf' 'unsafe-ipt-src 'se       "scr " +
    rc 'self';fault-s