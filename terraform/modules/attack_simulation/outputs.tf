# 攻撃シミュレーションモジュール出力

output "instance_id" {
  description = "攻撃シミュレーションインスタンスID"
  value       = var.enable_attack_simulation ? aws_instance.attack_simulation[0].id : null
}

output "instance_public_ip" {
  description = "攻撃シミュレーションインスタンスのパブリックIP"
  value       = var.enable_attack_simulation ? aws_instance.attack_simulation[0].public_ip : null
}

output "instance_private_ip" {
  description = "攻撃シミュレーションインスタンスのプライベートIP"
  value       = var.enable_attack_simulation ? aws_instance.attack_simulation[0].private_ip : null
}

output "security_group_id" {
  description = "攻撃シミュレーション用セキュリティグループID"
  value       = aws_security_group.attack_simulation.id
}

output "iam_role_arn" {
  description = "攻撃シミュレーション用IAMロールARN"
  value       = aws_iam_role.attack_simulation.arn
}

output "log_group_name" {
  description = "CloudWatchログループ名"
  value       = aws_cloudwatch_log_group.attack_simulation.name
}

output "results_bucket_name" {
  description = "攻撃結果保存用S3バケット名"
  value       = var.create_results_bucket ? aws_s3_bucket.attack_results[0].id : null
}

output "ssh_command" {
  description = "SSH接続コマンド（キーペアが設定されている場合）"
  value = var.enable_attack_simulation && var.key_pair_name != "" ? (
    "ssh -i ~/.ssh/${var.key_pair_name}.pem ec2-user@${aws_instance.attack_simulation[0].public_ip}"
  ) : null
}

output "attack_scripts_path" {
  description = "インスタンス内の攻撃スクリプトパス"
  value       = "/home/ec2-user/attack-scripts"
}

output "usage_instructions" {
  description = "使用方法の説明"
  value = var.enable_attack_simulation ? {
    ssh_access = var.key_pair_name != "" ? "SSH接続: ssh -i ~/.ssh/${var.key_pair_name}.pem ec2-user@${aws_instance.attack_simulation[0].public_ip}" : "SSH接続: キーペアが設定されていません"
    
    ddos_attack = "DDoS攻撃: ./attack-scripts/ddos_simulation.sh -u http://${var.target_alb_dns} -c 100 -d 60"
    
    sql_injection = "SQLインジェクション: python3 ./attack-scripts/sql_injection_test.py -u http://${var.target_alb_dns}"
    
    xss_test = "XSSテスト: python3 ./attack-scripts/xss_test.py -u http://${var.target_alb_dns}"
    
    file_upload = "ファイルアップロード: python3 ./attack-scripts/file_upload_test.py -u http://${var.target_alb_dns}"
    
    auth_bypass = "認証バイパス: python3 ./attack-scripts/auth_bypass_test.py -u http://${var.target_alb_dns}"
    
    logs = "ログ確認: sudo tail -f /var/log/attack-simulation.log"
  } : null
}