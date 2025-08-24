# 攻撃シミュレーションモジュール用変数

variable "project_name" {
  description = "プロジェクト名"
  type        = string
  default     = "gameday-ddos"
}

variable "environment" {
  description = "環境名"
  type        = string
  default     = "learning"
}

variable "aws_region" {
  description = "AWSリージョン"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "subnet_id" {
  description = "攻撃シミュレーションインスタンス用サブネットID"
  type        = string
}

variable "instance_type" {
  description = "EC2インスタンスタイプ"
  type        = string
  default     = "t3.small"
}

variable "key_pair_name" {
  description = "EC2キーペア名（SSH接続用）"
  type        = string
  default     = ""
}

variable "allowed_ssh_cidr_blocks" {
  description = "SSH接続を許可するCIDRブロック"
  type        = list(string)
  default     = ["10.0.0.0/8"]  # VPC内からのみ
}

variable "enable_attack_simulation" {
  description = "攻撃シミュレーションインスタンスを有効にするか"
  type        = bool
  default     = true
}

variable "target_alb_dns" {
  description = "ターゲットALBのDNS名"
  type        = string
}

variable "target_cloudfront_domain" {
  description = "ターゲットCloudFrontドメイン（存在する場合）"
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatchログの保持日数"
  type        = number
  default     = 7
}

variable "create_results_bucket" {
  description = "攻撃結果保存用S3バケットを作成するか"
  type        = bool
  default     = false
}

# 攻撃ツール設定
variable "install_tools" {
  description = "インストールする攻撃ツール"
  type = object({
    basic_tools    = bool  # curl, wget, ab
    python_tools   = bool  # Python3, pip, requests
    security_tools = bool  # nmap, sqlmap, nikto
    custom_scripts = bool  # カスタム攻撃スクリプト
  })
  default = {
    basic_tools    = true
    python_tools   = true
    security_tools = true
    custom_scripts = true
  }
}

variable "attack_scripts_source" {
  description = "攻撃スクリプトのソースパス"
  type        = string
  default     = "../../../scripts"
}