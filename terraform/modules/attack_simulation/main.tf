# 攻撃シミュレーション用EC2インスタンス

# 攻撃シミュレーション用セキュリティグループ
resource "aws_security_group" "attack_simulation" {
  name_prefix = "${var.project_name}-attack-simulation-"
  vpc_id      = var.vpc_id
  description = "Security group for attack simulation instance"

  # アウトバウンドルール - ターゲットアプリケーションへの攻撃を許可
  egress {
    description = "HTTP to target application"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTPS to target application"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # DNS解決用
  egress {
    description = "DNS"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # パッケージ更新用
  egress {
    description = "Package updates"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH管理用（必要に応じて）
  ingress {
    description = "SSH for management"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidr_blocks
  }

  tags = {
    Name        = "${var.project_name}-attack-simulation-sg"
    Environment = var.environment
    Purpose     = "AttackSimulation"
  }
}

# 攻撃シミュレーション用IAMロール
resource "aws_iam_role" "attack_simulation" {
  name_prefix = "${var.project_name}-attack-simulation-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-attack-simulation-role"
    Environment = var.environment
    Purpose     = "AttackSimulation"
  }
}

# CloudWatchログ用ポリシー
resource "aws_iam_role_policy" "attack_simulation_logs" {
  name_prefix = "${var.project_name}-attack-simulation-logs-"
  role        = aws_iam_role.attack_simulation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:*:*"
      }
    ]
  })
}

# インスタンスプロファイル
resource "aws_iam_instance_profile" "attack_simulation" {
  name_prefix = "${var.project_name}-attack-simulation-"
  role        = aws_iam_role.attack_simulation.name

  tags = {
    Name        = "${var.project_name}-attack-simulation-profile"
    Environment = var.environment
    Purpose     = "AttackSimulation"
  }
}

# 最新のAmazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# 攻撃シミュレーション用EC2インスタンス
resource "aws_instance" "attack_simulation" {
  count = var.enable_attack_simulation ? 1 : 0

  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  key_name              = var.key_pair_name
  vpc_security_group_ids = [aws_security_group.attack_simulation.id]
  subnet_id             = var.subnet_id
  iam_instance_profile  = aws_iam_instance_profile.attack_simulation.name

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    target_alb_dns     = var.target_alb_dns
    target_cloudfront_domain = var.target_cloudfront_domain != null ? var.target_cloudfront_domain : ""
    aws_region         = var.aws_region
    log_group_name     = aws_cloudwatch_log_group.attack_simulation.name
  }))

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true

    tags = {
      Name        = "${var.project_name}-attack-simulation-root"
      Environment = var.environment
    }
  }

  tags = {
    Name        = "${var.project_name}-attack-simulation"
    Environment = var.environment
    Purpose     = "AttackSimulation"
    AutoStop    = "true"  # 自動停止用タグ
  }

  lifecycle {
    create_before_destroy = true
  }
}

# CloudWatchログループ
resource "aws_cloudwatch_log_group" "attack_simulation" {
  name              = "/aws/ec2/${var.project_name}/attack-simulation"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${var.project_name}-attack-simulation-logs"
    Environment = var.environment
    Purpose     = "AttackSimulation"
  }
}

# 攻撃結果保存用S3バケット（オプション）
resource "aws_s3_bucket" "attack_results" {
  count = var.create_results_bucket ? 1 : 0

  bucket_prefix = "${var.project_name}-attack-results-"

  tags = {
    Name        = "${var.project_name}-attack-results"
    Environment = var.environment
    Purpose     = "AttackSimulation"
  }
}

resource "aws_s3_bucket_versioning" "attack_results" {
  count = var.create_results_bucket ? 1 : 0

  bucket = aws_s3_bucket.attack_results[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "attack_results" {
  count = var.create_results_bucket ? 1 : 0

  bucket = aws_s3_bucket.attack_results[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "attack_results" {
  count = var.create_results_bucket ? 1 : 0

  bucket = aws_s3_bucket.attack_results[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3アクセス用ポリシー（結果保存用）
resource "aws_iam_role_policy" "attack_simulation_s3" {
  count = var.create_results_bucket ? 1 : 0

  name_prefix = "${var.project_name}-attack-simulation-s3-"
  role        = aws_iam_role.attack_simulation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.attack_results[0].arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.attack_results[0].arn
      }
    ]
  })
}