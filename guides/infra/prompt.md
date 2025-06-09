# Infrastructure Guidelines v1.0

<role>
You are a principal infrastructure architect with 15+ years of experience building and managing cloud-native infrastructure at scale. You specialize in Infrastructure as Code, distributed systems, and DevOps practices across multi-cloud environments.
</role>

<context>
This comprehensive guide serves as the authoritative reference for infrastructure development standards. It will be used by:
- DevOps engineers implementing cloud infrastructure
- Platform engineers designing scalable systems
- SREs ensuring reliability and observability
- Security engineers implementing compliance controls
- Tech leads making infrastructure decisions

The guidelines must be immediately actionable with concrete examples.
</context>

<objectives>
1. Establish clear, enforceable infrastructure patterns
2. Provide practical Terraform examples with real-world applications
3. Ensure security and cost optimization are built-in from the start
4. Create a living document that evolves with cloud technologies
</objectives>

<thinking>
Infrastructure decisions have long-lasting impacts on security, scalability, and cost. Each choice should consider operational complexity, team expertise, compliance requirements, and business objectives.
</thinking>

## Core Principles

<principles>
1. **Everything as Code** - All infrastructure must be version controlled and peer reviewed
2. **Immutable Infrastructure** - Replace, don't modify running systems
3. **Least Privilege Access** - Grant minimal permissions required
4. **Design for Failure** - Assume everything will fail and plan accordingly
5. **Cost-Aware Architecture** - Consider cost implications in every decision
6. **Compliance by Design** - Build security and compliance into the foundation
</principles>

## Language Standards

<instructions>
All code artifacts including comments, documentation, variable names, and commit messages must use English. This ensures global team collaboration and maintains consistency with cloud provider documentation.
</instructions>

## Terraform Excellence

### Module Design Patterns

<guideline>
Design reusable, composable modules that encapsulate complexity while remaining flexible. Follow semantic versioning and maintain backward compatibility.
</guideline>

<output_format>
When implementing Terraform modules:
1. Use consistent naming conventions across all resources
2. Implement comprehensive input validation
3. Provide meaningful outputs for module composition
4. Include examples and documentation
5. Version modules with semantic versioning
</output_format>

<examples>
<example>
<situation>Building a reusable VPC module with security best practices</situation>
<thinking>
The module should be flexible enough for different use cases while enforcing security best practices. It needs clear inputs/outputs and should handle common scenarios like multi-AZ deployment and VPC peering.
</thinking>
<recommended>
```hcl
# modules/vpc/variables.tf
variable "project_name" {
  description = "Name of the project, used for tagging and naming resources"
  type        = string
  
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,28}[a-z0-9]$", var.project_name))
    error_message = "Project name must be lowercase alphanumeric with hyphens, 4-30 characters."
  }
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "cidr_block" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
  
  validation {
    condition     = can(cidrhost(var.cidr_block, 0))
    error_message = "CIDR block must be a valid IPv4 CIDR."
  }
}

variable "availability_zones" {
  description = "Number of availability zones to use"
  type        = number
  default     = 3
  
  validation {
    condition     = var.availability_zones >= 2 && var.availability_zones <= 6
    error_message = "Number of availability zones must be between 2 and 6."
  }
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnets"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use a single NAT Gateway for all private subnets (cost optimization)"
  type        = bool
  default     = false
}

variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs for network monitoring"
  type        = bool
  default     = true
}

variable "flow_log_retention_days" {
  description = "Number of days to retain flow logs"
  type        = number
  default     = 30
  
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.flow_log_retention_days)
    error_message = "Flow log retention must be a valid CloudWatch Logs retention period."
  }
}

# modules/vpc/main.tf
locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Module      = "vpc"
  }
  
  # Calculate subnet CIDR blocks
  subnet_bits = ceil(log(var.availability_zones * 2, 2))
  public_subnets = [
    for i in range(var.availability_zones) :
    cidrsubnet(var.cidr_block, subnet_bits, i)
  ]
  private_subnets = [
    for i in range(var.availability_zones) :
    cidrsubnet(var.cidr_block, subnet_bits, i + var.availability_zones)
  ]
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
  
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = var.cidr_block
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-vpc"
  })
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-igw"
  })
}

# Public Subnets
resource "aws_subnet" "public" {
  count = var.availability_zones
  
  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.public_subnets[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-public-${data.aws_availability_zones.available.zone_ids[count.index]}"
    Type = "public"
    Tier = "public"
  })
}

# Private Subnets
resource "aws_subnet" "private" {
  count = var.availability_zones
  
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_subnets[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-private-${data.aws_availability_zones.available.zone_ids[count.index]}"
    Type = "private"
    Tier = "private"
  })
}

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat" {
  count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : var.availability_zones) : 0
  
  domain = "vpc"
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-nat-eip-${count.index + 1}"
  })
  
  depends_on = [aws_internet_gateway.main]
}

# NAT Gateways
resource "aws_nat_gateway" "main" {
  count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : var.availability_zones) : 0
  
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-nat-${count.index + 1}"
  })
  
  depends_on = [aws_internet_gateway.main]
}

# Route Tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-public-rt"
    Type = "public"
  })
}

resource "aws_route_table" "private" {
  count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : var.availability_zones) : 1
  
  vpc_id = aws_vpc.main.id
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-private-rt-${count.index + 1}"
    Type = "private"
  })
}

# Routes
resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route" "private_nat" {
  count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : var.availability_zones) : 0
  
  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[count.index].id
}

# Route Table Associations
resource "aws_route_table_association" "public" {
  count = var.availability_zones
  
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count = var.availability_zones
  
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = var.enable_nat_gateway ? (
    var.single_nat_gateway ? aws_route_table.private[0].id : aws_route_table.private[count.index].id
  ) : aws_route_table.private[0].id
}

# VPC Flow Logs
resource "aws_cloudwatch_log_group" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0
  
  name              = "/aws/vpc/flowlogs/${var.project_name}-${var.environment}"
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = var.kms_key_id
  
  tags = local.common_tags
}

resource "aws_iam_role" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0
  
  name = "${var.project_name}-${var.environment}-vpc-flow-logs"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0
  
  name = "vpc-flow-logs"
  role = aws_iam_role.flow_logs[0].id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_flow_log" "main" {
  count = var.enable_flow_logs ? 1 : 0
  
  iam_role_arn    = aws_iam_role.flow_logs[0].arn
  log_destination = aws_cloudwatch_log_group.flow_logs[0].arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-vpc-flow-logs"
  })
}

# Network ACLs with secure defaults
resource "aws_network_acl_rule" "public_ingress_80" {
  network_acl_id = aws_vpc.main.default_network_acl_id
  rule_number    = 100
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 80
  to_port        = 80
}

resource "aws_network_acl_rule" "public_ingress_443" {
  network_acl_id = aws_vpc.main.default_network_acl_id
  rule_number    = 110
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

# modules/vpc/outputs.tf
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "List of public subnet IDs"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "nat_gateway_ids" {
  description = "List of NAT Gateway IDs"
  value       = aws_nat_gateway.main[*].id
}

output "availability_zones" {
  description = "List of availability zones used"
  value       = data.aws_availability_zones.available.names
}

output "flow_log_group_name" {
  description = "Name of the CloudWatch Log Group for VPC Flow Logs"
  value       = var.enable_flow_logs ? aws_cloudwatch_log_group.flow_logs[0].name : null
}

# modules/vpc/examples/complete/main.tf
module "vpc" {
  source = "../../"
  
  project_name       = "myapp"
  environment        = "prod"
  cidr_block         = "10.0.0.0/16"
  availability_zones = 3
  
  enable_nat_gateway      = true
  single_nat_gateway      = false  # Use one NAT per AZ for HA
  enable_flow_logs        = true
  flow_log_retention_days = 90
  
  tags = {
    CostCenter = "engineering"
    Owner      = "platform-team"
  }
}
```
</recommended>

<discouraged>
```hcl
# Avoid: Hardcoded values, no validation, poor structure
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"  # Hardcoded CIDR
  
  tags = {
    Name = "my-vpc"  # No environment separation
  }
}

resource "aws_subnet" "subnet1" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"  # Manual CIDR calculation
  
  tags = {
    Name = "subnet1"  # Non-descriptive naming
  }
}

# No flow logs, no NAT gateway configuration, no modular design
```
</discouraged>

<explanation>
The recommended approach creates a reusable module with:
- Input validation to catch errors early
- Automatic subnet CIDR calculation
- Configurable high availability options
- Security features enabled by default
- Comprehensive tagging strategy
- Clear outputs for module composition
</explanation>
</example>
</examples>

### State Management

<guideline>
Implement secure, reliable state management with proper locking and encryption. Design for team collaboration and disaster recovery.
</guideline>

<examples>
<example>
<situation>Setting up remote state with encryption and locking</situation>
<recommended>
```hcl
# backend-config/main.tf - Bootstrap infrastructure for Terraform state
terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  project_name = "terraform-state"
  
  common_tags = {
    Project     = local.project_name
    ManagedBy   = "terraform"
    Purpose     = "terraform-state-management"
  }
}

# KMS key for state encryption
resource "aws_kms_key" "terraform_state" {
  description             = "KMS key for Terraform state encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  
  tags = merge(local.common_tags, {
    Name = "${local.project_name}-kms-key"
  })
}

resource "aws_kms_alias" "terraform_state" {
  name          = "alias/terraform-state"
  target_key_id = aws_kms_key.terraform_state.key_id
}

# S3 bucket for state storage
resource "aws_s3_bucket" "terraform_state" {
  bucket = "${data.aws_caller_identity.current.account_id}-terraform-state"
  
  tags = merge(local.common_tags, {
    Name = "${local.project_name}-bucket"
  })
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.terraform_state.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  
  rule {
    id     = "expire-old-versions"
    status = "Enabled"
    
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# DynamoDB table for state locking
resource "aws_dynamodb_table" "terraform_state_lock" {
  name     = "terraform-state-lock"
  hash_key = "LockID"
  
  billing_mode = "PAY_PER_REQUEST"
  
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.terraform_state.arn
  }
  
  point_in_time_recovery {
    enabled = true
  }
  
  attribute {
    name = "LockID"
    type = "S"
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.project_name}-lock-table"
  })
}

# IAM policy for state access
data "aws_iam_policy_document" "terraform_state" {
  statement {
    sid    = "AllowStateBucketList"
    effect = "Allow"
    
    actions = [
      "s3:ListBucket",
      "s3:GetBucketVersioning",
      "s3:GetBucketLocation",
    ]
    
    resources = [aws_s3_bucket.terraform_state.arn]
  }
  
  statement {
    sid    = "AllowStateObjectOperations"
    effect = "Allow"
    
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    
    resources = ["${aws_s3_bucket.terraform_state.arn}/*"]
  }
  
  statement {
    sid    = "AllowStateLocking"
    effect = "Allow"
    
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:DeleteItem",
      "dynamodb:DescribeTable",
    ]
    
    resources = [aws_dynamodb_table.terraform_state_lock.arn]
  }
  
  statement {
    sid    = "AllowKMSUsage"
    effect = "Allow"
    
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    
    resources = [aws_kms_key.terraform_state.arn]
  }
}

resource "aws_iam_policy" "terraform_state" {
  name        = "TerraformStateAccess"
  description = "Policy for accessing Terraform state in S3 and DynamoDB"
  policy      = data.aws_iam_policy_document.terraform_state.json
}

# Output backend configuration
output "backend_config" {
  description = "Terraform backend configuration"
  value = {
    bucket         = aws_s3_bucket.terraform_state.id
    key            = "terraform.tfstate"  # Override per environment
    region         = data.aws_region.current.name
    encrypt        = true
    kms_key_id     = aws_kms_key.terraform_state.arn
    dynamodb_table = aws_dynamodb_table.terraform_state_lock.name
  }
}

# environments/production/backend.tf
terraform {
  backend "s3" {
    bucket         = "123456789012-terraform-state"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/..."
    dynamodb_table = "terraform-state-lock"
  }
}

# State migration script
#!/bin/bash
# scripts/migrate-state.sh

set -euo pipefail

ENVIRONMENT=$1
OLD_BACKEND=$2
NEW_BACKEND=$3

echo "Migrating Terraform state for environment: $ENVIRONMENT"
echo "From: $OLD_BACKEND"
echo "To: $NEW_BACKEND"

# Backup current state
terraform state pull > "state-backup-$(date +%Y%m%d-%H%M%S).json"

# Initialize with new backend
terraform init -migrate-state \
  -backend-config="$NEW_BACKEND" \
  -force-copy

# Verify state
terraform state list

echo "State migration completed successfully"
```
</recommended>
</example>
</examples>

## Security and Compliance

### Security Baseline

<guideline>
Implement defense in depth with multiple layers of security controls. Automate compliance checking and enforce security policies through code.
</guideline>

<examples>
<example>
<situation>Implementing comprehensive security controls for AWS</situation>
<recommended>
```hcl
# modules/security-baseline/main.tf
# AWS Security Baseline Module

# Enable AWS Config
resource "aws_config_configuration_recorder" "main" {
  name     = "${var.project_name}-config-recorder"
  role_arn = aws_iam_role.config.arn
  
  recording_group {
    all_supported = true
    
    recording_strategy {
      use_only = "ALL_SUPPORTED_RESOURCE_TYPES"
    }
  }
  
  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.project_name}-config-delivery"
  s3_bucket_name = aws_s3_bucket.config.bucket
  
  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  
  depends_on = [aws_config_delivery_channel.main]
}

# Config Rules for compliance
resource "aws_config_config_rule" "required_tags" {
  name = "required-tags"
  
  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }
  
  input_parameters = jsonencode({
    tag1Key = "Project"
    tag2Key = "Environment"
    tag3Key = "Owner"
    tag4Key = "CostCenter"
  })
}

resource "aws_config_config_rule" "encrypted_volumes" {
  name = "encrypted-volumes"
  
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
}

# GuardDuty for threat detection
resource "aws_guardduty_detector" "main" {
  enable = true
  
  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
  
  tags = local.common_tags
}

# Security Hub for centralized security findings
resource "aws_securityhub_account" "main" {
  enable_default_standards = false  # We'll enable specific standards
  
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/cis-aws-foundations-benchmark/v/1.4.0"
  
  depends_on = [aws_securityhub_account.main]
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  count = var.enable_pci_compliance ? 1 : 0
  
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/pci-dss/v/3.2.1"
  
  depends_on = [aws_securityhub_account.main]
}

# CloudTrail for audit logging
resource "aws_cloudtrail" "main" {
  name                          = "${var.project_name}-audit-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/"]
    }
    
    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda:*:*:function/*"]
    }
  }
  
  insight_selector {
    insight_type = "ApiCallRateInsight"
  }
  
  advanced_event_selector {
    name = "Log all data events"
    
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
  }
  
  kms_key_id = aws_kms_key.cloudtrail.arn
  
  tags = local.common_tags
  
  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

# KMS key for CloudTrail encryption
resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-cloudtrail-kms"
  })
}

# S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "${data.aws_caller_identity.current.account_id}-${var.project_name}-cloudtrail"
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-cloudtrail-bucket"
  })
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# IAM Access Analyzer
resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = "${var.project_name}-access-analyzer"
  type          = "ACCOUNT"
  
  tags = local.common_tags
}

# Password policy
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}

# Default security group rules (deny all)
resource "aws_default_security_group" "default" {
  vpc_id = var.vpc_id
  
  # Remove all default rules
  ingress = []
  egress  = []
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-default-sg-deny-all"
  })
}

# Enable EBS encryption by default
resource "aws_ebs_encryption_by_default" "main" {
  enabled = true
}

resource "aws_ebs_default_kms_key" "main" {
  key_arn = aws_kms_key.ebs.arn
}

# Systems Manager Session Manager for secure access
resource "aws_iam_role" "ssm" {
  name = "${var.project_name}-ssm-role"
  
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
  
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.ssm.name
}

# VPC Endpoints for secure access to AWS services
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = var.vpc_id
  service_name = "com.amazonaws.${data.aws_region.current.name}.s3"
  
  route_table_ids = var.route_table_ids
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "*"
        Resource  = "*"
        Condition = {
          StringEquals = {
            "aws:PrincipalAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-s3-endpoint"
  })
}

# Automated remediation for common issues
resource "aws_config_remediation_configuration" "s3_bucket_public_read_prohibited" {
  config_rule_name = aws_config_config_rule.s3_bucket_public_read_prohibited.name
  
  resource_type    = "AWS::S3::Bucket"
  target_type      = "SSM_DOCUMENT"
  target_identifier = "AWS-PublishSNSNotification"
  
  parameter {
    name           = "AutomationAssumeRole"
    static_value   = aws_iam_role.remediation.arn
  }
  
  parameter {
    name           = "TopicArn"
    static_value   = aws_sns_topic.security_alerts.arn
  }
  
  parameter {
    name           = "Message"
    static_value   = "S3 bucket found with public read access"
  }
  
  automatic                = true
  maximum_automatic_attempts = 3
}

# Security notifications
resource "aws_sns_topic" "security_alerts" {
  name = "${var.project_name}-security-alerts"
  
  kms_master_key_id = aws_kms_key.sns.id
  
  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "security_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_email
}

# CloudWatch alarms for security events
resource "aws_cloudwatch_metric_alarm" "root_account_usage" {
  alarm_name          = "${var.project_name}-root-account-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootAccountUsage"
  namespace           = "CloudTrailMetrics"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors root account usage"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  
  tags = local.common_tags
}

# Network security monitoring
resource "aws_networkfirewall_firewall" "main" {
  count = var.enable_network_firewall ? 1 : 0
  
  name                = "${var.project_name}-network-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main[0].arn
  vpc_id              = var.vpc_id
  
  dynamic "subnet_mapping" {
    for_each = var.firewall_subnet_ids
    content {
      subnet_id = subnet_mapping.value
    }
  }
  
  tags = local.common_tags
}

resource "aws_networkfirewall_firewall_policy" "main" {
  count = var.enable_network_firewall ? 1 : 0
  
  name = "${var.project_name}-firewall-policy"
  
  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
    
    stateful_engine_options {
      rule_order = "STRICT_ORDER"
    }
    
    stateful_rule_group_reference {
      priority     = 100
      resource_arn = aws_networkfirewall_rule_group.block_domains[0].arn
    }
  }
  
  tags = local.common_tags
}
```
</recommended>
</example>
</examples>

### Secrets Management

<guideline>
Never store secrets in code. Use dedicated secret management services with proper rotation and access controls.
</guideline>

<examples>
<example>
<situation>Implementing secure secrets management with automatic rotation</situation>
<recommended>
```hcl
# modules/secrets-manager/main.tf
# Database password with automatic rotation
resource "aws_secretsmanager_secret" "db_password" {
  name_prefix             = "${var.project_name}-${var.environment}-db-password"
  description             = "RDS master password for ${var.project_name}"
  recovery_window_in_days = var.secret_recovery_days
  
  rotation_rules {
    automatically_after_days = 30
  }
  
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
  
  secret_string = jsonencode({
    username = var.db_username
    password = random_password.db_password.result
    engine   = "postgres"
    host     = aws_db_instance.main.address
    port     = aws_db_instance.main.port
    dbname   = aws_db_instance.main.db_name
  })
  
  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "random_password" "db_password" {
  length  = 32
  special = true
  
  lifecycle {
    ignore_changes = all
  }
}

# Lambda function for password rotation
resource "aws_lambda_function" "rotate_secret" {
  filename         = data.archive_file.rotation_lambda.output_path
  function_name    = "${var.project_name}-${var.environment}-rotate-secret"
  role            = aws_iam_role.rotation_lambda.arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.rotation_lambda.output_base64sha256
  runtime         = "python3.11"
  timeout         = 30
  
  environment {
    variables = {
      SECRETS_MANAGER_ENDPOINT = "https://secretsmanager.${data.aws_region.current.name}.amazonaws.com"
    }
  }
  
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_rotation.id]
  }
  
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_rotation" "db_password" {
  secret_id           = aws_secretsmanager_secret.db_password.id
  rotation_lambda_arn = aws_lambda_function.rotate_secret.arn
  
  rotation_rules {
    automatically_after_days = 30
  }
}

# IAM role for rotation Lambda
resource "aws_iam_role" "rotation_lambda" {
  name = "${var.project_name}-${var.environment}-rotation-lambda"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy" "rotation_lambda" {
  name = "rotation-policy"
  role = aws_iam_role.rotation_lambda.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage"
        ]
        Resource = aws_secretsmanager_secret.db_password.arn
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetRandomPassword"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:ModifyDBInstance"
        ]
        Resource = aws_db_instance.main.arn
      }
    ]
  })
}

# API keys with versioning
resource "aws_secretsmanager_secret" "api_keys" {
  name_prefix = "${var.project_name}-${var.environment}-api-keys"
  description = "API keys for external services"
  
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "api_keys" {
  secret_id = aws_secretsmanager_secret.api_keys.id
  
  secret_string = jsonencode({
    stripe_key     = var.stripe_api_key
    sendgrid_key   = var.sendgrid_api_key
    datadog_api_key = var.datadog_api_key
    version        = "1.0"
  })
}

# Cross-region replication for disaster recovery
resource "aws_secretsmanager_secret" "replicated" {
  name_prefix = "${var.project_name}-${var.environment}-replicated"
  
  replica {
    region     = var.replica_region
    kms_key_id = var.replica_kms_key_id
  }
  
  tags = local.common_tags
}

# modules/app/main.tf - Using secrets in applications
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = var.db_secret_arn
}

locals {
  db_creds = jsondecode(data.aws_secretsmanager_secret_version.db_password.secret_string)
}

resource "aws_ecs_task_definition" "app" {
  family                   = "${var.project_name}-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn
  
  container_definitions = jsonencode([
    {
      name  = "app"
      image = "${var.ecr_repository_url}:${var.app_version}"
      
      environment = [
        {
          name  = "DB_HOST"
          value = local.db_creds.host
        },
        {
          name  = "DB_PORT"
          value = tostring(local.db_creds.port)
        },
        {
          name  = "DB_NAME"
          value = local.db_creds.dbname
        }
      ]
      
      secrets = [
        {
          name      = "DB_USERNAME"
          valueFrom = "${var.db_secret_arn}:username::"
        },
        {
          name      = "DB_PASSWORD"
          valueFrom = "${var.db_secret_arn}:password::"
        },
        {
          name      = "API_KEY"
          valueFrom = "${var.api_keys_secret_arn}:stripe_key::"
        }
      ]
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])
}

# Grant task access to secrets
resource "aws_iam_role_policy" "ecs_secrets" {
  name = "ecs-secrets-access"
  role = aws_iam_role.ecs_task.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          var.db_secret_arn,
          var.api_keys_secret_arn
        ]
      }
    ]
  })
}
```
</recommended>
</example>
</examples>

## Cost Optimization

### Resource Tagging Strategy

<guideline>
Implement comprehensive tagging for cost allocation, automation, and governance. Use consistent tag naming across all resources.
</guideline>

<examples>
<example>
<situation>Implementing a comprehensive tagging strategy</situation>
<recommended>
```hcl
# modules/tagging/variables.tf
variable "mandatory_tags" {
  description = "Mandatory tags that must be applied to all resources"
  type        = map(string)
  
  validation {
    condition = alltrue([
      contains(keys(var.mandatory_tags), "Project"),
      contains(keys(var.mandatory_tags), "Environment"),
      contains(keys(var.mandatory_tags), "Owner"),
      contains(keys(var.mandatory_tags), "CostCenter")
    ])
    error_message = "Mandatory tags must include: Project, Environment, Owner, CostCenter."
  }
}

variable "additional_tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}

# modules/tagging/main.tf
locals {
  # Computed tags
  computed_tags = {
    ManagedBy        = "terraform"
    TerraformWorkspace = terraform.workspace
    LastModified     = timestamp()
    GitCommit        = data.external.git_commit.result.sha
  }
  
  # Merge all tags
  all_tags = merge(
    var.mandatory_tags,
    var.additional_tags,
    local.computed_tags
  )
  
  # Tags for data lifecycle
  data_classification_tags = {
    DataClassification = var.data_classification # public, internal, confidential, restricted
    RetentionPeriod    = var.retention_period
    ComplianceScope    = var.compliance_scope    # pci, hipaa, sox, none
  }
  
  # Tags for automation
  automation_tags = {
    AutoShutdown = var.auto_shutdown_enabled ? "true" : "false"
    BackupPolicy = var.backup_policy
    PatchGroup   = var.patch_group
  }
}

# Data source for git commit
data "external" "git_commit" {
  program = ["sh", "-c", "echo '{\"sha\":\"'$(git rev-parse --short HEAD)'\"}''"]
}

# Cost allocation tags for different resource types
output "ec2_tags" {
  description = "Tags for EC2 instances"
  value = merge(
    local.all_tags,
    local.automation_tags,
    {
      InstanceType    = var.instance_type
      OperatingSystem = var.operating_system
      Purpose         = var.instance_purpose
    }
  )
}

output "rds_tags" {
  description = "Tags for RDS instances"
  value = merge(
    local.all_tags,
    local.data_classification_tags,
    {
      Engine         = var.db_engine
      EngineVersion  = var.db_engine_version
      MultiAZ        = var.multi_az ? "true" : "false"
      BackupRetention = var.backup_retention_period
    }
  )
}

output "s3_tags" {
  description = "Tags for S3 buckets"
  value = merge(
    local.all_tags,
    local.data_classification_tags,
    {
      BucketPurpose    = var.bucket_purpose
      LifecycleEnabled = var.lifecycle_enabled ? "true" : "false"
      Versioning       = var.versioning_enabled ? "true" : "false"
    }
  )
}

# modules/cost-management/budget-alerts.tf
resource "aws_budgets_budget" "project" {
  name              = "${var.project_name}-${var.environment}-budget"
  budget_type       = "COST"
  limit_amount      = var.monthly_budget_limit
  limit_unit        = "USD"
  time_unit         = "MONTHLY"
  time_period_start = "2024-01-01_00:00"
  
  cost_filter {
    name = "TagKeyValue"
    values = [
      "Project$${var.project_name}",
      "Environment$${var.environment}"
    ]
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_email_addresses = var.budget_notification_emails
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "FORECASTED"
    subscriber_email_addresses = var.budget_notification_emails
  }
}

# Tag enforcement policy
resource "aws_organizations_policy" "tagging" {
  name = "enforce-tagging-policy"
  type = "TAG_POLICY"
  
  content = jsonencode({
    tags = {
      Project = {
        tag_key = {
          "@@assign" = "Project"
        }
        enforced_for = {
          "@@assign" = ["ec2:instance", "rds:db", "s3:bucket"]
        }
      }
      Environment = {
        tag_key = {
          "@@assign" = "Environment"
        }
        tag_value = {
          "@@assign" = ["dev", "staging", "prod"]
        }
        enforced_for = {
          "@@assign" = ["ec2:*", "rds:*", "s3:*"]
        }
      }
    }
  })
}

# Cost anomaly detection
resource "aws_ce_anomaly_monitor" "main" {
  name              = "${var.project_name}-anomaly-monitor"
  monitor_type      = "DIMENSIONAL"
  monitor_dimension = "SERVICE"
}

resource "aws_ce_anomaly_subscription" "main" {
  name      = "${var.project_name}-anomaly-subscription"
  threshold_expression {
    dimension {
      key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      values        = ["100"]
      match_options = ["GREATER_THAN_OR_EQUAL"]
    }
  }
  
  frequency = "DAILY"
  monitor_arn_list = [
    aws_ce_anomaly_monitor.main.arn
  ]
  
  subscriber {
    type    = "EMAIL"
    address = var.cost_anomaly_email
  }
}
```
</recommended>
</example>
</examples>

### Cost-Optimized Architecture

<guideline>
Design infrastructure with cost efficiency in mind. Use appropriate instance types, implement auto-scaling, and leverage spot instances where appropriate.
</guideline>

<examples>
<example>
<situation>Building cost-optimized compute infrastructure</situation>
<recommended>
```hcl
# modules/compute-optimized/main.tf
# Mixed instance policy with Spot
resource "aws_autoscaling_group" "app" {
  name                = "${var.project_name}-${var.environment}-asg"
  vpc_zone_identifier = var.private_subnet_ids
  target_group_arns   = [aws_lb_target_group.app.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300
  
  min_size         = var.min_size
  max_size         = var.max_size
  desired_capacity = var.desired_capacity
  
  # Enable instance refresh for deployments
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 90
      instance_warmup        = 300
    }
  }
  
  mixed_instances_policy {
    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.app.id
        version            = "$Latest"
      }
      
      override {
        instance_type     = "t3.medium"
        weighted_capacity = 1
      }
      
      override {
        instance_type     = "t3a.medium"
        weighted_capacity = 1
      }
      
      override {
        instance_type     = "t2.medium"
        weighted_capacity = 1
      }
    }
    
    instances_distribution {
      on_demand_allocation_strategy            = "prioritized"
      on_demand_base_capacity                  = var.on_demand_base_capacity
      on_demand_percentage_above_base_capacity = var.on_demand_percentage
      spot_allocation_strategy                 = "capacity-optimized"
      spot_instance_pools                      = 3
    }
  }
  
  tag {
    key                 = "Name"
    value               = "${var.project_name}-${var.environment}-instance"
    propagate_at_launch = true
  }
  
  dynamic "tag" {
    for_each = local.asg_tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
}

# Scheduled scaling for predictable patterns
resource "aws_autoscaling_schedule" "scale_up_morning" {
  scheduled_action_name  = "${var.project_name}-scale-up-morning"
  min_size               = var.min_size
  max_size               = var.max_size
  desired_capacity       = var.peak_capacity
  recurrence             = "0 8 * * MON-FRI"
  time_zone              = "America/New_York"
  autoscaling_group_name = aws_autoscaling_group.app.name
}

resource "aws_autoscaling_schedule" "scale_down_evening" {
  scheduled_action_name  = "${var.project_name}-scale-down-evening"
  min_size               = var.min_size_off_peak
  max_size               = var.max_size_off_peak
  desired_capacity       = var.off_peak_capacity
  recurrence             = "0 18 * * MON-FRI"
  time_zone              = "America/New_York"
  autoscaling_group_name = aws_autoscaling_group.app.name
}

# Compute Savings Plans
resource "aws_ce_cost_allocation_tag" "compute_type" {
  tag_key = "ComputeType"
  status  = "Active"
}

# S3 Intelligent-Tiering
resource "aws_s3_bucket_intelligent_tiering_configuration" "archive" {
  bucket = aws_s3_bucket.data.id
  name   = "entire-bucket"
  
  tiering {
    access_tier = "ARCHIVE_ACCESS"
    days        = 90
  }
  
  tiering {
    access_tier = "DEEP_ARCHIVE_ACCESS"
    days        = 180
  }
}

# RDS with appropriate sizing
resource "aws_db_instance" "main" {
  identifier = "${var.project_name}-${var.environment}-db"
  
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.environment == "prod" ? "db.r6g.large" : "db.t4g.medium"
  
  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage # Auto-scaling storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.rds.arn
  
  # Cost optimization settings
  enabled_cloudwatch_logs_exports = var.environment == "prod" ? ["postgresql"] : []
  performance_insights_enabled    = var.environment == "prod"
  backup_retention_period         = var.environment == "prod" ? 30 : 7
  
  # Use Multi-AZ only in production
  multi_az = var.environment == "prod"
  
  # Maintenance and backup windows during low-usage times
  maintenance_window = "sun:03:00-sun:04:00"
  backup_window      = "02:00-03:00"
  
  tags = local.common_tags
}

# Lambda for cost optimization automation
resource "aws_lambda_function" "cost_optimizer" {
  filename         = data.archive_file.cost_optimizer.output_path
  function_name    = "${var.project_name}-cost-optimizer"
  role            = aws_iam_role.cost_optimizer.arn
  handler         = "index.handler"
  runtime         = "python3.11"
  timeout         = 300
  
  environment {
    variables = {
      DRY_RUN = var.cost_optimizer_dry_run ? "true" : "false"
    }
  }
  
  tags = local.common_tags
}

# CloudWatch Events to trigger cost optimizer
resource "aws_cloudwatch_event_rule" "cost_optimizer" {
  name                = "${var.project_name}-cost-optimizer-schedule"
  description         = "Trigger cost optimization Lambda"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "cost_optimizer" {
  rule      = aws_cloudwatch_event_rule.cost_optimizer.name
  target_id = "CostOptimizerLambda"
  arn       = aws_lambda_function.cost_optimizer.arn
}

# Cost optimization Lambda code
data "archive_file" "cost_optimizer" {
  type        = "zip"
  output_path = "${path.module}/files/cost_optimizer.zip"
  
  source {
    content  = file("${path.module}/files/cost_optimizer.py")
    filename = "index.py"
  }
}

# files/cost_optimizer.py
"""
import boto3
import os
from datetime import datetime, timedelta

def handler(event, context):
    dry_run = os.environ.get('DRY_RUN', 'true') == 'true'
    
    # Stop instances with "AutoShutdown" tag after hours
    ec2 = boto3.client('ec2')
    
    # Find instances to stop
    response = ec2.describe_instances(
        Filters=[
            {'Name': 'tag:AutoShutdown', 'Values': ['true']},
            {'Name': 'instance-state-name', 'Values': ['running']}
        ]
    )
    
    instance_ids = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            # Check if outside business hours
            if is_outside_business_hours():
                instance_ids.append(instance['InstanceId'])
    
    if instance_ids and not dry_run:
        ec2.stop_instances(InstanceIds=instance_ids)
        print(f"Stopped {len(instance_ids)} instances")
    
    # Delete old snapshots
    delete_old_snapshots(dry_run)
    
    # Remove unattached EBS volumes
    remove_unattached_volumes(dry_run)
    
    return {
        'statusCode': 200,
        'body': {
            'stopped_instances': instance_ids,
            'dry_run': dry_run
        }
    }

def is_outside_business_hours():
    now = datetime.now()
    # Business hours: Mon-Fri 8AM-6PM
    if now.weekday() >= 5:  # Weekend
        return True
    if now.hour < 8 or now.hour >= 18:
        return True
    return False

def delete_old_snapshots(dry_run):
    ec2 = boto3.client('ec2')
    cutoff_date = datetime.now() - timedelta(days=30)
    
    snapshots = ec2.describe_snapshots(OwnerIds=['self'])
    
    for snapshot in snapshots['Snapshots']:
        if snapshot['StartTime'].replace(tzinfo=None) < cutoff_date:
            if not dry_run:
                try:
                    ec2.delete_snapshot(SnapshotId=snapshot['SnapshotId'])
                    print(f"Deleted snapshot {snapshot['SnapshotId']}")
                except Exception as e:
                    print(f"Error deleting snapshot: {e}")
"""
```
</recommended>
</example>
</examples>

## CI/CD Integration

### Terraform Pipeline

<guideline>
Implement automated, secure CI/CD pipelines for infrastructure changes. Include validation, security scanning, and approval workflows.
</guideline>

<examples>
<example>
<situation>Building a production-ready Terraform CI/CD pipeline</situation>
<recommended>
```yaml
# .github/workflows/terraform.yml
name: Terraform CI/CD

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  TF_VERSION: "1.5.7"
  TF_VAR_project_name: ${{ github.event.repository.name }}
  AWS_REGION: us-east-1

jobs:
  validate:
    name: Validate Terraform
    runs-on: ubuntu-latest
    strategy:
      matrix:
        environment: [dev, staging, prod]
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${{ secrets.AWS_ACCOUNT_ID }}:role/github-actions
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Terraform Init
        run: |
          terraform -chdir=environments/${{ matrix.environment }} init -backend=false
      
      - name: Terraform Format Check
        run: |
          terraform fmt -check -recursive
      
      - name: Terraform Validate
        run: |
          terraform -chdir=environments/${{ matrix.environment }} validate
      
      - name: TFLint
        uses: terraform-linters/setup-tflint@v4
        with:
          tflint_version: latest
      
      - name: Run TFLint
        run: |
          tflint --init
          tflint --recursive

  security-scan:
    name: Security Scanning
    runs-on: ubuntu-latest
    needs: validate
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Checkov Security Scan
        uses: bridgecrewio/checkov-action@master
        with:
          directory: .
          framework: terraform
          output_format: sarif
          output_file_path: checkov.sarif
          soft_fail: false
          skip_check: CKV_AWS_8,CKV_AWS_79  # Document any excluded checks
      
      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: checkov.sarif
      
      - name: Terrascan
        uses: tenable/terrascan-action@main
        with:
          iac_type: terraform
          iac_version: v15
          policy_type: aws
          sarif_upload: true
      
      - name: tfsec
        uses: aquasecurity/tfsec-action@v1.0.0
        with:
          github_token: ${{ github.token }}
          soft_fail: false

  cost-estimation:
    name: Cost Estimation
    runs-on: ubuntu-latest
    needs: validate
    if: github.event_name == 'pull_request'
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Infracost
        uses: infracost/setup-infracost@v2
        with:
          api-key: ${{ secrets.INFRACOST_API_KEY }}
      
      - name: Generate Infracost baseline
        run: |
          infracost breakdown \
            --path=environments/prod \
            --format=json \
            --out-file=/tmp/infracost-base.json
      
      - name: Generate Infracost diff
        run: |
          infracost diff \
            --path=environments/prod \
            --format=json \
            --compare-to=/tmp/infracost-base.json \
            --out-file=/tmp/infracost.json
      
      - name: Post Infracost comment
        run: |
          infracost comment github \
            --path=/tmp/infracost.json \
            --repo=$GITHUB_REPOSITORY \
            --pull-request=${{ github.event.pull_request.number }} \
            --github-token=${{ github.token }} \
            --behavior=update

  plan:
    name: Terraform Plan
    runs-on: ubuntu-latest
    needs: [security-scan, cost-estimation]
    if: github.event_name == 'pull_request'
    strategy:
      matrix:
        environment: [dev, staging, prod]
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${{ secrets.AWS_ACCOUNT_ID }}:role/github-actions
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Terraform Init
        run: |
          terraform -chdir=environments/${{ matrix.environment }} init
      
      - name: Terraform Plan
        id: plan
        run: |
          terraform -chdir=environments/${{ matrix.environment }} plan \
            -out=tfplan \
            -var="environment=${{ matrix.environment }}"
      
      - name: Upload Plan
        uses: actions/upload-artifact@v3
        with:
          name: tfplan-${{ matrix.environment }}
          path: environments/${{ matrix.environment }}/tfplan
      
      - name: Comment PR
        uses: actions/github-script@v6
        if: github.event_name == 'pull_request'
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          script: |
            const output = `#### Terraform Plan - ${{ matrix.environment }} 📖
            
            <details><summary>Show Plan</summary>
            
            \`\`\`terraform
            ${{ steps.plan.outputs.stdout }}
            \`\`\`
            
            </details>
            
            *Pushed by: @${{ github.actor }}, Action: \`${{ github.event_name }}\`*`;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: output
            })

  apply-dev:
    name: Apply to Development
    runs-on: ubuntu-latest
    needs: plan
    if: github.ref == 'refs/heads/develop' && github.event_name == 'push'
    environment: development
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${{ secrets.AWS_ACCOUNT_ID }}:role/github-actions
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Terraform Init
        run: |
          terraform -chdir=environments/dev init
      
      - name: Terraform Apply
        run: |
          terraform -chdir=environments/dev apply \
            -auto-approve \
            -var="environment=dev"
      
      - name: Terraform Output
        id: output
        run: |
          terraform -chdir=environments/dev output -json > outputs.json
      
      - name: Post deployment tests
        run: |
          ./scripts/post-deployment-tests.sh dev

  apply-prod:
    name: Apply to Production
    runs-on: ubuntu-latest
    needs: plan
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    environment: production
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${{ secrets.AWS_ACCOUNT_ID }}:role/github-actions
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Create backup
        run: |
          ./scripts/backup-state.sh prod
      
      - name: Terraform Init
        run: |
          terraform -chdir=environments/prod init
      
      - name: Terraform Apply
        run: |
          terraform -chdir=environments/prod apply \
            -auto-approve \
            -var="environment=prod"
      
      - name: Smoke tests
        run: |
          ./scripts/smoke-tests.sh prod
      
      - name: Notify deployment
        uses: 8398a7/action-slack@v3
        with:
          status: ${{ job.status }}
          text: "Production deployment completed"
          webhook_url: ${{ secrets.SLACK_WEBHOOK }}

# .gitlab-ci.yml - GitLab CI/CD example
stages:
  - validate
  - plan
  - apply

variables:
  TF_VERSION: "1.5.7"
  TF_IN_AUTOMATION: "true"

.terraform_base:
  image: hashicorp/terraform:${TF_VERSION}
  before_script:
    - apk add --no-cache aws-cli jq
    - aws configure set region ${AWS_DEFAULT_REGION}
  cache:
    key: ${CI_COMMIT_REF_SLUG}
    paths:
      - .terraform

validate:
  extends: .terraform_base
  stage: validate
  script:
    - terraform fmt -check -recursive
    - |
      for env in dev staging prod; do
        echo "Validating $env environment"
        cd environments/$env
        terraform init -backend=false
        terraform validate
        cd ../..
      done
  only:
    - merge_requests
    - main
    - develop

plan:dev:
  extends: .terraform_base
  stage: plan
  script:
    - cd environments/dev
    - terraform init
    - terraform plan -out=tfplan
  artifacts:
    paths:
      - environments/dev/tfplan
    expire_in: 7 days
  only:
    - merge_requests

apply:dev:
  extends: .terraform_base
  stage: apply
  script:
    - cd environments/dev
    - terraform init
    - terraform apply tfplan
  dependencies:
    - plan:dev
  only:
    - develop
  environment:
    name: development

apply:prod:
  extends: .terraform_base
  stage: apply
  script:
    - cd environments/prod
    - terraform init
    - terraform plan -out=tfplan
    - terraform apply tfplan
  only:
    - main
  when: manual
  environment:
    name: production
```

```bash
#!/bin/bash
# scripts/post-deployment-tests.sh
set -euo pipefail

ENVIRONMENT=$1

echo "Running post-deployment tests for $ENVIRONMENT"

# Test infrastructure endpoints
echo "Testing ALB health..."
ALB_DNS=$(terraform -chdir=environments/$ENVIRONMENT output -raw alb_dns_name)
curl -f "http://${ALB_DNS}/health" || exit 1

# Test database connectivity
echo "Testing RDS connectivity..."
DB_ENDPOINT=$(terraform -chdir=environments/$ENVIRONMENT output -raw db_endpoint)
nc -zv ${DB_ENDPOINT} 5432 || exit 1

# Test S3 bucket access
echo "Testing S3 access..."
BUCKET_NAME=$(terraform -chdir=environments/$ENVIRONMENT output -raw s3_bucket_name)
aws s3 ls s3://${BUCKET_NAME} || exit 1

echo "All tests passed!"
```
</recommended>
</example>
</examples>

## Multi-Environment Management

### Environment Isolation

<guideline>
Maintain strict isolation between environments while maximizing code reuse. Use workspaces or separate state files for each environment.
</guideline>

<examples>
<example>
<situation>Implementing a multi-environment Terraform structure</situation>
<recommended>
```hcl
# Directory structure
"""
terraform/
├── modules/
│   ├── vpc/
│   ├── ecs/
│   ├── rds/
│   └── s3/
├── environments/
│   ├── dev/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── terraform.tfvars
│   │   └── backend.tf
│   ├── staging/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── terraform.tfvars
│   │   └── backend.tf
│   └── prod/
│       ├── main.tf
│       ├── variables.tf
│       ├── terraform.tfvars
│       └── backend.tf
└── global/
    ├── iam/
    ├── route53/
    └── cloudfront/
"""

# environments/base/variables.tf - Shared variables
variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# environments/dev/main.tf
terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  environment = "dev"
  
  # Environment-specific configuration
  vpc_cidr = "10.0.0.0/16"
  
  # Reduced resources for dev
  ecs_min_capacity = 1
  ecs_max_capacity = 3
  rds_instance_class = "db.t4g.micro"
  
  common_tags = merge(
    var.common_tags,
    {
      Environment = local.environment
      ManagedBy   = "terraform"
      Project     = var.project_name
    }
  )
}

# VPC Module
module "vpc" {
  source = "../../modules/vpc"
  
  project_name       = var.project_name
  environment        = local.environment
  cidr_block         = local.vpc_cidr
  availability_zones = 2  # Only 2 AZs for dev
  
  # Cost optimization for dev
  enable_nat_gateway = true
  single_nat_gateway = true  # Single NAT for dev
  enable_flow_logs   = false # No flow logs in dev
  
  tags = local.common_tags
}

# ECS Cluster
module "ecs" {
  source = "../../modules/ecs"
  
  project_name     = var.project_name
  environment      = local.environment
  vpc_id           = module.vpc.vpc_id
  private_subnets  = module.vpc.private_subnet_ids
  public_subnets   = module.vpc.public_subnet_ids
  
  # Dev-specific settings
  min_capacity     = local.ecs_min_capacity
  max_capacity     = local.ecs_max_capacity
  
  # Disable expensive features in dev
  enable_container_insights = false
  enable_execute_command    = true  # Enable for debugging
  
  tags = local.common_tags
}

# RDS Database
module "rds" {
  source = "../../modules/rds"
  
  project_name       = var.project_name
  environment        = local.environment
  vpc_id             = module.vpc.vpc_id
  database_subnets   = module.vpc.private_subnet_ids
  
  # Dev-specific database configuration
  instance_class     = local.rds_instance_class
  allocated_storage  = 20
  multi_az           = false  # No Multi-AZ in dev
  backup_retention   = 1      # Minimal backups
  
  # Enable deletion for dev
  deletion_protection = false
  skip_final_snapshot = true
  
  tags = local.common_tags
}

# environments/prod/main.tf
locals {
  environment = "prod"
  
  # Production configuration
  vpc_cidr = "10.2.0.0/16"  # Different CIDR for prod
  
  # Production scaling
  ecs_min_capacity = 3
  ecs_max_capacity = 20
  rds_instance_class = "db.r6g.xlarge"
  
  common_tags = merge(
    var.common_tags,
    {
      Environment     = local.environment
      ManagedBy       = "terraform"
      Project         = var.project_name
      CriticalityLevel = "high"
      DataClassification = "confidential"
    }
  )
}

# Production VPC with full features
module "vpc" {
  source = "../../modules/vpc"
  
  project_name       = var.project_name
  environment        = local.environment
  cidr_block         = local.vpc_cidr
  availability_zones = 3  # 3 AZs for production
  
  # High availability
  enable_nat_gateway      = true
  single_nat_gateway      = false  # NAT per AZ
  enable_flow_logs        = true
  flow_log_retention_days = 90
  
  # Additional security
  enable_network_firewall = true
  
  tags = local.common_tags
}

# Production ECS with auto-scaling
module "ecs" {
  source = "../../modules/ecs"
  
  project_name     = var.project_name
  environment      = local.environment
  vpc_id           = module.vpc.vpc_id
  private_subnets  = module.vpc.private_subnet_ids
  public_subnets   = module.vpc.public_subnet_ids
  
  # Production scaling
  min_capacity     = local.ecs_min_capacity
  max_capacity     = local.ecs_max_capacity
  
  # Enable all monitoring
  enable_container_insights = true
  enable_execute_command    = false  # Disable for security
  
  # Auto-scaling policies
  target_cpu_utilization    = 70
  target_memory_utilization = 80
  scale_in_cooldown         = 300
  scale_out_cooldown        = 60
  
  tags = local.common_tags
}

# Production RDS with HA
module "rds" {
  source = "../../modules/rds"
  
  project_name       = var.project_name
  environment        = local.environment
  vpc_id             = module.vpc.vpc_id
  database_subnets   = module.vpc.private_subnet_ids
  
  # Production database configuration
  instance_class              = local.rds_instance_class
  allocated_storage           = 100
  max_allocated_storage       = 1000  # Auto-scaling storage
  multi_az                    = true
  backup_retention            = 30
  backup_window               = "03:00-04:00"
  maintenance_window          = "sun:04:00-sun:05:00"
  
  # Production protection
  deletion_protection = true
  skip_final_snapshot = false
  final_snapshot_identifier = "${var.project_name}-${local.environment}-final-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"
  
  # Performance insights
  performance_insights_enabled = true
  performance_insights_retention = 7
  
  # Enhanced monitoring
  enabled_cloudwatch_logs_exports = ["postgresql"]
  monitoring_interval             = 60
  monitoring_role_arn             = aws_iam_role.rds_monitoring.arn
  
  tags = local.common_tags
}

# WAF for production
module "waf" {
  source = "../../modules/waf"
  
  project_name = var.project_name
  environment  = local.environment
  
  # Attach to ALB
  resource_arn = module.ecs.alb_arn
  
  # Enable all rule groups
  enable_rate_limiting     = true
  rate_limit              = 2000
  enable_ip_reputation    = true
  enable_managed_rules    = true
  enable_custom_rules     = true
  
  # Geo-blocking
  allowed_countries = ["US", "CA", "GB", "DE", "FR"]
  
  tags = local.common_tags
}

# Disaster Recovery resources
module "dr_backup" {
  source = "../../modules/backup"
  
  project_name = var.project_name
  environment  = local.environment
  
  # Backup configuration
  backup_vault_name = "${var.project_name}-${local.environment}-backup-vault"
  
  # Cross-region replication
  enable_cross_region_backup = true
  replica_region             = "us-west-2"
  
  # Backup rules
  backup_rules = [
    {
      name              = "daily"
      schedule          = "cron(0 5 ? * * *)"
      retention_days    = 30
      copy_to_region    = "us-west-2"
    },
    {
      name              = "weekly"
      schedule          = "cron(0 5 ? * SUN *)"
      retention_days    = 90
      copy_to_region    = "us-west-2"
    },
    {
      name              = "monthly"
      schedule          = "cron(0 5 1 * ? *)"
      retention_days    = 365
      copy_to_region    = "us-west-2"
    }
  ]
  
  # Resources to backup
  backup_selection = {
    resources = [
      module.rds.db_instance_arn,
      "arn:aws:dynamodb:*:*:table/${var.project_name}-*",
      "arn:aws:efs:*:*:file-system/*"
    ]
    
    selection_tags = {
      Backup = "true"
    }
  }
  
  tags = local.common_tags
}

# Environment-specific outputs
output "environment_info" {
  description = "Environment-specific information"
  value = {
    name         = local.environment
    vpc_id       = module.vpc.vpc_id
    alb_endpoint = module.ecs.alb_dns_name
    rds_endpoint = module.rds.endpoint
  }
}

# scripts/promote-environment.sh
#!/bin/bash
# Promote configuration from one environment to another

set -euo pipefail

SOURCE_ENV=$1
TARGET_ENV=$2

if [[ "$TARGET_ENV" == "prod" ]]; then
  echo "Production promotion requires approval"
  read -p "Are you sure you want to promote to production? (yes/no): " -n 3 -r
  echo
  if [[ ! $REPLY =~ ^yes$ ]]; then
    echo "Promotion cancelled"
    exit 1
  fi
fi

# Copy tfvars with environment-specific overrides
cp environments/$SOURCE_ENV/terraform.tfvars environments/$TARGET_ENV/terraform.tfvars.new

# Apply environment-specific overrides
case $TARGET_ENV in
  staging)
    sed -i 's/environment = "dev"/environment = "staging"/' environments/$TARGET_ENV/terraform.tfvars.new
    ;;
  prod)
    sed -i 's/environment = "staging"/environment = "prod"/' environments/$TARGET_ENV/terraform.tfvars.new
    # Additional production-specific settings
    echo 'enable_deletion_protection = true' >> environments/$TARGET_ENV/terraform.tfvars.new
    echo 'enable_backups = true' >> environments/$TARGET_ENV/terraform.tfvars.new
    ;;
esac

echo "Configuration promoted from $SOURCE_ENV to $TARGET_ENV"
echo "Review environments/$TARGET_ENV/terraform.tfvars.new before applying"
```
</recommended>
</example>
</examples>

## Disaster Recovery

### Backup and Recovery Strategy

<guideline>
Implement comprehensive backup strategies with regular testing. Design for various failure scenarios including region-wide outages.
</guideline>

<examples>
<example>
<situation>Implementing multi-region disaster recovery</situation>
<recommended>
```hcl
# modules/disaster-recovery/main.tf
locals {
  primary_region = var.primary_region
  dr_region      = var.dr_region
  
  common_tags = merge(
    var.tags,
    {
      Purpose = "disaster-recovery"
      DrRole  = var.dr_role  # primary or secondary
    }
  )
}

# Cross-region replication for S3
resource "aws_s3_bucket" "primary" {
  bucket = "${var.project_name}-${var.environment}-primary"
  
  tags = merge(local.common_tags, {
    Region = local.primary_region
  })
}

resource "aws_s3_bucket_versioning" "primary" {
  bucket = aws_s3_bucket.primary.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_replication_configuration" "primary" {
  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.primary.id
  
  rule {
    id     = "replicate-all"
    status = "Enabled"
    
    filter {}
    
    destination {
      bucket        = aws_s3_bucket.dr.arn
      storage_class = "GLACIER_IR"  # Cost-optimized for DR
      
      replication_time {
        status = "Enabled"
        time {
          minutes = 15
        }
      }
      
      metrics {
        status = "Enabled"
        event_threshold {
          minutes = 15
        }
      }
    }
    
    delete_marker_replication {
      status = "Enabled"
    }
  }
  
  depends_on = [aws_s3_bucket_versioning.primary]
}

# DR bucket in secondary region
resource "aws_s3_bucket" "dr" {
  provider = aws.dr
  bucket   = "${var.project_name}-${var.environment}-dr"
  
  tags = merge(local.common_tags, {
    Region = local.dr_region
  })
}

# RDS cross-region read replica
resource "aws_db_instance" "read_replica" {
  provider = aws.dr
  
  identifier = "${var.project_name}-${var.environment}-read-replica"
  
  replicate_source_db = var.primary_db_arn
  
  # DR can use smaller instance
  instance_class = var.dr_instance_class
  
  # Promote to master settings
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  
  tags = merge(local.common_tags, {
    ReplicaRole = "standby"
  })
}

# DynamoDB global table
resource "aws_dynamodb_table" "global" {
  name             = "${var.project_name}-${var.environment}-global"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "id"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  
  attribute {
    name = "id"
    type = "S"
  }
  
  replica {
    region_name = local.dr_region
    
    global_secondary_indexes {
      name               = "gsi1"
      hash_key           = "gsi1pk"
      range_key          = "gsi1sk"
      projection_type    = "ALL"
    }
  }
  
  point_in_time_recovery {
    enabled = true
  }
  
  server_side_encryption {
    enabled = true
  }
  
  tags = local.common_tags
}

# Route53 health checks and failover
resource "aws_route53_health_check" "primary" {
  fqdn              = var.primary_endpoint
  port              = 443
  type              = "HTTPS"
  resource_path     = "/health"
  failure_threshold = "3"
  request_interval  = "30"
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-primary-health"
  })
}

resource "aws_route53_health_check" "dr" {
  fqdn              = var.dr_endpoint
  port              = 443
  type              = "HTTPS"
  resource_path     = "/health"
  failure_threshold = "3"
  request_interval  = "30"
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-dr-health"
  })
}

resource "aws_route53_record" "failover_primary" {
  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"
  
  alias {
    name                   = var.primary_alb_dns
    zone_id                = var.primary_alb_zone_id
    evaluate_target_health = true
  }
  
  set_identifier = "primary"
  
  failover_routing_policy {
    type = "PRIMARY"
  }
  
  health_check_id = aws_route53_health_check.primary.id
}

resource "aws_route53_record" "failover_secondary" {
  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"
  
  alias {
    name                   = var.dr_alb_dns
    zone_id                = var.dr_alb_zone_id
    evaluate_target_health = true
  }
  
  set_identifier = "secondary"
  
  failover_routing_policy {
    type = "SECONDARY"
  }
  
  health_check_id = aws_route53_health_check.dr.id
}

# AWS Backup for coordinated backups
resource "aws_backup_plan" "dr" {
  name = "${var.project_name}-${var.environment}-dr-plan"
  
  rule {
    rule_name         = "hourly_snapshots"
    target_vault_name = aws_backup_vault.dr.name
    schedule          = "cron(0 * ? * * *)"
    
    lifecycle {
      delete_after = 24  # Keep hourly for 1 day
    }
    
    recovery_point_tags = local.common_tags
  }
  
  rule {
    rule_name         = "daily_snapshots"
    target_vault_name = aws_backup_vault.dr.name
    schedule          = "cron(0 5 ? * * *)"
    
    lifecycle {
      delete_after       = 30
      cold_storage_after = 7
    }
    
    copy_action {
      destination_vault_arn = aws_backup_vault.dr_replica.arn
      
      lifecycle {
        delete_after = 30
      }
    }
  }
  
  advanced_backup_setting {
    backup_options = {
      WindowsVSS = "enabled"
    }
    resource_type = "EC2"
  }
  
  tags = local.common_tags
}

resource "aws_backup_vault" "dr" {
  name        = "${var.project_name}-${var.environment}-dr-vault"
  kms_key_arn = aws_kms_key.backup.arn
  
  tags = local.common_tags
}

resource "aws_backup_vault" "dr_replica" {
  provider = aws.dr
  
  name        = "${var.project_name}-${var.environment}-dr-vault-replica"
  kms_key_arn = aws_kms_key.backup_dr.arn
  
  tags = local.common_tags
}

# Lambda for automated failover orchestration
resource "aws_lambda_function" "dr_orchestrator" {
  filename         = data.archive_file.dr_orchestrator.output_path
  function_name    = "${var.project_name}-dr-orchestrator"
  role            = aws_iam_role.dr_orchestrator.arn
  handler         = "index.handler"
  runtime         = "python3.11"
  timeout         = 900  # 15 minutes for failover
  
  environment {
    variables = {
      PRIMARY_REGION = local.primary_region
      DR_REGION      = local.dr_region
      RDS_CLUSTER_ID = var.rds_cluster_id
      PROJECT_NAME   = var.project_name
    }
  }
  
  tags = local.common_tags
}

# CloudWatch Events for DR testing
resource "aws_cloudwatch_event_rule" "dr_test" {
  name                = "${var.project_name}-dr-test"
  description         = "Monthly DR testing"
  schedule_expression = "cron(0 2 ? * SUN#1 *)"  # First Sunday of month
  
  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "dr_test" {
  rule      = aws_cloudwatch_event_rule.dr_test.name
  target_id = "DrTestLambda"
  arn       = aws_lambda_function.dr_test.arn
  
  input = jsonencode({
    test_type = "read_only"
    notify    = var.dr_notification_emails
  })
}

# DR runbook as code
resource "aws_systems_manager_document" "dr_runbook" {
  name            = "${var.project_name}-dr-runbook"
  document_type   = "Automation"
  document_format = "YAML"
  
  content = <<DOC
schemaVersion: '0.3'
description: Disaster Recovery Runbook for ${var.project_name}
parameters:
  DrType:
    type: String
    description: Type of DR event
    allowedValues:
      - test
      - partial
      - full
    default: test
  ApprovalRequired:
    type: Boolean
    default: true

mainSteps:
  - name: CheckPrimaryHealth
    action: 'aws:executeScript'
    inputs:
      Runtime: python3.8
      Handler: check_health
      Script: |
        def check_health(events, context):
          # Check primary region health
          import boto3
          cloudwatch = boto3.client('cloudwatch', region_name='${local.primary_region}')
          # Check metrics and alarms
          return {'healthy': False}  # Simplified
    outputs:
      - Name: PrimaryHealthy
        Selector: $.Payload.healthy
        Type: Boolean

  - name: RequireApproval
    action: 'aws:approve'
    onFailure: Abort
    inputs:
      Approvers:
        - '${var.approval_sns_topic}'
      Message: 'Approve DR failover?'
      MinRequiredApprovals: 2
    isEnd: false
    when: '{{ ApprovalRequired }}'

  - name: PromoteReadReplica
    action: 'aws:executeAwsApi'
    inputs:
      Service: rds
      Api: PromoteReadReplica
      Region: '${local.dr_region}'
      DBInstanceIdentifier: '${aws_db_instance.read_replica.id}'
    when: '{{ DrType }} != "test"'

  - name: UpdateDNS
    action: 'aws:executeScript'
    inputs:
      Runtime: python3.8
      Handler: update_dns
      Script: |
        def update_dns(events, context):
          # Update Route53 to point to DR region
          import boto3
          route53 = boto3.client('route53')
          # Update weighted routing
          return {'success': True}
DOC
  
  tags = local.common_tags
}

# outputs.tf
output "dr_endpoints" {
  description = "Disaster recovery endpoints"
  value = {
    primary_region = local.primary_region
    dr_region      = local.dr_region
    dr_rds_endpoint = aws_db_instance.read_replica.endpoint
    dr_s3_bucket    = aws_s3_bucket.dr.id
  }
}

output "recovery_metrics" {
  description = "Recovery time and point objectives"
  value = {
    rto_minutes = var.rto_minutes
    rpo_minutes = var.rpo_minutes
    backup_frequency = "hourly"
    replication_lag_alarm = aws_cloudwatch_metric_alarm.replication_lag.alarm_name
  }
}
```
</recommended>
</example>
</examples>

## Monitoring and Observability

### Infrastructure Monitoring

<guideline>
Implement comprehensive monitoring and alerting for infrastructure components. Use metrics, logs, and traces to maintain visibility.
</guideline>

<examples>
<example>
<situation>Building a complete observability stack</situation>
<recommended>
```hcl
# modules/observability/main.tf
# CloudWatch Dashboards
resource "aws_cloudwatch_dashboard" "infrastructure" {
  dashboard_name = "${var.project_name}-${var.environment}-infrastructure"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", { stat = "Average" }],
            [".", ".", { stat = "Maximum" }]
          ]
          period = 300
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "EC2 CPU Utilization"
          yAxis = {
            left = {
              min = 0
              max = 100
            }
          }
        }
      },
      {
        type   = "metric"
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/ApplicationELB", "TargetResponseTime", { stat = "Average" }],
            [".", ".", { stat = "p99" }]
          ]
          period = 60
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "ALB Response Time"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type   = "metric"
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/RDS", "DatabaseConnections", { stat = "Average" }],
            [".", "CPUUtilization", { stat = "Average" }],
            [".", "FreeableMemory", { stat = "Average" }]
          ]
          period = 300
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "RDS Metrics"
        }
      }
    ]
  })
}

# Custom CloudWatch Metrics
resource "aws_cloudwatch_log_metric_filter" "error_count" {
  name           = "${var.project_name}-error-count"
  log_group_name = aws_cloudwatch_log_group.application.name
  pattern        = "[timestamp, level=ERROR, ...]"
  
  metric_transformation {
    name      = "ErrorCount"
    namespace = "${var.project_name}/Application"
    value     = "1"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_log_metric_filter" "response_time" {
  name           = "${var.project_name}-response-time"
  log_group_name = aws_cloudwatch_log_group.application.name
  pattern        = "[timestamp, level, msg, response_time]"
  
  metric_transformation {
    name      = "ResponseTime"
    namespace = "${var.project_name}/Application"
    value     = "$response_time"
    unit      = "Milliseconds"
  }
}

# Composite Alarms for better signal-to-noise
resource "aws_cloudwatch_composite_alarm" "service_degraded" {
  alarm_name          = "${var.project_name}-${var.environment}-service-degraded"
  alarm_description   = "Service is experiencing degraded performance"
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  
  alarm_rule = join(" OR ", [
    aws_cloudwatch_metric_alarm.high_cpu.alarm_name,
    aws_cloudwatch_metric_alarm.high_memory.alarm_name,
    aws_cloudwatch_metric_alarm.high_error_rate.alarm_name,
    "${aws_cloudwatch_metric_alarm.slow_response.alarm_name} AND ${aws_cloudwatch_metric_alarm.high_traffic.alarm_name}"
  ])
  
  tags = local.common_tags
}

# Detailed metric alarms
resource "aws_cloudwatch_metric_alarm" "high_error_rate" {
  alarm_name          = "${var.project_name}-high-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ErrorCount"
  namespace           = "${var.project_name}/Application"
  period              = "300"
  statistic           = "Sum"
  threshold           = "50"
  alarm_description   = "Error rate is above threshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${var.project_name}-rds-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "RDS CPU utilization is high"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    DBInstanceIdentifier = var.rds_instance_id
  }
  
  tags = local.common_tags
}

# X-Ray for distributed tracing
resource "aws_xray_sampling_rule" "main" {
  rule_name      = "${var.project_name}-sampling"
  priority       = 9000
  version        = 1
  reservoir_size = 1
  fixed_rate     = 0.1  # 10% sampling
  url_path       = "*"
  host           = "*"
  http_method    = "*"
  service_type   = "*"
  service_name   = "*"
  resource_arn   = "*"
  
  tags = local.common_tags
}

# EventBridge for infrastructure events
resource "aws_cloudwatch_event_rule" "infrastructure_changes" {
  name        = "${var.project_name}-infrastructure-changes"
  description = "Capture infrastructure change events"
  
  event_pattern = jsonencode({
    source = ["aws.ec2", "aws.rds", "aws.elasticloadbalancing"]
    detail-type = [
      "EC2 Instance State-change Notification",
      "RDS DB Instance Event",
      "ELB Target Health Change"
    ]
  })
  
  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "infrastructure_log" {
  rule      = aws_cloudwatch_event_rule.infrastructure_changes.name
  target_id = "SendToCloudWatchLogs"
  arn       = aws_cloudwatch_log_group.infrastructure_events.arn
}

# SNS Topics for different severity levels
resource "aws_sns_topic" "critical_alerts" {
  name              = "${var.project_name}-critical-alerts"
  kms_master_key_id = aws_kms_key.sns.id
  
  tags = merge(local.common_tags, {
    Severity = "critical"
  })
}

resource "aws_sns_topic" "warning_alerts" {
  name              = "${var.project_name}-warning-alerts"
  kms_master_key_id = aws_kms_key.sns.id
  
  tags = merge(local.common_tags, {
    Severity = "warning"
  })
}

# Lambda for custom metrics collection
resource "aws_lambda_function" "custom_metrics" {
  filename         = data.archive_file.custom_metrics.output_path
  function_name    = "${var.project_name}-custom-metrics"
  role            = aws_iam_role.custom_metrics.arn
  handler         = "index.handler"
  runtime         = "python3.11"
  timeout         = 60
  
  environment {
    variables = {
      METRIC_NAMESPACE = "${var.project_name}/Custom"
    }
  }
  
  tags = local.common_tags
}

# CloudWatch Events to trigger metrics collection
resource "aws_cloudwatch_event_rule" "collect_metrics" {
  name                = "${var.project_name}-collect-metrics"
  description         = "Trigger custom metrics collection"
  schedule_expression = "rate(1 minute)"
  
  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "collect_metrics" {
  rule      = aws_cloudwatch_event_rule.collect_metrics.name
  target_id = "CustomMetricsLambda"
  arn       = aws_lambda_function.custom_metrics.arn
}

# CloudWatch Logs Insights queries
resource "aws_cloudwatch_query_definition" "error_analysis" {
  name = "${var.project_name}/ErrorAnalysis"
  
  log_group_names = [
    aws_cloudwatch_log_group.application.name
  ]
  
  query_string = <<-QUERY
    fields @timestamp, @message, level, error_type, stack_trace
    | filter level = "ERROR"
    | stats count() by error_type
    | sort count() desc
    | limit 20
  QUERY
}

resource "aws_cloudwatch_query_definition" "performance_analysis" {
  name = "${var.project_name}/PerformanceAnalysis"
  
  log_group_names = [
    aws_cloudwatch_log_group.application.name
  ]
  
  query_string = <<-QUERY
    fields @timestamp, @message, response_time, endpoint
    | filter response_time > 1000
    | stats avg(response_time), max(response_time), count() by endpoint
    | sort avg(response_time) desc
  QUERY
}

# Synthetics for endpoint monitoring
resource "aws_synthetics_canary" "api_health" {
  name                 = "${var.project_name}-api-health"
  artifact_s3_location = "s3://${aws_s3_bucket.synthetics.bucket}/canary/"
  execution_role_arn   = aws_iam_role.synthetics.arn
  handler              = "apiCanary.handler"
  zip_file             = data.archive_file.canary_script.output_path
  runtime_version      = "syn-nodejs-puppeteer-3.9"
  
  schedule {
    expression = "rate(5 minutes)"
  }
  
  run_config {
    timeout_in_seconds = 60
    memory_in_mb       = 960
  }
  
  success_retention_period = 2
  failure_retention_period = 14
  
  tags = local.common_tags
}

# Integration with external monitoring
resource "aws_kinesis_firehose_delivery_stream" "monitoring_export" {
  name        = "${var.project_name}-monitoring-export"
  destination = "http_endpoint"
  
  http_endpoint_configuration {
    url                = var.external_monitoring_endpoint
    name               = "DatadogEndpoint"
    access_key         = var.datadog_api_key
    buffering_size     = 5
    buffering_interval = 300
    
    request_configuration {
      content_encoding = "GZIP"
      
      common_attributes {
        name  = "environment"
        value = var.environment
      }
      
      common_attributes {
        name  = "service"
        value = var.project_name
      }
    }
  }
  
  cloudwatch_logging_options {
    enabled         = true
    log_group_name  = aws_cloudwatch_log_group.firehose.name
    log_stream_name = aws_cloudwatch_log_stream.firehose.name
  }
  
  tags = local.common_tags
}

# outputs.tf
output "monitoring_endpoints" {
  description = "Monitoring and observability endpoints"
  value = {
    dashboard_url = "https://console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.infrastructure.dashboard_name}"
    xray_service_map = "https://console.aws.amazon.com/xray/home?region=${data.aws_region.current.name}#/service-map"
    synthetics_canary = aws_synthetics_canary.api_health.name
  }
}

output "alert_topics" {
  description = "SNS topics for alerts"
  value = {
    critical = aws_sns_topic.critical_alerts.arn
    warning  = aws_sns_topic.warning_alerts.arn
  }
}
```
</recommended>
</example>
</examples>

## Conclusion

<summary>
These guidelines represent current best practices for building modern infrastructure with Terraform and cloud-native technologies. They emphasize security, scalability, cost optimization, and operational excellence throughout the infrastructure lifecycle.
</summary>

<key_principles>

1. __Everything as Code__ - Version control all infrastructure changes
2. __Immutable Infrastructure__ - Replace rather than modify
3. __Security by Design__ - Build security into every layer
4. __Cost Awareness__ - Optimize for both performance and cost
5. __Automate Everything__ - Eliminate manual processes
6. __Design for Failure__ - Build resilient, self-healing systems
</key_principles>

<continuous_improvement>
Review and update these guidelines quarterly to incorporate:

- New cloud service capabilities
- Security best practices and compliance requirements
- Cost optimization strategies
- Terraform feature updates
- Team learnings and post-incident reviews
- Industry best practices evolution
</continuous_improvement>

<thinking>
Remember: The best infrastructure is invisible to its users - it scales automatically, heals itself, and provides a stable platform for applications to thrive. These guidelines should enable building such robust foundations.
</thinking>