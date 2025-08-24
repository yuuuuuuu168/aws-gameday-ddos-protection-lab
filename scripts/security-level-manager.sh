#!/bin/bash

# AWS GameDay DDoS Environment - Security Level Manager
# This script helps manage security level transitions

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to display security level information
show_security_levels() {
    echo -e "\n${BLUE}=== AWS GameDay DDoS Environment - Security Levels ===${NC}\n"
    
    echo -e "${GREEN}Level 1: Baseline (No Protection)${NC}"
    echo "  - Vulnerable web application exposed directly"
    echo "  - No WAF, no Shield, no CloudFront"
    echo "  - Rate limit: 10,000 requests/5min per IP"
    echo "  - Purpose: Experience attacks without protection"
    echo ""
    
    echo -e "${GREEN}Level 2: Basic WAF Protection${NC}"
    echo "  - AWS WAF v2 with managed rule sets enabled"
    echo "  - SQL injection and XSS protection"
    echo "  - Rate limit: 5,000 requests/5min per IP"
    echo "  - Purpose: Learn basic web application firewall protection"
    echo ""
    
    echo -e "${GREEN}Level 3: Advanced Protection (WAF + Shield)${NC}"
    echo "  - All Level 2 features"
    echo "  - AWS Shield Advanced DDoS protection"
    echo "  - Rate limit: 2,000 requests/5min per IP"
    echo "  - Purpose: Experience advanced DDoS protection"
    echo ""
    
    echo -e "${GREEN}Level 4: Full Protection (CloudFront + WAF + Shield)${NC}"
    echo "  - All Level 3 features"
    echo "  - CloudFront CDN with global edge locations"
    echo "  - Origin access control"
    echo "  - Rate limit: 1,000 requests/5min per IP"
    echo "  - Purpose: Experience complete protection stack"
    echo ""
}

# Function to get current security level
get_current_level() {
    if [ -f "terraform.tfvars" ]; then
        grep "security_level" terraform.tfvars | cut -d'=' -f2 | tr -d ' "'
    else
        echo "1"
    fi
}

# Function to validate security level
validate_level() {
    local level=$1
    if [[ ! "$level" =~ ^[1-4]$ ]]; then
        print_error "Invalid security level: $level. Must be 1, 2, 3, or 4."
        return 1
    fi
    return 0
}

# Function to set security level
set_security_level() {
    local new_level=$1
    local current_level=$(get_current_level)
    
    if ! validate_level "$new_level"; then
        return 1
    fi
    
    if [ "$new_level" = "$current_level" ]; then
        print_warning "Already at security level $new_level"
        return 0
    fi
    
    print_info "Changing security level from $current_level to $new_level"
    
    # Update terraform.tfvars
    if [ -f "terraform.tfvars" ]; then
        sed -i.bak "s/security_level = .*/security_level = $new_level/" terraform.tfvars
    else
        echo "security_level = $new_level" > terraform.tfvars
    fi
    
    print_success "Updated terraform.tfvars with security_level = $new_level"
    
    # Apply changes
    print_info "Applying Terraform changes..."
    if terraform plan -var="security_level=$new_level" -out=tfplan; then
        print_info "Terraform plan created successfully. Review the changes above."
        echo ""
        read -p "Do you want to apply these changes? (y/N): " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if terraform apply tfplan; then
                print_success "Successfully upgraded to security level $new_level"
                rm -f tfplan
                show_current_status
            else
                print_error "Failed to apply Terraform changes"
                return 1
            fi
        else
            print_info "Terraform apply cancelled"
            rm -f tfplan
        fi
    else
        print_error "Failed to create Terraform plan"
        return 1
    fi
}

# Function to show current status
show_current_status() {
    local current_level=$(get_current_level)
    
    echo -e "\n${BLUE}=== Current Environment Status ===${NC}\n"
    echo "Security Level: $current_level"
    
    case $current_level in
        1)
            echo "Status: Baseline (No Protection)"
            echo "Features: Vulnerable application only"
            ;;
        2)
            echo "Status: Basic WAF Protection"
            echo "Features: WAF enabled with managed rules"
            ;;
        3)
            echo "Status: Advanced Protection"
            echo "Features: WAF + Shield Advanced"
            ;;
        4)
            echo "Status: Full Protection"
            echo "Features: CloudFront + WAF + Shield Advanced"
            ;;
    esac
    
    echo ""
    print_info "Getting Terraform outputs..."
    terraform output -json | jq -r '
        "Application URL: " + .application_url.value,
        if .cloudfront_url.value then "CloudFront URL: " + .cloudfront_url.value else "CloudFront: Not enabled" end,
        "Security Features:",
        "  WAF Enabled: " + (.security_features.value.waf_enabled | tostring),
        "  Shield Advanced: " + (.security_features.value.shield_advanced | tostring),
        "  CloudFront: " + (.security_features.value.cloudfront_enabled | tostring),
        "  Rate Limit: " + (.security_features.value.rate_limit | tostring) + " requests/5min per IP"
    '
}

# Function to run security tests
run_security_tests() {
    local current_level=$(get_current_level)
    
    print_info "Running security tests for level $current_level..."
    
    # Get application URL
    local app_url=$(terraform output -raw application_url 2>/dev/null || echo "")
    
    if [ -z "$app_url" ]; then
        print_error "Could not get application URL. Make sure Terraform has been applied."
        return 1
    fi
    
    echo "Testing against: $app_url"
    
    # Basic connectivity test
    print_info "Testing basic connectivity..."
    if curl -s -o /dev/null -w "%{http_code}" "$app_url" | grep -q "200"; then
        print_success "Application is accessible"
    else
        print_warning "Application may not be fully ready"
    fi
    
    # SQL injection test (should be blocked at level 2+)
    print_info "Testing SQL injection protection..."
    local sqli_response=$(curl -s -o /dev/null -w "%{http_code}" "$app_url/login" -d "username=admin' OR '1'='1&password=test" -H "Content-Type: application/x-www-form-urlencoded")
    
    if [ "$current_level" -ge 2 ] && [ "$sqli_response" = "403" ]; then
        print_success "SQL injection blocked by WAF"
    elif [ "$current_level" = 1 ] && [ "$sqli_response" != "403" ]; then
        print_success "SQL injection not blocked (expected for level 1)"
    else
        print_warning "Unexpected SQL injection test result: HTTP $sqli_response"
    fi
    
    # Rate limiting test
    print_info "Testing rate limiting (sending 10 rapid requests)..."
    local blocked_count=0
    for i in {1..10}; do
        local response=$(curl -s -o /dev/null -w "%{http_code}" "$app_url")
        if [ "$response" = "429" ] || [ "$response" = "403" ]; then
            ((blocked_count++))
        fi
        sleep 0.1
    done
    
    if [ "$blocked_count" -gt 0 ]; then
        print_success "Rate limiting is working ($blocked_count requests blocked)"
    else
        print_info "No rate limiting detected (may need more aggressive testing)"
    fi
}

# Main script logic
case "${1:-}" in
    "show"|"list"|"levels")
        show_security_levels
        ;;
    "status"|"current")
        show_current_status
        ;;
    "set"|"level")
        if [ -z "${2:-}" ]; then
            print_error "Please specify a security level (1-4)"
            echo "Usage: $0 set <level>"
            exit 1
        fi
        set_security_level "$2"
        ;;
    "test")
        run_security_tests
        ;;
    "help"|"-h"|"--help")
        echo "AWS GameDay DDoS Environment - Security Level Manager"
        echo ""
        echo "Usage: $0 <command> [options]"
        echo ""
        echo "Commands:"
        echo "  show, list, levels    Show available security levels"
        echo "  status, current       Show current environment status"
        echo "  set <level>          Set security level (1-4)"
        echo "  test                 Run security tests"
        echo "  help                 Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0 show              # Show all security levels"
        echo "  $0 status            # Show current status"
        echo "  $0 set 2             # Upgrade to level 2"
        echo "  $0 test              # Test current security configuration"
        ;;
    *)
        print_error "Unknown command: ${1:-}"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac