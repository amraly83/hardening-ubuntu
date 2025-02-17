#!/bin/bash
# Docker test environment for security hardening validation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="/tmp/hardening-tests"
DOCKER_IMAGE="ubuntu:22.04"

setup_test_env() {
    log "INFO" "Setting up test environment..."
    
    # Create test directory
    mkdir -p "$TEST_DIR"/{scripts,config,results}
    
    # Create Docker test environment
    cat > "$TEST_DIR/Dockerfile" << 'EOF'
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    fail2ban \
    ufw \
    git \
    curl \
    jq \
    bc \
    netcat \
    systemctl \
    libpam-google-authenticator \
    && rm -rf /var/lib/apt/lists/*

# Setup initial SSH configuration
RUN mkdir /run/sshd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Create test user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:testpass" | chpasswd && \
    usermod -aG sudo testuser

WORKDIR /hardening
COPY scripts/ /hardening/scripts/
COPY config/ /hardening/config/

CMD ["/usr/sbin/sshd", "-D"]
EOF

    # Copy scripts to test environment
    cp -r "${SCRIPT_DIR}/../scripts" "$TEST_DIR/scripts/"
    cp -r "${SCRIPT_DIR}/../examples/config" "$TEST_DIR/config/"
    
    # Build test container
    docker build -t hardening-test "$TEST_DIR"
}

run_test_suite() {
    local container_id
    
    # Start test container
    container_id=$(docker run -d --privileged hardening-test)
    
    # Wait for container to be ready
    sleep 5
    
    log "INFO" "Running test suite in container: $container_id"
    
    # Run tests in sequence
    run_unit_tests "$container_id"
    run_integration_tests "$container_id"
    run_security_tests "$container_id"
    run_stress_tests "$container_id"
    
    # Generate test report
    generate_test_report "$container_id"
    
    # Cleanup
    docker stop "$container_id"
    docker rm "$container_id"
}

run_unit_tests() {
    local container_id="$1"
    
    log "INFO" "Running unit tests..."
    
    # Test individual components
    docker exec "$container_id" bash -c '
        cd /hardening/scripts
        ./test_user_handling.sh
        ./test-2fa.sh
        ./verify-sudo.sh testuser
        ./verify-network.sh
    '
}

run_integration_tests() {
    local container_id="$1"
    
    log "INFO" "Running integration tests..."
    
    # Test complete hardening process
    docker exec "$container_id" bash -c '
        cd /hardening/scripts
        ./test-integration.sh --ci
    '
}

run_security_tests() {
    local container_id="$1"
    
    log "INFO" "Running security tests..."
    
    # Test security configurations
    docker exec "$container_id" bash -c '
        cd /hardening/scripts
        ./verify-deployment.sh testuser
        ./verify-complete.sh testuser
    '
}

run_stress_tests() {
    local container_id="$1"
    
    log "INFO" "Running stress tests..."
    
    # Simulate concurrent access and recovery scenarios
    docker exec "$container_id" bash -c '
        cd /hardening/scripts
        
        # Multiple concurrent SSH connections
        for i in {1..10}; do
            ssh -o StrictHostKeyChecking=no testuser@localhost "echo test" &
        done
        
        # Rapid sudo commands
        for i in {1..20}; do
            sudo -u testuser sudo echo "test" &
        done
        
        # Simulate recovery during load
        ./emergency-recovery.sh all testuser
        
        wait
    '
}

generate_test_report() {
    local container_id="$1"
    local report_file="$TEST_DIR/results/test-report.html"
    
    log "INFO" "Generating test report..."
    
    # Collect test results
    docker exec "$container_id" bash -c '
        cd /hardening
        {
            echo "<html><body>"
            echo "<h1>Security Hardening Test Report</h1>"
            echo "<h2>System Information</h2>"
            echo "<pre>"
            uname -a
            echo "</pre>"
            
            echo "<h2>Test Results</h2>"
            echo "<h3>Unit Tests</h3>"
            cat scripts/test-results.log 2>/dev/null || echo "No unit test results"
            
            echo "<h3>Integration Tests</h3>"
            cat scripts/integration-results.log 2>/dev/null || echo "No integration test results"
            
            echo "<h3>Security Tests</h3>"
            cat scripts/security-results.log 2>/dev/null || echo "No security test results"
            
            echo "<h2>System Status</h2>"
            echo "<pre>"
            systemctl status sshd fail2ban ufw
            echo "</pre>"
            
            echo "<h2>Security Configuration</h2>"
            echo "<pre>"
            cat /etc/ssh/sshd_config
            echo "</pre>"
            
            echo "</body></html>"
        }
    ' > "$report_file"
    
    log "SUCCESS" "Test report generated: $report_file"
}

cleanup_test_env() {
    log "INFO" "Cleaning up test environment..."
    
    # Stop and remove any running test containers
    docker ps -q --filter "ancestor=hardening-test" | xargs -r docker stop
    docker ps -aq --filter "ancestor=hardening-test" | xargs -r docker rm
    
    # Remove test image
    docker rmi hardening-test 2>/dev/null || true
    
    # Cleanup test directory
    rm -rf "$TEST_DIR"
}

# Main execution
case "${1:-}" in
    "setup")
        setup_test_env
        ;;
    "run")
        run_test_suite
        ;;
    "cleanup")
        cleanup_test_env
        ;;
    *)
        echo "Usage: $0 <setup|run|cleanup>"
        echo "Examples:"
        echo "  $0 setup    # Setup test environment"
        echo "  $0 run      # Run test suite"
        echo "  $0 cleanup  # Cleanup test environment"
        exit 1
        ;;
esac