#!/bin/bash

# Status List Server Kubernetes Deployment Test Script
# This script sets up a local Kubernetes cluster using kind and deploys the status list server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CLUSTER_NAME="status-list-test"
NAMESPACE="statuslist"
HELM_RELEASE_NAME="status-list-server"
KIND_CONFIG="kind-config.yaml"
HELM_CHART_PATH="./helm"
TEST_VALUES="helm/values-local.yaml"
KIND_CMD="./kind"  # Use local kind binary

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

install_kind() {
    log_info "Installing kind..."
    
    # Detect OS and architecture
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    # Download URL for kind binary
    KIND_VERSION="v0.20.0"
    KIND_URL="https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-${OS}-${ARCH}"
    
    log_info "Downloading kind ${KIND_VERSION} for ${OS}/${ARCH}..."
    
    # Download kind binary
    if ! curl -Lo ./kind "${KIND_URL}"; then
        log_error "Failed to download kind from ${KIND_URL}"
        exit 1
    fi
    
    # Make it executable
    chmod +x ./kind
    
    log_info "kind installed successfully"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if local kind binary is available
    if [ -x "./kind" ]; then
        KIND_CMD="./kind"
        log_info "Using local kind binary: $KIND_CMD"
    elif command -v kind &> /dev/null; then
        KIND_CMD="kind"
        log_info "Using system kind binary: $KIND_CMD"
    else
        log_warn "kind is not available. Attempting to install it automatically..."
        install_kind
        KIND_CMD="./kind"
        log_info "Using newly installed kind binary: $KIND_CMD"
    fi
    
    # Check if helm is available
    if ! command -v helm &> /dev/null; then
        log_error "helm is not available. Please install helm"
        log_error "Installation: https://helm.sh/docs/intro/install/"
        exit 1
    fi
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not available. Please install kubectl"
        log_error "Installation: https://kubernetes.io/docs/tasks/tools/"
        exit 1
    fi
    
    # Check if curl is available for testing
    if ! command -v curl &> /dev/null; then
        log_warn "curl is not available. Testing functionality will be limited"
    fi
    
    log_info "All prerequisites satisfied"
}

create_kind_config() {
    log_info "Creating kind cluster configuration..."
    
    cat > ${KIND_CONFIG} <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
EOF
}

create_cluster() {
    log_info "Creating kind cluster: ${CLUSTER_NAME}"
    
    # Delete existing cluster if it exists
    ${KIND_CMD} delete cluster --name ${CLUSTER_NAME} 2>/dev/null || true
    
    # Create new cluster
    ${KIND_CMD} create cluster --name ${CLUSTER_NAME} --config ${KIND_CONFIG}
    
    # Set kubectl context
    ${KIND_CMD} export kubeconfig --name ${CLUSTER_NAME}
    
    log_info "Cluster created successfully"
}

deploy_dependencies() {
    log_info "Deploying dependencies..."
    
    # Create namespace
    kubectl create namespace ${NAMESPACE} 2>/dev/null || true
    
    # Add Helm repositories
    log_info "Adding Helm repositories..."
    helm repo add dandydeveloper https://dandydeveloper.github.io/charts 2>/dev/null || true
    helm repo add bitnami https://charts.bitnami.com/bitnami 2>/dev/null || true
    helm repo update
    
    log_info "Dependencies ready"
}

create_secrets() {
    log_info "Creating required Kubernetes secrets..."
    
    # Create database and redis secrets
    kubectl create secret generic statuslist-secret \
        --from-literal=postgres-password=postgres \
        --from-literal=redis-password=password \
        --namespace=${NAMESPACE} \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Create dummy AWS credentials secret (not used in local deployment but required by deployment)
    kubectl create secret generic aws-credentials-secret \
        --from-literal=credentials="[default]\naws_access_key_id=dummy\naws_secret_access_key=dummy" \
        --namespace=${NAMESPACE} \
        --dry-run=client -o yaml | kubectl apply -f -
    
    log_info "Secrets created successfully"
}

deploy_status_list_server() {
    log_info "Deploying status list server..."
    
    # Validate Helm chart path exists
    if [ ! -d "${HELM_CHART_PATH}" ]; then
        log_error "Helm chart path does not exist: ${HELM_CHART_PATH}"
        exit 1
    fi
    
    # Validate values file exists
    if [ ! -f "${TEST_VALUES}" ]; then
        log_error "Values file does not exist: ${TEST_VALUES}"
        exit 1
    fi
    
    # Build Helm dependencies
    log_info "Building Helm dependencies..."
    cd ${HELM_CHART_PATH}
    if ! helm dependency update; then
        log_error "Failed to build Helm dependencies"
        cd - > /dev/null
        exit 1
    fi
    cd - > /dev/null
    
    # Uninstall existing release if it exists
    helm uninstall ${HELM_RELEASE_NAME} -n ${NAMESPACE} 2>/dev/null || true
    sleep 5
    
    # Install the Helm chart
    log_info "Installing Helm chart..."
    if ! helm install ${HELM_RELEASE_NAME} ${HELM_CHART_PATH} \
        --namespace ${NAMESPACE} \
        --values ${TEST_VALUES} \
        --wait \
        --timeout 10m; then
        log_error "Helm installation failed"
        log_info "Checking Helm release status..."
        helm status ${HELM_RELEASE_NAME} -n ${NAMESPACE} || true
        log_info "Checking pod logs..."
        kubectl logs -n ${NAMESPACE} -l app.kubernetes.io/name=status-list-server --tail=50 || true
        exit 1
    fi
    
    log_info "Status list server deployed successfully"
}

get_service_name() {
    # Get the actual service name from the cluster
    local service_name=$(kubectl get svc -n ${NAMESPACE} -l app.kubernetes.io/name=status-list-server -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -z "$service_name" ]; then
        # Fallback to constructed name based on Helm chart templates
        service_name="${HELM_RELEASE_NAME}-status-list-server-chart-service"
    fi
    
    echo "$service_name"
}

get_deployment_name() {
    # Get the actual deployment name from the cluster
    local deployment_name=$(kubectl get deployment -n ${NAMESPACE} -l app.kubernetes.io/name=status-list-server -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -z "$deployment_name" ]; then
        # Fallback to constructed name based on Helm chart templates
        deployment_name="${HELM_RELEASE_NAME}-status-list-server-chart-deployment"
    fi
    
    echo "$deployment_name"
}

wait_for_deployment() {
    log_info "Waiting for deployment to be ready..."
    
    local deployment_name=$(get_deployment_name)
    log_info "Waiting for deployment: ${deployment_name}"
    
    # Wait for deployment with better error handling
    if ! kubectl wait --for=condition=available --timeout=300s deployment/${deployment_name} -n ${NAMESPACE} 2>/dev/null; then
        log_error "Deployment failed to become available within timeout"
        log_info "Checking deployment status..."
        kubectl describe deployment/${deployment_name} -n ${NAMESPACE} || true
        log_info "Checking pod logs..."
        kubectl logs -n ${NAMESPACE} -l app.kubernetes.io/name=status-list-server --tail=100 || true
        return 1
    fi
    
    # Wait for pods to be ready
    if ! kubectl wait --for=condition=ready --timeout=300s pod -l app.kubernetes.io/name=status-list-server -n ${NAMESPACE} 2>/dev/null; then
        log_error "Pods failed to become ready within timeout"
        log_info "Checking pod status..."
        kubectl get pods -n ${NAMESPACE} -o wide
        kubectl describe pods -n ${NAMESPACE} -l app.kubernetes.io/name=status-list-server || true
        return 1
    fi
    
    log_info "Deployment is ready"
}

test_deployment() {
    log_info "Testing deployment..."
    
    local service_name=$(get_service_name)
    log_info "Testing service: ${service_name}"
    
    # Get service information
    kubectl get svc -n ${NAMESPACE}
    
    # Get pod information
    kubectl get pods -n ${NAMESPACE}
    
    # Check if service exists
    if ! kubectl get svc ${service_name} -n ${NAMESPACE} &>/dev/null; then
        log_error "Service ${service_name} not found"
        log_info "Available services:"
        kubectl get svc -n ${NAMESPACE}
        return 1
    fi
    
    # Port forward to test the service
    log_info "Setting up port forwarding for testing..."
    
    # Kill any existing port forwards
    pkill -f "kubectl port-forward" 2>/dev/null || true
    sleep 2
    
    # Start port forwarding in background
    kubectl port-forward -n ${NAMESPACE} svc/${service_name} 8081:8081 &
    PORT_FORWARD_PID=$!
    
    # Wait for port forward to be ready
    sleep 5
    
    # Test health endpoint
    log_info "Testing health endpoint..."
    HEALTH_RESPONSE=$(curl -s --max-time 10 http://localhost:8081/health 2>/dev/null || echo "FAILED")
    
    if [ "$HEALTH_RESPONSE" = "OK" ]; then
        log_info "✅ [PASS] Health check passed"
    else
        log_error "❌ [FAIL] Health check failed (response: $HEALTH_RESPONSE)"
        kill ${PORT_FORWARD_PID} 2>/dev/null || true
        return 1
    fi
    
    # Test root endpoint
    log_info "Testing root endpoint..."
    ROOT_RESPONSE=$(curl -s --max-time 10 http://localhost:8081/ 2>/dev/null || echo "FAILED")
    
    if [ "$ROOT_RESPONSE" != "FAILED" ]; then
        log_info "✅ [PASS] Root endpoint accessible"
    else
        log_warn "⚠️  [WARN] Root endpoint failed"
    fi
    
    # Test status lists endpoint
    log_info "Testing status lists endpoint..."
    STATUS_LISTS_RESPONSE=$(curl -s --max-time 10 http://localhost:8081/status-lists 2>/dev/null || echo "FAILED")
    
    if [ "$STATUS_LISTS_RESPONSE" != "FAILED" ]; then
        log_info "✅ [PASS] Status lists endpoint accessible"
    else
        log_error "❌ [FAIL] Status lists endpoint failed"
        kill ${PORT_FORWARD_PID} 2>/dev/null || true
        return 1
    fi
    
    # Clean up port forwarding
    kill ${PORT_FORWARD_PID} 2>/dev/null || true
    
    log_info "✅ [SUCCESS] All tests passed!"
}

show_status() {
    log_info "Deployment Status:"
    echo "Namespace: ${NAMESPACE}"
    echo "Cluster: ${CLUSTER_NAME}"
    echo "Helm Release: ${HELM_RELEASE_NAME}"
    echo ""
    
    # Check if namespace exists
    if ! kubectl get namespace ${NAMESPACE} &>/dev/null; then
        log_error "Namespace ${NAMESPACE} does not exist"
        log_info "Run './k8s-deployment-test.sh deploy' to create the deployment"
        return 1
    fi
    
    log_info "Helm Releases:"
    helm list -n ${NAMESPACE} || echo "No Helm releases found"
    echo ""
    
    log_info "Pods:"
    kubectl get pods -n ${NAMESPACE} -o wide || echo "No pods found"
    echo ""
    
    log_info "Services:"
    kubectl get svc -n ${NAMESPACE} || echo "No services found"
    echo ""
    
    log_info "Deployments:"
    kubectl get deployments -n ${NAMESPACE} || echo "No deployments found"
    echo ""
    
    log_info "PersistentVolumeClaims:"
    kubectl get pvc -n ${NAMESPACE} || echo "No PVCs found"
    echo ""
    
    # If resources exist, show how to access
    if kubectl get svc -n ${NAMESPACE} &>/dev/null; then
        local service_name=$(get_service_name)
        if kubectl get svc ${service_name} -n ${NAMESPACE} &>/dev/null; then
            log_info "========================================"
            log_info "Access Instructions"
            log_info "========================================"
            echo "To access the application, run:"
            echo "  kubectl port-forward svc/${service_name} 8081:8081 -n ${NAMESPACE}"
            echo ""
            echo "Then test with:"
            echo "  curl http://localhost:8081/health"
            echo "  curl http://localhost:8081/status-lists"
        fi
    fi
}

cleanup() {
    log_info "Cleaning up..."
    
    # Kill port forwarding
    pkill -f "kubectl port-forward" 2>/dev/null || true
    sleep 2
    
    # Uninstall Helm release
    log_info "Uninstalling Helm release..."
    helm uninstall ${HELM_RELEASE_NAME} -n ${NAMESPACE} 2>/dev/null || true
    
    # Delete namespace
    log_info "Deleting namespace..."
    kubectl delete namespace ${NAMESPACE} --wait=false 2>/dev/null || true
    
    # Delete cluster
    log_info "Deleting kind cluster..."
    ${KIND_CMD} delete cluster --name ${CLUSTER_NAME} 2>/dev/null || true
    
    # Clean up files
    if [ -f "${KIND_CONFIG}" ]; then
        rm -f ${KIND_CONFIG}
    fi
    
    log_info "✅ Cleanup completed"
}

# Main execution
main() {
    case "${1:-deploy}" in
        deploy)
            check_prerequisites
            create_kind_config
            create_cluster
            deploy_dependencies
            create_secrets
            deploy_status_list_server
            wait_for_deployment
            test_deployment
            show_status
            log_info "[SUCCESS] Deployment completed successfully!"
            log_info ""
            log_info "[SUMMARY] Deployment Summary:"
            log_info "[PASS] Kubernetes cluster created with kind"
            log_info "[PASS] PostgreSQL deployed and running"
            log_info "[PASS] Redis deployed and running"
            log_info "[PASS] Status List Server deployed and running"
            log_info "[PASS] Health check endpoint responding"
            log_info "[PASS] API endpoints accessible"
            log_info ""
            log_info "[READY] The Status List Server is ready for use!"
            log_info ""
            log_info "To access the application:"
            log_info "kubectl port-forward svc/status-list-test-status-list-server-local 8081:8081 -n statuslist"
            log_info "Then visit: http://localhost:8081/health"
            ;;
        test)
            test_deployment
            ;;
        status)
            show_status
            ;;
        cleanup)
            cleanup
            ;;
        *)
            echo "Usage: $0 {deploy|test|status|cleanup}"
            echo "  deploy - Full deployment and testing"
            echo "  test   - Test existing deployment"
            echo "  status - Show deployment status"
            echo "  cleanup - Clean up resources"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"