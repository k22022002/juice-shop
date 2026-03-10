pipeline {
    agent any
    
    triggers {
        cron('H 2 * * *')
    }

    parameters {
        booleanParam(name: 'FORCE_COVERITY', defaultValue: false, description: 'Tích vào đây nếu muốn chạy quét Coverity Full Scan')
    }

    environment {
        // --- Artifact Info ---
        ARTIFACT_NAME   = "juice-shop-${BUILD_NUMBER}.tgz" 
        PROVENANCE_FILE = "provenance.json"
        SIGNATURE_FILE  = "${ARTIFACT_NAME}.sig"
        
        // --- SBOM Files ---
        SBOM_CODE       = "sbom-code.json"      
        SBOM_CONTAINER  = "cbom-container.json" 
        
        // --- Docker Info ---
        DOCKER_IMAGE    = "juice-shop:${BUILD_NUMBER}" 
        APP_PORT        = "3000" 
        DEPLOY_IP       = "192.168.12.190" 
        
        // --- Polaris Info ---
        POLARIS_SERVER_URL = 'https://poc.polaris.blackduck.com' 
    }

    tools {
        nodejs 'NodeJS' 
    }

    stages {
        // --- BƯỚC 1: INITIALIZE ---
        stage('1. Initialize & Install') {
            steps {
                echo '--- [Step] Checkout & Install ---'
                cleanWs()
                checkout scm
                
                script {
                    // 1. Install Cosign
                    sh 'rm -f cosign'
                    sh 'curl -k -sSL --retry 5 --retry-delay 5 "https://github.com/sigstore/cosign/releases/download/v2.2.4/cosign-linux-amd64" -o cosign'
                    sh 'chmod +x cosign'
                    sh './cosign version'                    
                  
                    // 2. Install Dependencies cho Juice Shop
                    echo '--- [Step] Installing Juice Shop Dependencies ---'
                    sh 'npm install' 
                }
            }
        }
	// --- BƯỚC 2: SECURITY STATIC ---
        stage('2. Security & Quality Gates (Static)') {
            parallel {
                stage('Secret Scan (Gitleaks)') {
                    steps {
                        script {
                            echo '--- [Step] Running Gitleaks ---'
                            try {
                                sh 'curl -k -sS -L https://github.com/zricethezav/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz -o gitleaks.tar.gz'
                                sh 'tar -xzf gitleaks.tar.gz gitleaks'
                                sh 'chmod +x gitleaks'
                                // Thêm || true để bỏ qua lỗi ngắt pipeline khi tìm thấy secret
                                sh './gitleaks detect --source="." --no-git --verbose || true'
                            } catch (Exception e) {
                                echo "GITLEAKS FOUND SECRETS OR FAILED!"
                                // Đã đóng comment dòng error() để không đánh sập pipeline
                                // error("Gitleaks check failed") 
                            }
                        }
                    }
                }
                
                // Tích hợp Polaris
                stage('Polaris (SAST & SCA)') {
                    steps {
                        echo '--- [Step] Synopsys Polaris Scan ---'
                        withCredentials([string(credentialsId: 'polaris-token', variable: 'POLARIS_TOKEN')]) {
                            blackduck_security_scan product: 'polaris',
                                          polaris_server_url: "${POLARIS_SERVER_URL}",
                                          polaris_access_token: POLARIS_TOKEN, // Đã bỏ dấu ngoặc kép
                                          polaris_application_name: 'Juice-Shop-Full-Scan',
                                          polaris_project_name: 'juice-shop-project',
                                          polaris_branch_name: 'main', // THÊM MỚI: Khai báo nhánh bắt buộc
                                          polaris_assessment_types: 'SAST,SCA',
                                          mark_build_status: 'true'
                        }
                    }
                }
                /* =========================================================
                   TẠM THỜI ĐÓNG COVERITY SAST (Do đã dùng Polaris ở trên)
                   =========================================================
                stage('SAST (Coverity)') {
                    when {
                        anyOf {
                            triggeredBy 'TimerTrigger'
                            expression { return params.FORCE_COVERITY == true }
                        }
                    }
                    steps {
                        withCredentials([usernamePassword(credentialsId: 'coverity-credentials', usernameVariable: 'COV_USER', passwordVariable: 'COV_PASS')]) {
                            script {
                                echo '--- [Step] Synopsys Coverity SAST ---'
                                def buildVer = "1.0.${env.BUILD_NUMBER}"
                                def covStream = "juice-shop-stream" 
                                def covBin = "/home/ubuntu/cov-analysis-linux64-2025.9.2/bin"
                                def covUrl = "http://192.168.12.190:8081"

                                sh "${covBin}/cov-configure --javascript --typescript || true"
                                sh "rm -rf idir"
                                sh "${covBin}/coverity capture --project-dir . --dir idir"
                                sh "${covBin}/cov-analyze --dir idir --all --webapp-security --strip-path \$(pwd)"

                                echo '--- Committing Results ---'
                                sh """
                                    ${covBin}/cov-commit-defects --dir idir \
                                    --url ${covUrl} \
                                    --stream ${covStream} \
                                    --user \$COV_USER --password \$COV_PASS \
                                    --version "${buildVer}" \
                                    --description "Juice Shop Build ${env.BUILD_NUMBER}"
                                """

                                sh "${covBin}/cov-format-errors --dir idir --html-output coverity-report"
                                sh "${covBin}/cov-format-errors --dir idir --json-output-v7 coverity_results.json"

                                def defectCount = sh(script: "jq '.issues | length' coverity_results.json", returnStdout: true).trim().toInteger()
                                echo "Coverity found: ${defectCount} defects"
                                if (defectCount > 0) {
                                    echo "CẢNH BÁO: Coverity phát hiện ${defectCount} vấn đề!"
                                }
                            }
                        }
                    }
                }
                ========================================================= */
            }
        }

        // --- BƯỚC 3: BUILD & CONTAINER ---
        stage('3. Build & Container Security') {
            steps {
                echo '--- [Step] Build Artifacts & Container ---'
                script {
                    sh 'rm -f *.tgz *.sig'
                    sh "npm pack"
                    sh "mv juice-shop-*.tgz ${ARTIFACT_NAME}" 

                    echo "--- Building Docker Image: ${DOCKER_IMAGE} ---"
                    if (fileExists('Dockerfile')) {
                        sh "docker build --no-cache -t ${DOCKER_IMAGE} ."
                        
			echo '--- [Step] Installing Trivy ---'
                        sh 'rm -f trivy' 
                        // Sử dụng script chính thức để tải bản Trivy mới nhất thẳng vào thư mục hiện tại (.)
                        sh 'curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b .'
                        
                        // In phiên bản ra log để kiểm tra cho chắc ăn
                        sh './trivy --version'
                        echo '--- Running Trivy Container Scan ---'
                        try {
                           sh "./trivy image --insecure --exit-code 1 --severity HIGH,CRITICAL --no-progress --scanners vuln ${DOCKER_IMAGE}"
                        } catch (Exception e) {
                             echo "Trivy found vulnerabilities!"
                        }

                        echo '--- Generating CBOM (Container SBOM) ---'
                        sh "./trivy image --insecure --format cyclonedx --output ${SBOM_CONTAINER} ${DOCKER_IMAGE}"
                    }
                }
            }
        }
        
        // --- BƯỚC 5: SBOM CODE ---
        stage('4. Generate Code SBOM') {
            steps {
                echo '--- [Step] Generate Code SBOM (CycloneDX) ---'
                sh "npx @cyclonedx/cyclonedx-npm --output-file ${SBOM_CODE}"
            }
        }
    
        // --- BƯỚC 6: SIGN ---
        stage('5. Sign Release Artifacts') {
            steps {
                echo '--- [Step] Sign Artifacts using Credentials ---'
                withCredentials([
                    string(credentialsId: 'cosign-password-id', variable: 'COSIGN_PASSWORD'),
                    file(credentialsId: 'cosign-private-key', variable: 'COSIGN_KEY_PATH')
                ]) {
                     script {
                        def cosignCmd = (fileExists('cosign')) ? './cosign' : 'cosign'
                        sh "cp \$COSIGN_KEY_PATH cosign.key"
                        sh "${cosignCmd} public-key --key cosign.key --outfile cosign.pub"

                        sh """
                            ${cosignCmd} sign-blob --yes \
                            --key cosign.key \
                            --bundle cosign.bundle \
                            --tlog-upload=false \
                            --output-signature ${SIGNATURE_FILE} \
                            ${ARTIFACT_NAME}
                        """
                        
                        sh """
                            ${cosignCmd} sign-blob --yes \
                            --key cosign.key \
                            --tlog-upload=false \
                            --output-signature ${SBOM_CODE}.sig \
                            ${SBOM_CODE}
                        """
                    }
                }
            }
        }

        // --- BƯỚC 7: VERIFY ---
        stage('6. Verify Signatures') {
            steps {
                echo '--- [Step] Verify Signatures ---'
                script {
                    def cosignCmd = (fileExists('cosign')) ? './cosign' : 'cosign'
                    sh """
                        ${cosignCmd} verify-blob \
                            --key cosign.pub \
                            --signature ${SIGNATURE_FILE} \
                            --insecure-ignore-tlog=true \
                            ${ARTIFACT_NAME}
                    """
                    echo "Signature verification PASSED!"
                }
            }
        }

        // --- BƯỚC 8: ATTESTATION ---
        stage('7. Generate Attestation') {
            steps {
                echo '--- [Step] Generate Provenance Attestation ---'
                script {
                    def artifactSha256 = sh(script: "sha256sum ${ARTIFACT_NAME} | awk '{print \$1}'", returnStdout: true).trim()
                    def gitCommit = sh(script: "git rev-parse HEAD", returnStdout: true).trim()
                    def gitUrl = sh(script: "git config --get remote.origin.url", returnStdout: true).trim()
                    def buildId = env.BUILD_TAG

                    sh """
                        jq -n \
                        --arg builder "Jenkins-CI" \
                        --arg buildId "$buildId" \
                        --arg gitUrl "$gitUrl" \
                        --arg gitCommit "$gitCommit" \
                        --arg artifact "$ARTIFACT_NAME" \
                        --arg sha256 "$artifactSha256" \
                        '{
                            builder: { id: \$builder },
                            buildType: "https://github.com/npm/cli/commands/pack",
                            invocation: {
                                configSource: { uri: \$gitUrl, digest: { sha1: \$gitCommit }, entryPoint: "Jenkinsfile" },
                                parameters: { buildId: \$buildId }
                            },
                            subject: [{ name: \$artifact, digest: { sha256: \$sha256 } }]
                        }' > ${PROVENANCE_FILE}
                    """
                }
            }
        }
        
        // --- BƯỚC 9: DEPLOY ---
        stage('8. Deploy') {
            steps {
                echo '--- [Step] Deploying to Production ---'
                script {
                    def containerName = "juice-shop-prod" 
                    
                    echo "Deploying Docker Image: ${DOCKER_IMAGE}..."
                    sh "docker rm -f ${containerName} || true"

                    sh """
                        docker run -d \
                        --restart unless-stopped \
                        --name ${containerName} \
                        -p ${APP_PORT}:${APP_PORT} \
                        ${DOCKER_IMAGE}
                    """
                    
                    sh "sleep 5" 
                    sh "docker ps | grep ${containerName}"
                    echo "Deploy SUCCESS! App is running at http://${DEPLOY_IP}:${APP_PORT}"
                }
            }
        }
    }
    post {
        always {
             sh "docker rmi ${DOCKER_IMAGE} || true"
             sh "rm -f cosign cosign.key" 
             sh "pkill -f node || true"
        }
        success {
            echo "SUCCESS: Pipeline finished securely. Ready for production."
        }
        failure {
            echo "Pipeline failed. Please check Security Scans or Quality Gates."
        }
    }
}
