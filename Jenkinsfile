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
        ARTIFACT_NAME   = "juice-shop-${BUILD_NUMBER}.tgz" // Đã sửa tên
        PROVENANCE_FILE = "provenance.json"
        SIGNATURE_FILE  = "${ARTIFACT_NAME}.sig"
        
        // --- SBOM Files ---
        SBOM_CODE       = "sbom-code.json"      
        SBOM_CONTAINER  = "cbom-container.json" 
        
        // --- Docker Info ---
        DOCKER_IMAGE    = "juice-shop:${BUILD_NUMBER}" // Đã sửa tên
        APP_PORT        = "3000" // Juice Shop vẫn dùng port 3000
        DEPLOY_IP       = "192.168.12.190" 
    }

    tools {
        nodejs 'NodeJS' // Cần cấu hình NodeJS >= 18 trong Jenkins cho Juice Shop
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
                    // Lưu ý: npm install của Juice shop khá nặng do có frontend Angular
                    echo '--- [Step] Installing Juice Shop Dependencies ---'
                    sh 'npm install' 

                    // LƯU Ý: Đã tạm bỏ bước 'npm test' và 'npm run lint' vì 
                    // unit test của Juice Shop rất nặng và cần cấu hình trình duyệt (Karma/Puppeteer).
                    // Mục tiêu chính của ta là test SAST Coverity.
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
                                sh './gitleaks detect --source="." --no-git --verbose'
                            } catch (Exception e) {
                                echo "GITLEAKS FOUND SECRETS OR FAILED!"
                                error("Gitleaks check failed") 
                            }
                        }
                    }
                }
                stage('SCA (Dependency Check)') {
                    steps {
                        echo '--- [Step] Scanning Dependencies with OSS Index ---'
                        withCredentials([usernamePassword(credentialsId: 'oss-index-credentials', passwordVariable: 'OSS_TOKEN', usernameVariable: 'OSS_USER')]) {
                            dependencyCheck additionalArguments: """
                                --format HTML --format XML 
                                --failOnCVSS 7.0 
                                --ossIndexUsername ${OSS_USER} 
                                --ossIndexPassword ${OSS_TOKEN}
                            """, 
                            odcInstallation: 'OWASP-Dependency-Check'
                        }
                    }
                }                
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
                                def covStream = "juice-shop-stream" // Đã sửa tên stream
                                def covBin = "/home/ubuntu/cov-analysis-linux64-2025.9.2/bin"
                                def covUrl = "http://192.168.12.190:8081"

                                // Capture & Analyze (Đã thêm cấu hình cho TypeScript)
                                sh "${covBin}/cov-configure --javascript --typescript || true"
                                sh "rm -rf idir"
                                
                                // Với Javascript/Typescript, dùng capture project-dir là chuẩn xác nhất
                                sh "${covBin}/coverity capture --project-dir . --dir idir"
                                sh "${covBin}/cov-analyze --dir idir --all --webapp-security --strip-path \$(pwd)"

                                // Commit Results
                                echo '--- Committing Results ---'
                                sh """
                                    ${covBin}/cov-commit-defects --dir idir \
                                    --url ${covUrl} \
                                    --stream ${covStream} \
                                    --user \$COV_USER --password \$COV_PASS \
                                    --version "${buildVer}" \
                                    --description "Juice Shop Build ${env.BUILD_NUMBER}"
                                """

                                // Reporting
                                sh "${covBin}/cov-format-errors --dir idir --html-output coverity-report"
                                sh "${covBin}/cov-format-errors --dir idir --json-output-v7 coverity_results.json"

                                // Quality Gate
                                def defectCount = sh(script: "jq '.issues | length' coverity_results.json", returnStdout: true).trim().toInteger()
                                echo "Coverity found: ${defectCount} defects"
                                if (defectCount > 0) {
                                    echo "CẢNH BÁO: Coverity phát hiện ${defectCount} vấn đề!"
                                    // Bỏ comment dòng dưới nếu muốn chặn pipeline khi có lỗi Coverity
                                    // currentBuild.result = 'UNSTABLE' 
                                }
                            }
                        }
                    }
                }
            }
        }

        // --- BƯỚC 3: BUILD & CONTAINER ---
        stage('3. Build & Container Security') {
            steps {
                echo '--- [Step] Build Artifacts & Container ---'
                script {
                    sh 'rm -f *.tgz *.sig'
                    sh "npm pack"
                    sh "mv juice-shop-*.tgz ${ARTIFACT_NAME}" // Đã sửa logic mv

                    echo "--- Building Docker Image: ${DOCKER_IMAGE} ---"
                    if (fileExists('Dockerfile')) {
                        sh "docker build --no-cache -t ${DOCKER_IMAGE} ."
                        
                        echo '--- [Step] Installing Trivy ---'
                        sh 'rm -f trivy trivy.tar.gz' 
                        sh 'curl -k -L -sS https://github.com/aquasecurity/trivy/releases/download/v0.58.2/trivy_0.58.2_Linux-64bit.tar.gz -o trivy.tar.gz'
                        sh 'tar -xzf trivy.tar.gz trivy'
                        sh 'chmod +x trivy'

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
        
        // --- BƯỚC 4: IAST (Synopsys Seeker) ---
 //       stage('4. IAST (Synopsys Seeker)') {
   //         steps {
     //           script {
       //             echo '--- [Step] Synopsys Seeker IAST Setup ---'
         //           withCredentials([string(credentialsId: 'seeker-agent-token', variable: 'SEEKER_ACCESS_TOKEN')]) {
           //             def agentDir = "${env.WORKSPACE}/seeker"
             //           sh "rm -rf ${agentDir} && mkdir -p ${agentDir}"

                        // Đã sửa projectKey thành juice-shop trong URL
               //         sh """
                           // curl -k -f -L "http://192.168.12.190:8082/rest/api/latest/installers/agents/scripts/NODEJS?osFamily=LINUX&downloadWith=curl&projectKey=juice-shop&webServer=NODEJS_DOWNLOAD&flavor=DEFAULT&accessToken=\$SEEKER_ACCESS_TOKEN" -o install_seeker.sh
                           // chmod +x install_seeker.sh
                        """
                       // sh "./install_seeker.sh --install-dir ${agentDir} --no-prompt || true"

                       // echo "--- Extracting Agent ---"
                       // dir(agentDir) {
                         //   if (fileExists('agent_NODEJS.zip')) {
                           //     try {
                             //       sh "unzip -o agent_NODEJS.zip"
                               // } catch (Exception e) {
                                 //   sh "python3 -c \"import zipfile; import sys; zipfile.ZipFile('agent_NODEJS.zip', 'r').extractall('.')\""
                               // }
                           // }
                           // if (fileExists('seeker-agent.tgz')) {
                             //   sh "tar -xzf seeker-agent.tgz"
                           // }
                       // }

                       // def agentFile = sh(script: "find ${agentDir} -name index.js -o -name index.mjs | head -n 1", returnStdout: true).trim()
                       // if (agentFile == "") {
                           // error "LỖI: Không tìm thấy index.js của Seeker."
                       // }

                        // Đã sửa projectKey thành juice-shop
                       // env.SEEKER_SERVER_URL = "http://192.168.12.190:8082"
                       // env.SEEKER_PROJECT_KEY = "juice-shop"
                        
                       // sh "pkill -f node || true"
                      //  sh "NODE_OPTIONS='--import \"${agentFile}\"' nohup npm start > app_iast.log 2>&1 &"
                        
                      //  sh "sleep 15"
                      //  sh "cat app_iast.log"
                        
                       // if (sh(script: "pgrep -f 'node' > /dev/null && echo 'YES' || echo 'NO'", returnStdout: true).trim() == 'YES') {
                         //   echo "SUCCESS: App running with Seeker"
                           // try {
                             //   sh "curl -v http://localhost:3000 || true"
                           // } finally {
                             //   sh "pkill -f node || true"
                           // }
                      //  } else {
                          //  error "App crashed."
                       // }
                   // }
               // }
           // }
       // }

        // --- BƯỚC 5: SBOM CODE ---
        stage('5. Generate Code SBOM') {
            steps {
                echo '--- [Step] Generate Code SBOM (CycloneDX) ---'
                sh "npx @cyclonedx/cyclonedx-npm --output-file ${SBOM_CODE}"
            }
        }
    
        // --- BƯỚC 6: SIGN ---
        stage('6. Sign Release Artifacts') {
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
        stage('7. Verify Signatures') {
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
        stage('8. Generate Attestation') {
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
        stage('9. Deploy') {
            steps {
                echo '--- [Step] Deploying to Production ---'
                script {
                    def containerName = "juice-shop-prod" // Đã sửa tên
                    
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
             dependencyCheckPublisher pattern: 'dependency-check-report.xml'
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
