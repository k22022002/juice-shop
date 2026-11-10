pipeline {
    agent any

    environment {
        CYPRESS_INSTALL_BINARY = '0'
        ARTIFACT_NAME          = "juice-shop-${BUILD_NUMBER}.tgz"
        DOCKER_IMAGE           = "juice-shop:${BUILD_NUMBER}"
        APP_PORT               = "3000"
        DEPLOY_IP              = "192.168.12.190"

        // --- CẤU HÌNH BLACK DUCK ON-PREMISE (SCA) ---
        BLACKDUCK_URL          = 'https://192.168.12.204'
        BLACKDUCK_PROJECT_NAME = 'juice-shop-project'
        BLACKDUCK_VERSION_NAME = 'main'

        // --- CẤU HÌNH COVERITY (SAST) ---
        COV_BIN                = "/home/ubuntu/cov-analysis-linux64-2026.9.0/bin"
        COV_URL                = "http://192.168.12.190:8081"
        COV_STREAM             = "juice-shop-stream"
    }

    tools {
        nodejs 'NodeJS'
    }

    stages {
        stage('1. Initialize & Install') {
            steps {
                echo '--- [Step] Checkout & Install ---'
                cleanWs()
                git branch: 'main', url: 'https://github.com/k22022002/juice-shop.git'
                script {
                    echo '--- [Step] Installing Dependencies ---'
                    sh 'CYPRESS_INSTALL_BINARY=0 npm install --ignore-scripts'
                }
            }
        }

        stage('2. Security Scans') {
            parallel {
                // Nhánh 1: Quét SCA qua Black Duck On-Premise
                stage('Black Duck On-Prem SCA') {
                    steps {
                        echo '--- [Step] Black Duck On-Prem SCA Scan ---'
                        timeout(time: 30, unit: 'MINUTES') {
                            // Cập nhật đúng ID credential: blackduck-sca-token
                            withCredentials([string(credentialsId: 'blackduck-sca-token', variable: 'BLACKDUCK_TOKEN')]) {
                                script {
                                    sh """
                                        curl -s -L -o detect9.sh https://detect.synopsys.com/detect9.sh
                                        bash detect9.sh \
                                            --blackduck.url="${BLACKDUCK_URL}" \
                                            --blackduck.api.token="\${BLACKDUCK_TOKEN}" \
                                            --blackduck.trust.cert=true \
                                            --detect.project.name="${BLACKDUCK_PROJECT_NAME}" \
                                            --detect.project.version.name="${BLACKDUCK_VERSION_NAME}" \
                                            --detect.detector.search.depth=3 \
                                            --detect.npm.include.dev.dependencies=false \
                                            --detect.blackduck.scan.mode=INTELLIGENT \
                                            --detect.wait.for.results=true
                                    """
                                }
                            }
                        }
                    }
                }

                // Nhánh 2: Quét SAST trên Coverity Local CLI & Server
                stage('Coverity SAST') {
                    steps {
                        withCredentials([file(credentialsId: 'coverity-credentials', variable: 'COV_AUTH_KEY')]) {
                            script {
                                echo '--- [Step] Coverity SAST Scan ---'
                                def buildVer = "1.0.${env.BUILD_NUMBER}"

                                sh "${COV_BIN}/cov-configure --javascript --typescript || true"
                                sh "rm -rf idir"
                                
                                sh "${COV_BIN}/coverity capture --project-dir . --dir idir"
                                sh "${COV_BIN}/cov-analyze --dir idir --all --webapp-security --strip-path \$(pwd)"

                                sh """
                                    ${COV_BIN}/cov-commit-defects --dir idir \
                                    --url ${COV_URL} \
                                    --stream ${COV_STREAM} \
                                    --auth-key-file "\$COV_AUTH_KEY" \
                                    --version "${buildVer}" \
                                    --description "Juice Shop Build ${env.BUILD_NUMBER}"
                                """

                                sh "${COV_BIN}/cov-format-errors --dir idir --html-output coverity-report || true"
                                sh "${COV_BIN}/cov-format-errors --dir idir --json-output-v7 coverity_results.json || true"

                                if (fileExists('coverity_results.json')) {
                                    def defectCount = sh(script: "jq '.issues | length' coverity_results.json", returnStdout: true).trim()
                                    echo "Coverity found: ${defectCount} defects"
                                }
                            }
                        }
                    }
                }
            }
        }

        stage('3. Build & Package') {
            steps {
                script {
                    // Sửa cú pháp TypeScript của Angular
                    sh "sed -i 's/changes: type SimpleChanges/changes: SimpleChanges/g' frontend/src/app/password-strength/password-strength.component.ts || true"
                    sh "sed -i 's/, SimpleChanges }/, type SimpleChanges }/g' frontend/src/app/password-strength/password-strength.component.ts || true"

                    // Xử lý lỗi SBOM XML: chuyển lệnh sang chỉ sinh JSON (hoặc bỏ qua) để không bị ngắt docker build
                    sh "sed -i 's/RUN npm run sbom/RUN npm run sbom:json || true/g' Dockerfile"

                    sh 'rm -f *.tgz'
                    sh "npm pack"
                    sh "mv juice-shop-*.tgz ${ARTIFACT_NAME}"
                    if (fileExists('Dockerfile')) {
                        sh "docker build --no-cache -t ${DOCKER_IMAGE} ."
                    }
                }
            }
        }

        stage('4. Deploy') {
            steps {
                script {
                    def containerName = "juice-shop-prod"
                    sh "docker rm -f ${containerName} || true"
                    sh "docker run -d --restart unless-stopped --name ${containerName} -p ${APP_PORT}:${APP_PORT} ${DOCKER_IMAGE}"
                    sh "sleep 5"
                    sh "docker ps | grep ${containerName}"
                }
            }
        }
    }

    post {
        always {
             sh "docker rmi ${DOCKER_IMAGE} || true"
             sh "pkill -f node || true"
        }
        success {
            echo "SUCCESS: Pipeline finished. Security scans and deployment completed."
        }
        failure {
            echo "Pipeline failed. Please check security scan or build logs."
        }
    }
}