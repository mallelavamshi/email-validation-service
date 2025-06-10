pipeline {
    agent any
    
    environment {
        DOCKER_IMAGE = 'email-validation-service'
        DOCKER_TAG = "${BUILD_NUMBER}"
        REGISTRY = credentials('docker-registry')
        DEPLOY_HOST = credentials('deploy-host')
        SSH_KEY = credentials('ssh-deploy-key')
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.GIT_COMMIT = sh(
                        script: 'git rev-parse HEAD',
                        returnStdout: true
                    ).trim()
                }
            }
        }
        
        stage('Test') {
            steps {
                script {
                    sh """
                        docker build -f Dockerfile.test -t ${DOCKER_IMAGE}-test:${DOCKER_TAG} .
                        docker run --rm -v \$(pwd)/test-results:/app/test-results ${DOCKER_IMAGE}-test:${DOCKER_TAG}
                    """
                }
            }
            post {
                always {
                    junit 'test-results/junit.xml'
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'test-results/htmlcov',
                        reportFiles: 'index.html',
                        reportName: 'Coverage Report'
                    ])
                }
            }
        }
        
        stage('Code Quality') {
            parallel {
                stage('Lint') {
                    steps {
                        sh """
                            docker run --rm -v \$(pwd):/app python:3.11-slim sh -c "
                                cd /app && 
                                pip install flake8 black mypy && 
                                flake8 . --max-line-length=100 &&
                                black --check . &&
                                mypy . --ignore-missing-imports
                            "
                        """
                    }
                }
                
                stage('Security Scan') {
                    steps {
                        sh """
                            docker run --rm -v \$(pwd):/app python:3.11-slim sh -c "
                                cd /app && 
                                pip install bandit safety && 
                                bandit -r . -x tests/ &&
                                safety check -r requirements.txt
                            "
                        """
                    }
                }
            }
        }
        
        stage('Build') {
            steps {
                script {
                    sh """
                        docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} .
                        docker tag ${DOCKER_IMAGE}:${DOCKER_TAG} ${DOCKER_IMAGE}:latest
                    """
                }
            }
        }
        
        stage('Integration Tests') {
            steps {
                script {
                    sh """
                        docker-compose -f docker-compose.test.yml up -d
                        sleep 30
                        docker-compose -f docker-compose.test.yml exec -T email-validator-test pytest tests/integration/ -v
                        docker-compose -f docker-compose.test.yml down
                    """
                }
            }
        }
        
        stage('Deploy to Staging') {
            when {
                branch 'develop'
            }
            steps {
                script {
                    sh """
                        # Deploy to staging environment
                        docker tag ${DOCKER_IMAGE}:${DOCKER_TAG} ${DOCKER_IMAGE}:staging
                        
                        # SSH to staging server and deploy
                        ssh -i ${SSH_KEY} -o StrictHostKeyChecking=no deploy@\${DEPLOY_HOST} '
                            cd /opt/email-validator-staging &&
                            docker-compose pull &&
                            docker-compose up -d
                        '
                    """
                }
            }
        }
        
        stage('Deploy to Production') {
            when {
                branch 'main'
            }
            steps {
                input message: 'Deploy to Production?', ok: 'Deploy'
                
                script {
                    sh """
                        # Tag for production
                        docker tag ${DOCKER_IMAGE}:${DOCKER_TAG} ${DOCKER_IMAGE}:production
                        
                        # Deploy to production
                        ssh -i ${SSH_KEY} -o StrictHostKeyChecking=no deploy@\${DEPLOY_HOST} '
                            cd /opt/email-validator &&
                            git pull origin main &&
                            docker-compose build &&
                            docker-compose up -d &&
                            
                            # Health check
                            sleep 30 &&
                            curl -f http://localhost/health
                        '
                    """
                }
            }
        }
        
        stage('Post-Deploy Tests') {
            when {
                branch 'main'
            }
            steps {
                script {
                    sh """
                        # Run production smoke tests
                        docker run --rm --network host ${DOCKER_IMAGE}-test:${DOCKER_TAG} \\
                            pytest tests/smoke/ -v --base-url=http://\${DEPLOY_HOST}
                    """
                }
            }
        }
    }
    
    post {
        always {
            sh "docker system prune -f"
        }
        
        success {
            slackSend(
                channel: '#deployments',
                color: 'good',
                message: """
                    ✅ Email Validation Service deployed successfully!
                    Branch: ${env.BRANCH_NAME}
                    Build: ${BUILD_NUMBER}
                    Commit: ${GIT_COMMIT}
                """
            )
        }
        
        failure {
            slackSend(
                channel: '#deployments',
                color: 'danger',
                message: """
                    ❌ Email Validation Service deployment failed!
                    Branch: ${env.BRANCH_NAME}
                    Build: ${BUILD_NUMBER}
                    Check: ${BUILD_URL}
                """
            )
        }
    }
}