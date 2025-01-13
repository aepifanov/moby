#!groovy
dockerhubCred = [
    $class: 'UsernamePasswordMultiBinding',
    usernameVariable: 'REGISTRY_USERNAME',
    passwordVariable: 'REGISTRY_PASSWORD',
    credentialsId: 'core-dockerhub-up',
]

pipeline {
    agent none

    options {
        buildDiscarder(logRotator(daysToKeepStr: '30'))
        timeout(time: 2, unit: 'HOURS')
        timestamps()
    }
    parameters {
        booleanParam(name: 'arm64', defaultValue: true, description: 'ARM (arm64) Build/Test')
        booleanParam(name: 'dco', defaultValue: true, description: 'Run the DCO check')
    }
    environment {
        DOCKER_BUILDKIT     = '1'
        DOCKER_EXPERIMENTAL = '1'
        DOCKER_GRAPHDRIVER  = 'overlay2'
        CHECK_CONFIG_COMMIT = '33a3680e08d1007e72c3b3f1454f823d8e9948ee'
        TESTDEBUG           = '0'
        TIMEOUT             = '120m'
        SSH_AGENT_ARGS      = 'echo -n "-v \$(dirname \$SSH_AUTH_SOCK):/opt\$(dirname \$SSH_AUTH_SOCK) -v \$WORKSPACE/known_hosts-github.com:/etc/ssh/ssh_known_hosts:ro -e SSH_AUTH_SOCK=/opt\$SSH_AUTH_SOCK"'
    }
    stages {
        stage('pr-hack') {
            when { changeRequest() }
            steps {
                script {
                    echo "Workaround for PR auto-cancel feature. Borrowed from https://issues.jenkins-ci.org/browse/JENKINS-43353"
                    def buildNumber = env.BUILD_NUMBER as int
                    if (buildNumber > 1) milestone(buildNumber - 1)
                    milestone(buildNumber)
                }
            }
        }
        stage('DCO-check') {
            when {
                beforeAgent true
                expression { false }
            }
            agent { label 'arm64 && ubuntu-2004' }
            steps {
                sshagent(['core-github-ssh-key']) {
                sh '''
                docker run --rm \
                  -v "$WORKSPACE:/workspace" \
                  \$(eval "$SSH_AGENT_ARGS") \
                  -e VALIDATE_REPO=${GIT_URL} \
                  -e VALIDATE_BRANCH=${CHANGE_TARGET} \
                  alpine sh -c 'apk add --no-cache -q bash git openssh-client && git config --system --add safe.directory /workspace && cd /workspace && hack/validate/dco'
                '''
                }
            }
        }
        stage('Build') {
            parallel {
                stage('arm64') {
                    when {
                        beforeAgent true
                        expression { params.arm64 }
                    }
                    agent { label 'arm64 && linux && ec2' }
                    environment {
                        TEST_SKIP_INTEGRATION_CLI = '1'
                    }

                    stages {
                        stage("Load kernel modules") {
                            steps {
                                sh '''
                                sudo modprobe ip6table_filter
                                sudo modprobe -va br_netfilter
                                sudo systemctl restart docker.service
                                '''
                            }
                        }
                        stage("Print info") {
                            steps {
                                sh 'docker version'
                                sh 'docker info'
                                sh '''
                                echo "check-config.sh version: ${CHECK_CONFIG_COMMIT}"
                                curl -fsSL -o ${WORKSPACE}/check-config.sh "https://raw.githubusercontent.com/moby/moby/${CHECK_CONFIG_COMMIT}/contrib/check-config.sh" \
                                && bash ${WORKSPACE}/check-config.sh || true
                                '''
                            }
                        }
                        stage("Build dev image") {
                            steps {
                              withCredentials([dockerhubCred]) {
                                  sh '''
                                    docker login --username "${REGISTRY_USERNAME}" --password "${REGISTRY_PASSWORD}"
                                    docker build --force-rm --build-arg APT_MIRROR -t docker:${GIT_COMMIT} .
                                  '''
                              }
                            }
                        }
                        stage("Unit tests") {
                            steps {
                                sh '''
                                docker run --rm -t --privileged \
                                  -v "$WORKSPACE/bundles:/go/src/github.com/docker/docker/bundles" \
                                  --name docker-pr$BUILD_NUMBER \
                                  -e DOCKER_EXPERIMENTAL \
                                  -e DOCKER_GITCOMMIT=${GIT_COMMIT} \
                                  -e DOCKER_GRAPHDRIVER \
                                  -e VALIDATE_REPO=${GIT_URL} \
                                  -e VALIDATE_BRANCH=${CHANGE_TARGET} \
                                  docker:${GIT_COMMIT} \
                                  hack/test/unit
                                '''
                            }
                            post {
                                always {
                                    junit testResults: 'bundles/junit-report*.xml', allowEmptyResults: true
                                }
                            }
                        }
                        stage("Integration tests") {
                            environment { TEST_SKIP_INTEGRATION_CLI = '1' }
                            steps {
                                sh '''
                                docker run --rm -t --privileged \
                                  -v "$WORKSPACE/bundles:/go/src/github.com/docker/docker/bundles" \
                                  --name docker-pr$BUILD_NUMBER \
                                  -e DOCKER_EXPERIMENTAL \
                                  -e DOCKER_GITCOMMIT=${GIT_COMMIT} \
                                  -e DOCKER_GRAPHDRIVER \
                                  -e TESTDEBUG \
                                  -e TEST_INTEGRATION_USE_SNAPSHOTTER \
                                  -e TEST_SKIP_INTEGRATION_CLI \
                                  -e TIMEOUT \
                                  -e VALIDATE_REPO=${GIT_URL} \
                                  -e VALIDATE_BRANCH=${CHANGE_TARGET} \
                                  docker:${GIT_COMMIT} \
                                  hack/make.sh \
                                    dynbinary \
                                    test-integration
                                '''
                            }
                            post {
                                always {
                                    junit testResults: 'bundles/**/*-report.xml', allowEmptyResults: true
                                }
                            }
                        }
                    }

                    post {
                        always {
                            sh '''
                            echo "Ensuring container killed."
                            docker rm -vf docker-pr$BUILD_NUMBER || true
                            '''

                            sh '''
                            echo "Chowning /workspace to jenkins user"
                            docker run --rm -v "$WORKSPACE:/workspace" busybox chown -R "$(id -u):$(id -g)" /workspace
                            '''

                            catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE', message: 'Failed to create bundles.tar.gz') {
                                sh '''
                                bundleName=arm64-integration
                                echo "Creating ${bundleName}-bundles.tar.gz"
                                # exclude overlay2 directories
                                find bundles -path '*/root/*overlay2' -prune -o -type f \\( -name '*-report.json' -o -name '*.log' -o -name '*.prof' -o -name '*-report.xml' \\) -print | xargs tar -czf ${bundleName}-bundles.tar.gz
                                '''

                                archiveArtifacts artifacts: '*-bundles.tar.gz', allowEmptyArchive: true
                            }
                        }
                        cleanup {
                            sh 'make clean'
                            deleteDir()
                        }
                    }
                }
            }
        }
    }
}
