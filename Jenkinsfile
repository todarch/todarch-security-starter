pipeline {
  agent any

  stages {
    stage('Build') {
      steps {
        sh 'mvn -B -DskipTests clean deploy'
      }
    }
    stage('Test') {
      steps {
        sh 'mvn test'
      }
      post {
        always {
          junit 'target/surefire-reports/*.xml'
        }
      }
    }
    stage('Deploy') {
      when {
        branch 'master'
      }
      steps {
        sh "${env.JENKINS_SCRIPTS}/deploy-artifact.sh"
      }
    }
  }
}
