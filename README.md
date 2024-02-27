
Setup issue tracker
====================

- Setup JIRA with
  - an empty project
  - a custom issue type to use for security vulnerabilities
  - custom text fields to receive the microservice, the CVE ID and if a fix is available
- Generate an access token to access your JIRA by API

How to develop locally
=======================

- Install Node.js and Trivy
- `cd .github/actions/sync-trivy-to-jira`
- Create a `.env` file like
  ```shell
  JIRA_DOMAIN=your-jira-domain
  JIRA_EMAIL=your-login-email@example.com
  JIRA_TOKEN="secret-token-to-access-jira"

  INPUT_SERVICES="services.json"
  INPUT_MIN_SEVERITY="CRITICAL"
  INPUT_JIRA_PROJECT_KEY="SEC"
  INPUT_JIRA_ISSUETYPE_NAME="Security issue"
  INPUT_JIRA_SERVICE_FIELD_ID="customfield_14712"
  INPUT_JIRA_SERVICE_FIELD_NAME="Microservice"
  INPUT_JIRA_TEAM_FIELD_ID="customfield_10001"
  INPUT_JIRA_CVE_ID_FIELD_ID="customfield_10042"
  INPUT_JIRA_CVE_ID_FIELD_NAME="CVE ID"
  INPUT_JIRA_CVE_STATUS_FIELD_ID="customfield_14711"
  INPUT_JIRA_PRIORITY_IDS="1,2,3,4,5"
  
  DISABLE_HGA_DEBUG=true
  ```
  JIRA IDs you have to pick from browser dev-tools 🙈
- Create a `services.json` like
  ```json
  {
    "frontend": {
        "image": "python:3.4-alpine",
        "jiraTeamId": "bed416e0-bfc5-4e46-8f5c-e7578395c366"
    },
    "backend-login": {
        "image": "ubuntu:20.04",
        "jiraTeamId": "329b0dcd-8583-40c4-96f0-fcd763d9eca8"
    },
    "backend-shop": {
        "image": "php:7.2.3-alpine3.6",
        "jiraTeamId": "329b0dcd-8583-40c4-96f0-fcd763d9eca8"
    },
    "monitoring": {
        "image": "httpd:2.4.58",
        "jiraTeamId": "588e4ad4-a0c6-4985-8b2b-6e643f93a503"
    }
  }
  ```
- Run:
  ```shell
  node --env-file=.env index.js
  ```
