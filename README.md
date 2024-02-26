
Setup issue tracker
====================

- Setup JIRA with
  - an empty project
  - a custom issue type to use for security vulnerabilities
  - custom text fields to receive the CVE ID and if a fix is available
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

  INPUT_TRIVY_RESULTS="trivy-results.json"
  INPUT_MIN_SEVERITY="CRITICAL"
  INPUT_JIRA_PROJECT_KEY="SEC"
  INPUT_JIRA_ISSUETYPE_NAME="Security issue"
  INPUT_JIRA_TEAM_FIELD_ID="customfield_10001"
  INPUT_JIRA_TEAM_FIELD_NAME="Team"
  INPUT_JIRA_TEAM_FIELD_VALUE="12345678-0000-dead-beef-ba9876543210"
  INPUT_JIRA_CVE_ID_FIELD_ID="customfield_10042"
  INPUT_JIRA_CVE_ID_FIELD_NAME="CVE ID"
  INPUT_JIRA_CVE_STATUS_FIELD_ID="customfield_14711"
  INPUT_JIRA_PRIORITY_IDS="1,2,3,4,5"
  ```
  JIRA IDs you have to pick from browser dev-tools 🙈
- Run Trivy on an image of your choice to generate a `trivy-results.json`
  ```shell
  trivy image --format=json --output=trivy-results.json ubuntu:20.04
  ```
- Run:
  ```shell
  node --env-file=.env index.js
  ```
