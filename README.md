
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
  export JIRA_DOMAIN=your-jira-domain
  export JIRA_EMAIL=your-login-email@example.com
  export JIRA_TOKEN="secret-token-to-access-jira"

  export INPUT_TRIVY_RESULTS="trivy-results.json"
  export INPUT_MIN_SEVERITY="CRITICAL"
  export INPUT_JIRA_PROJECT_KEY="SEC"
  export INPUT_JIRA_ISSUETYPE_NAME="Security issue"
  export INPUT_JIRA_TEAM_FIELD_ID="customfield_10001"
  export INPUT_JIRA_TEAM_FIELD_NAME="Team"
  export INPUT_JIRA_TEAM_FIELD_VALUE="12345678-0000-dead-beef-ba9876543210"
  export INPUT_JIRA_CVE_ID_FIELD_ID="customfield_10042"
  export INPUT_JIRA_CVE_ID_FIELD_NAME="CVE ID"
  export INPUT_JIRA_CVE_STATUS_FIELD_ID="customfield_14711"
  export INPUT_JIRA_PRIORITY_IDS="1,2,3,4,5"
  ```
  JIRA IDs you have to pick from browser dev-tools 🙈
- Run Trivy on an image of your choice to generate a `trivy-results.json`
  ```shell
  trivy image --format=json --output=trivy-results.json ubuntu:20.04
  ```
- Run:
  ```shell
  source .env && node index.js
  ```
