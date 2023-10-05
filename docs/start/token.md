---
order: -1
icon: key
---

# Create API Token

!!!danger [Danger, Will Robinson <small>:icon-link-external:</small>](https://cultural-phenomenons.fandom.com/wiki/Danger,_Will_Robinson){ target="blank" }
Failing to perform the following will cause this add-on to not be able to interact with the CrowdStrike API.
!!!

In CrowdStrike, create a new API token with the following permissions:

API | Permissions
--- | -----------
Identity Protection Entities | :icon-checkbox: **Read & Write**
Identity Protection GraphQL | :icon-checkbox: **Write**

_<small>**reference:** [https://falcon.crowdstrike.com/documentation/184/identity-protection-apis <small>:icon-link-external:</small>](https://falcon.crowdstrike.com/documentation/184/identity-protection-apis){ target="blank" }</small>_

You will need the following when setting up the configuration in Splunk during the next steps:

1. Client ID
2. Secret key
3. Cloud Environment (US Commercial, US Commercial 2, EU Cloud, US GovCloud)
