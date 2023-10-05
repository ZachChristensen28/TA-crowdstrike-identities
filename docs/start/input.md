---
order: -3
icon: checklist
---

# Create Input

!!!success (optional) Create a new index
**If you do not wish to create a new index, skip to [Create Account](#create-account).**

Splunk stores data in indexes. This add-on may be configured to send to a custom event index instead of the default index, main. For more information and steps to create a new index, see [Splunk Docs: Create events indexes <small>:icon-link-external:</small>](https://docs.splunk.com/Documentation/Splunk/latest/Indexer/Setupmultipleindexes#Create_events_indexes_2){ target="blank" }.

**Purpose for Creating a new index**

The out of the box Splunk configuration stores all data in the default index, main. It is encouraged to create a new index to ensure optimal performance, for setting retention policies, and for providing stricter access controls. For more information about how Splunk indexes work with add-ons, see [Splunk Docs: Add-ons and indexes <small>:icon-link-external:</small>](https://docs.splunk.com/Documentation/AddOns/released/Overview/Add-onsandindexes){ target="blank" }.
!!!

## Create Account

1. From Splunk Web, navigate to this app (CrowdStrike Falcon Identity Protection).
2. Click the "Configuration" tab and then click "Add."
3. Provide a unique name (no spaces) and the [API Credentials](token.md).
4. (optional) Configure proxy.

## Create Input

1. On the "Inputs" tab click "Create New Input."
2. Provide a unique name (no spaces).
3. Enter a time interval in seconds or a valid cron schedule.

    !!!info Note
    Data collection may take a few hours. It is recommended to set an interval to run once per day.

    i.e.

    ```shell
    3 3 * * * *
    ```

    The above will run once per day at 3:03 am.
    !!!

4. Select the index, Cloud Environment, and the Account that was just set up.
