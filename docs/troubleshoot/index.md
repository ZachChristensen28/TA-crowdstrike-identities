---
order: -4
label: Troubleshooting
icon: question
---

# Modular Input

If no logs appear in the index you specified after configuring the input, use the following to troubleshoot.

1. Set the logging mode to "Debug" on the Configuration Tab.
2. Search the internal logs with the following search:

    ``` shell
    index=_internal sourcetype="tacrowdstrikeidentities:log"
    ```