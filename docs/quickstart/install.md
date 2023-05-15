# Where to Install

For detailed information on where to install Splunk Apps/add-ons, including best practices, can be found at [Splunk Docs: About Installing Splunk add-ons](https://docs.splunk.com/Documentation/AddOns/released/Overview/Wheretoinstall)

## Splunk Cloud Deployments

Install this add-on on your Splunk Cloud instance. For more information see [Splunk Docs: Install apps on your Splunk Cloud Platform deployment](https://docs.splunk.com/Documentation/SplunkCloud/latest/Admin/SelfServiceAppInstall){ target="_blank" }

## Standalone Deployments

Install this add-on to the single instance. For more information see [Splunk Docs: Install add-on in a single-instance Splunk deployment](https://docs.splunk.com/Documentation/AddOns/released/Overview/Singleserverinstall){ target="_blank" }

## Distributed Deployments

Splunk Instance type | Supported | Required | Comments
-------------------- | --------- | -------- | --------
Search Heads | Yes | Yes | Install this add-on to search heads. **Note:** change app visibility to disabled if collecting data on another search head or Heavy Forwarder.
Indexers | No | No | Do not install this add-on to indexers.
Heavy Forwarders | Yes | Conditional | Required, if HFs are used to collect this data source.
Universal Forwarders | No | No | Do not install this add-on Universal Forwarders.

The installation steps for deploying Apps/add-ons in a distributed environment can be found at [Splunk Docs: Install an add-on in a distributed Splunk deployment](https://docs.splunk.com/Documentation/AddOns/released/Overview/Distributedinstall){ target="_blank" }

## Distributed Deployment Compatibility

Distributed deployment feature | Supported | Comments
------------------------------ | --------- | --------
Search Head Clusters | Yes | You can install this add-on to a search head cluster.
Indexer Clusters | No | Do not install this add-on to a indexer cluster.

\* For more information, see Splunk's [documentation](https://docs.splunk.com/Documentation/AddOns/released/Overview/Installingadd-ons) on installing Add-ons.

--8<-- "includes/abbreviations.md"
