
# encoding = utf-8

from falconpy import IdentityProtection
from crowdstrike_identities_version import *
import json
from time import time
from datetime import datetime
from zts_helper import *


def validate_input(helper, definition):
    pass


def collect_events(helper, ew):
    log_level = helper.get_log_level()
    helper.set_log_level(log_level)
    helper.log_info(f'log_level="{log_level}"')

    api_credentials = helper.get_arg('api_credentials')
    api_clientid = api_credentials['username']
    api_secret = api_credentials['password']
    cloud_env = helper.get_arg('cloud_environment')
    user_agent = f'zTsSplunkTAFalconIdentities/{APP_VERSION}'
    stanza = str(helper.get_input_stanza_names())
    hostname = f'crowdstrike/{cloud_env}'

    proxy = helper.get_proxy()
    event_type = 'proxy_config'
    if proxy:
        if proxy["proxy_username"]:
            event_log = zts_logger(
                msg='Proxy is configured with authentication',
                action='success',
                event_type=event_type,
                stanza=stanza,
                hostname=hostname
            )
            helper.log_info(event_log)
            proxy_string = f'{proxy["proxy_type"]}://{proxy["proxy_username"]}:{proxy["proxy_password"]}@{proxy["proxy_url"]}:{proxy["proxy_port"]}'
        else:
            event_log = zts_logger(
                msg='Proxy is configured with no authentication',
                action='success',
                event_type=event_type,
                stanza=stanza,
                hostname=hostname
            )
            helper.log_info(event_log)
            proxy_string = f'{proxy["proxy_type"]}://{proxy["proxy_url"]}:{proxy["proxy_port"]}'

        proxy_config = {'http': proxy_string, 'https': proxy_string}
    else:
        event_log = zts_logger(
            msg='Proxy is not configured',
            action='success',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname
        )
        helper.log_info(event_log)
        proxy_config = None

    event_type = "checkpointer"
    get_after_time = None
    if helper.get_check_point(stanza):
        get_after_time = helper.get_check_point(stanza)
        event_log = zts_logger(
            msg='Checkpoint found',
            action='success',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname,
            checkpoint_value=helper.get_check_point(stanza)
        )
        helper.log_info(event_log)
    else:
        event_log = zts_logger(
            msg='Checkpoint not found',
            action='none',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname
        )
        helper.log_info(event_log)

    event_type = 'api_call'
    event_log = zts_logger(
        msg='Sending request',
        action='started',
        event_type=event_type,
        stanza=stanza,
        hostname=hostname,
        base_url=cloud_env,
        user_agent=user_agent
    )
    helper.log_info(event_log)
    falcon = IdentityProtection(client_id=api_clientid,
                                client_secret=api_secret,
                                base_url=cloud_env,
                                user_agent=user_agent,
                                ssl_verify=True,
                                proxy=proxy_config
                                )

    idp_query = """
    query ($after: Cursor) {
        entities(
            types: [USER]
            archived: false
            learned: false
            first: 10
            after: $after
        ) {
            nodes {
                entityId
                learned
                accounts
                archived
                associations
                primaryDisplayName
                secondaryDisplayName
                type
                watched
                isHuman: hasRole(type: HumanUserAccountRole)
                riskScore
                riskScoreSeverity
                riskFactors {
                    type
                    severity
                }
                roles { 
                    type
                    fullPath
                    probability
                }
                isProgrammatic: hasRole(type: ProgrammaticUserAccountRole) ... on UserEntity {
                    emailAddresses
                }
                accounts { 
                    description
                    ... on ActiveDirectoryAccountDescriptor {
                        passwordAttributes {
                            lastChange
                        }
                        creationTime
                        objectSid
                        samAccountName
                        domain
                        enabled
                        dn
                        department
                        ou
                        servicePrincipalNames
                        upn
                        title
                        userAccountControl
                        objectGuid
                    }
                }
            }
            pageInfo {
                hasNextPage
                endCursor
            }
        }
    }
    """

    get_data = True
    returned_identities = []
    query_vars = {}
    page_count = 0
    start_time = time()
    while get_data:
        page_count += 1
        response = falcon.graphql(query=idp_query, variables=query_vars)

        if response["status_code"] != 200:
            error_msg = response["body"]["errors"]
            event_log = zts_logger(
                msg='Request failed',
                action='failure',
                event_type=event_type,
                stanza=stanza,
                hostname=hostname,
                http_status_code=response["status_code"],
                error_message=json.dumps(error_msg),
                base_url=cloud_env,
                user_agent=user_agent
            )
            helper.log_error(event_log)
            raise SystemExit(response["status_code"])

        if response["body"]["data"].get("entities"):
            if "nodes" in response["body"]["data"]["entities"]:
                returned_identities.extend(response["body"]["data"]["entities"]["nodes"])
                page_info = response["body"]["data"]["entities"]["pageInfo"]
                if page_info["hasNextPage"]:
                    query_vars["after"] = page_info["endCursor"]
                else:
                    get_data = False
            else:
                get_data = False
        else:
            event_log = zts_logger(
                msg="No data returned.",
                action="none",
                event_type=event_type,
                stanza=stanza,
                hostname=hostname
            )
            helper.log_info(event_log)
            raise SystemExit()

    collection_end_time = f'{datetime.utcnow().isoformat(timespec="milliseconds")}Z'
    event_log = zts_logger(
        msg='Finished collection',
        action='success',
        event_type=event_type,
        stanza=stanza,
        hostname=hostname,
        base_url=cloud_env,
        user_agent=user_agent,
        time_taken_sec=time() - start_time
    )
    helper.log_info(event_log)

    event_type = "event indexing"
    event_log = zts_logger(
        msg="Indexing events",
        action="started",
        event_type=event_type,
        stanza=stanza,
        hostname=hostname
    )
    helper.log_info(event_log)

    identity_count = 0
    for identity in returned_identities:
        identity_count += 1
        splunk_event = helper.new_event(source=helper.get_input_type(), index=helper.get_output_index(
        ), sourcetype=helper.get_sourcetype(), data=json.dumps(identity), host=hostname)
        ew.write_event(splunk_event)

    event_log = zts_logger(
        msg="Finished Indexing",
        action='success',
        event_type=event_type,
        stanza=stanza,
        hostname=hostname,
        identity_count=identity_count
    )
    helper.log_info(event_log)

    helper.save_check_point(stanza, collection_end_time)
    raise SystemExit()

