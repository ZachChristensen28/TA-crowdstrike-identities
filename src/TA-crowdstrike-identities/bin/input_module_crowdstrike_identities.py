
# encoding = utf-8

from falconpy import IdentityProtection
from crowdstrike_identities_version import *
import json
import datetime
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
    query {
        entities(
        sortKey: PRIMARY_DISPLAY_NAME
        sortOrder: ASCENDING
        first: 1000) {
            nodes {
                primaryDisplayName
                secondaryDisplayName
                riskScore
                riskScoreSeverity
                type
                roles { type }
                isProgrammatic: hasRole(type: ProgrammaticUserAccountRole) ... on UserEntity {
                    emailAddresses
                }
                watched
                accounts { ... on ActiveDirectoryAccountDescriptor {
                    domain
                    samAccountName
                    dn
                    department
                    ou
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

    start_time = datetime.datetime.now()
    response = falcon.api_preempt_proxy_post_graphql(query=idp_query, variables=None)
    status_code = response['status_code']

    if status_code != 200:
        error_msg = response["body"]["errors"]
        event_log = zts_logger(
            msg='Request failed',
            action='failure',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname,
            http_status_code=status_code,
            error_message=json.dumps(error_msg),
            base_url=cloud_env,
            user_agent=user_agent
        )
        helper.log_error(event_log)
        exit(status_code)

    event_log = zts_logger(
        msg='Request succeeded',
        action='success',
        event_type=event_type,
        stanza=stanza,
        hostname=hostname,
        base_url=cloud_env,
        user_agent=user_agent
    )
    helper.log_info(event_log)

    data = response["body"]["data"]["entities"]["nodes"]
    page_info = response["body"]["data"]["entities"]["pageInfo"]

    identity_count = 0
    for account in data:
        identity_count += 1
        splunk_event = helper.new_event(source=helper.get_input_type(), index=helper.get_output_index(
        ), sourcetype=helper.get_sourcetype(), data=json.dumps(account), host=hostname)
        ew.write_event(splunk_event)

    next_page_exists = page_info['hasNextPage']
    page_count = 0
    while next_page_exists:
        page_count += 1
        event_log = zts_logger(
            msg='More pages exist',
            action='success',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname,
            base_url=cloud_env,
            user_agent=user_agent,
            page_count=page_count,
            next_page_exists=next_page_exists,
            current_identity_count=identity_count
        )
        helper.log_info(event_log)

        idp_query = """
        query ($after: Cursor) {
            entities(
            sortKey: PRIMARY_DISPLAY_NAME
            sortOrder: ASCENDING
            first: 1000
            after: $after) {
                nodes {
                    primaryDisplayName
                    secondaryDisplayName
                    riskScore
                    riskScoreSeverity
                    type
                    roles { type }
                    isProgrammatic: hasRole(type: ProgrammaticUserAccountRole) ... on UserEntity {
                        emailAddresses
                    }
                    watched
                    accounts { ... on ActiveDirectoryAccountDescriptor {
                        domain
                        samAccountName
                        dn
                        department
                        ou
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

        variables = {
            "after": page_info["endCursor"]
        }

        response = falcon.api_preempt_proxy_post_graphql(query=idp_query, variables=variables)
        if status_code != 200:
            error_msg = response["body"]["errors"]
            event_log = zts_logger(
                msg='Request failed',
                action='failure',
                event_type=event_type,
                stanza=stanza,
                hostname=hostname,
                http_status_code=status_code,
                error_message=json.dumps(error_msg),
                base_url=cloud_env,
                user_agent=user_agent
            )
            helper.log_error(event_log)
            exit(status_code)

        data = response["body"]["data"]["entities"]["nodes"]
        page_info = response["body"]["data"]["entities"]["pageInfo"]

        event_log = zts_logger(
            msg='Request succeeded',
            action='success',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname,
            base_url=cloud_env,
            user_agent=user_agent
        )
        helper.log_info(event_log)

        for account in data:
            identity_count += 1
            splunk_event = helper.new_event(source=helper.get_input_type(), index=helper.get_output_index(
            ), sourcetype=helper.get_sourcetype(), data=json.dumps(account), host=hostname)
            ew.write_event(splunk_event)
        
        next_page_exists = page_info['hasNextPage']

    end_time = datetime.datetime.now()
    duration = end_time - start_time

    event_log = zts_logger(
        msg='Finished collection',
        action='success',
        event_type=event_type,
        stanza=stanza,
        hostname=hostname,
        base_url=cloud_env,
        user_agent=user_agent,
        identity_count=identity_count,
        time_taken=duration
    )
    helper.log_info(event_log)
    exit(0)

