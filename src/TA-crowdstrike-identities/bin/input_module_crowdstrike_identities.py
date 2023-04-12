
# encoding = utf-8

from falconpy import IdentityProtection
from crowdstrike_identities_version import *
import json
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
    user_agent = helper.get_arg('application_id')
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
        msg = 'Sending request',
        action = 'started',
        event_type = event_type,
        stanza=stanza,
        hostname = hostname,
        base_url=cloud_env,
        user_agent=f'{user_agent}/{APP_VERSION}'
    )
    helper.log_info(event_log)
    falcon = IdentityProtection(client_id=api_clientid,
                                client_secret=api_secret,
                                base_url=cloud_env,
                                user_agent=f'{user_agent}/{APP_VERSION}',
                                ssl_verify=True,
                                proxy=proxy_config
                                )

    idp_query = """
    query ($after: Cursor) {
    entities(types: [USER], archived: false, learned: false, first: 5, after: $after) {
        nodes {
        primaryDisplayName
        secondaryDisplayName
        accounts {
            ... on ActiveDirectoryAccountDescriptor {
            domain
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
        "string": "string, int, float"
    }

    response = falcon.api_preempt_proxy_post_graphql(query=idp_query, variables=variables)
    
    splunk_event = helper.new_event(source=helper.get_input_type(), index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(response), host=hostname)
    
    ew.write_event(splunk_event)
