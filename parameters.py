
import os
import logging

""" Configurable parameters """
# if os.getenv("KEYCLOAK_SERVER") is None and os.getenv("KEYCOLAK_REALM") is None:
#     raise Exception("Values for Keycloak server and realm isn't avalable")

keycloak_server = os.getenv("KEYCLOAK_SERVER","http://kc.cfg.cpc.uow/auth/")
keycloak_realm = os.getenv("KEYCOLAK_REALM","cfg")
server_port = os.getenv("API_PORT", "8080")
emgum_api_url_context = os.getenv("URL_CONTEXT", "/emgum/api/v1.0/")