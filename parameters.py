
import os
import logging

""" Configurable parameters """
# if os.getenv("KEYCLOAK_SERVER") is None and os.getenv("KEYCOLAK_REALM") is None:
#     raise Exception("Values for Keycloak server and realm isn't avalable")

#keycloak_server = os.getenv("KEYCLOAK_SERVER","https://api.emgora.eu/v1/emgum/server/auth/")
keycloak_server = os.getenv("KEYCLOAK_SERVER","https://crazykiko.net/v1/emgum/server/auth/")
keycloak_realm = os.getenv("KEYCLOAK_REALM","cfg")
server_port = os.getenv("API_PORT", "8080")
emgum_api_url_context = os.getenv("URL_CONTEXT", "/emgum/api/v1.0/")
postgres_server = os.getenv("DB_ADDR")
postgres_username = os.getenv("DB_USER")
postgres_pwd = os.getenv("DB_PASSWORD")
postgres_db = os.getenv("DB_DATABASE")

ssl_cert = os.getenv("SSL_CERT")
ssl_key  = os.getenv("SSL_KEY")
pass_auth_cert = True if os.getenv("PASS_AUTH_CERT","false") == "true" else False