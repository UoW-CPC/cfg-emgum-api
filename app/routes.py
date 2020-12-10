from app import app, openidc
from flask_restful import Api
from parameters import emgum_api_url_context, keycloak_server,server_port,postgres_server,postgres_username,postgres_pwd,postgres_db,ssl_cert,ssl_key
from flask import render_template

from healthcheck import HealthCheck
import requests

health = HealthCheck()
HTTP_CODE_OK = 200
EMGUM_VERSION = "1.7"

# add your own check function to the healthcheck
def keycloak_available():
	x = requests.get(keycloak_server+"realms/master/",cert =(ssl_cert,ssl_key))
	ret = (x.status_code==HTTP_CODE_OK)
	return ret, "Keycloak ok"

def emgum_api_available():
	x = requests.get("http://127.0.0.1:"+server_port+emgum_api_url_context,cert =(ssl_cert,ssl_key))
	ret = (x.status_code==HTTP_CODE_OK)
	return ret, "EMGUM API ok"

health.add_check(keycloak_available)
#health.add_check(database_available)
health.add_check(emgum_api_available)
health.add_section("EMGUM API version", EMGUM_VERSION)


def index():
	"""[summary]
	Hello world function
	[description]
	This function returns the list of supported APIs
	"""	
	return render_template('index.html', title='EMGUM API')

##### Index
app.add_url_rule(emgum_api_url_context,'index',index)
app.add_url_rule(emgum_api_url_context+'health','health',view_func=health.run)

api = Api(app)
api.add_resource(openidc.Client,emgum_api_url_context + 'clients/<client_id>')
api.add_resource(openidc.Clients,emgum_api_url_context + 'clients')

api.add_resource(openidc.Token,emgum_api_url_context + 'tokens/<token>')
api.add_resource(openidc.Tokens,emgum_api_url_context + 'tokens')

api.add_resource(openidc.UserInfo,emgum_api_url_context + 'userinfo/<token>')

api.add_resource(openidc.Users,emgum_api_url_context + 'users')
api.add_resource(openidc.User,emgum_api_url_context + 'users/<username>')

api.add_resource(openidc.Endpoint,emgum_api_url_context + 'endpoint')

api.add_resource(openidc.Rpt,emgum_api_url_context + 'rpt')
api.add_resource(openidc.RptToken,emgum_api_url_context + 'rpt/<token>')

api.add_resource(openidc.Groups,emgum_api_url_context + 'groups')
api.add_resource(openidc.UsersGroups,emgum_api_url_context + 'users/<username>/groups/<groupname>')
api.add_resource(openidc.UserRole,emgum_api_url_context + 'users/<username>/roles/<rolename>')
api.add_resource(openidc.UserRole1,emgum_api_url_context + 'users/<username>/roles')

api.add_resource(openidc.Roles,emgum_api_url_context + 'roles')

#api.add_resource(openidc.ExchangedToken,'/v1.0/tokens/exchange')

#api.add_resource(openidc.UserPassword,'/v1.0/users/<username>/password')

#api.add_resource(openidc.AdminClient,'/v1.0/admin/clients/<client_id>')
#api.add_resource(openidc.AdminClients,'/v1.0/admin/clients')

