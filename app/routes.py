from app import app, openidc
from flask_restful import Api

def index():
	"""[summary]
	Hello world function
	[description]
	This function is only for testing if the web service is in operating
	"""
	return "Hello, this is CFGUM API server."
 
##### Index
app.add_url_rule('/v1.0/','index',index)

api = Api(app)
api.add_resource(openidc.Client,'/v1.0/clients/<client_id>')
api.add_resource(openidc.Clients,'/v1.0/clients')

api.add_resource(openidc.Token,'/v1.0/tokens/<token>')
api.add_resource(openidc.Tokens,'/v1.0/tokens')

api.add_resource(openidc.UserInfo,'/v1.0/userinfo/<token>')

api.add_resource(openidc.Users,'/v1.0/users')
api.add_resource(openidc.User,'/v1.0/users/<username>')

api.add_resource(openidc.Endpoint,'/v1.0/endpoint')

api.add_resource(openidc.Rpt,'/v1.0/rpt')

#api.add_resource(openidc.UserPassword,'/v1.0/users/<username>/password')

#api.add_resource(openidc.AdminClient,'/v1.0/admin/clients/<client_id>')
#api.add_resource(openidc.AdminClients,'/v1.0/admin/clients')

