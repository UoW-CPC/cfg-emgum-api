from app import app, openidc

#@app.route('/')
#@app.route('/index')
def index():
	"""[summary]
	Hello world function
	[description]
	This function is only for testing if the web service is in operating
	"""
	return "Hello, World!"
 
##### Index
app.add_url_rule('/v1.0/','index',index)

##### User information
app.add_url_rule('/v1.0/userinfo','get_userinfo_api', openidc.get_userinfo_api, methods=['GET'])

##### Tokens
app.add_url_rule('/v1.0/alltokens','get_tokens_api', openidc.get_tokens_api, methods=['GET'])

app.add_url_rule('/v1.0/tokens','logout_api', openidc.logout_api, methods=['DELETE'])
app.add_url_rule('/v1.0/tokens','refresh_token_api', openidc.refresh_token_api, methods=['PUT'])
app.add_url_rule('/v1.0/tokens','introspect_accesstoken_api', openidc.instropect_accesstoken_api, methods=['GET'])

##### Clients
app.add_url_rule('/v1.0/clients','set_client_api', openidc.set_client_api, methods=['PUT'])
app.add_url_rule('/v1.0/clients','create_client_api', openidc.create_client_api, methods=['POST'])

app.add_url_rule('/v1.0/admin','set_admin_api', openidc.set_admin_api, methods=['POST'])

##### Users
app.add_url_rule('/v1.0/users','create_user_api', openidc.create_user_api, methods=['POST'])
app.add_url_rule('/v1.0/users','retrieve_user_api', openidc.retrieve_user_by_username_api, methods=['GET'])
app.add_url_rule('/v1.0/users','delete_user_api', openidc.delete_user_api, methods=['DELETE'])
app.add_url_rule('/v1.0/users','update_user_api', openidc.update_user_by_username_api, methods=['PUT'])

