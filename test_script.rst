.. default-role:: code
.. code:: robotframework

	*** Settings *** 				
	Library     lib/cfg_test_lib.py
	Library           Collections

	*** Test Cases *** 
	Application with initial registration token could register itself as Keycloak client
		${client_id_res}    ${client_secret_res}    ${reg_token} =    Dynamically register client    ${initial_reg_token}   ${client_name}    ${redirect_uris}
		Set Global Variable     ${client_id_res}
		Set Global Variable     ${client_secret_res}
		Set Global Variable     ${reg_token}
		Status should be 	  ${http_code_ok}
	
	Client with registration token could update its information in Keycloak
		${new_reg_token} =    Update client       ${client_id_res}   ${reg_token}    ${new_redirect_uris}   ${new_client_name}
		Set Global Variable    ${new_reg_token}
		Status should be 	  ${http_code_ok}
	    Data should be     ${new_client_name}

	Client with registration token could retrieve its information in Keycloak
		Retrieve client     ${client_id_res}   ${new_reg_token}
		Status should be 	  ${http_code_ok}

	Client with invalid registration token cannot retrieve its information in Keycloak
		Retrieve client     ${client_id_res}   ${invalid_reg_token}
		Status should be 	  ${http_code_bad_request}	

	Client with invalid client_id token cannot retrieve its information in Keycloak
		Retrieve client     ${invalid_client_id}   ${new_reg_token}
		Status should be 	  ${http_code_bad_request}

	Client with expired registration token cannot retrieve its information in Keycloak
		Retrieve client    ${client_id_res}    ${reg_token}	
		Status should be 	  ${http_code_bad_request}
		
	Client with registration token could delete itself from Keycloak
		Delete client     ${client_id_res}   ${new_reg_token}
		Status should be 	  ${http_code_ok}

	Client could not retrieve its information after being deleted
		Retrieve client     ${client_id_res}   ${new_reg_token}
		Status should be 	  ${http_code_bad_request}

	User who is assigned 'manage-users' role can add a new user
	    ${manager_access_token}    ${manager_refresh_token} =    Retrieve tokens    ${client_id}     ${client_secret}     ${manager_user_name}    ${manager_password}
		Set Global Variable    ${manager_access_token}
		Add user    ${manager_access_token}    ${new_username}     ${new_password}    ${firstname}    ${lastname}    ${email}
		Status should be     ${http_code_created}

	User who is assigned 'manage-users' role can retrieve a user
		Retrieve user    ${manager_access_token}    ${new_username}
		Status should be     ${http_code_ok}
		Data should be    ${firstname}

	User who is assigned 'manage-users' role can update a user
		Update user    ${manager_access_token}    ${new_username}    ${firstname_update}    ${lastname_update}
		Status should be     ${http_code_ok}
		Retrieve user    ${manager_access_token}    ${new_username}
		Data should be    ${firstname_update}

	Client can retrieve access token and refresh token from user's username and password
		${access_token}    ${refresh_token} =    Retrieve tokens    ${client_id}     ${client_secret}     ${new_username}    ${new_password}
		Set Global Variable    ${access_token}
		Set Global Variable    ${refresh_token} 
		Status should be 	  ${http_code_ok}

	Client can introspect/ verify the access token
		Verify token    ${access_token}    ${client_id}     ${client_secret}
		Status should be 	  ${http_code_ok}

	Client can use the access token to retrieve the user information
		Retrieve userinfo    ${access_token}    ${client_id}     ${client_secret}
		Status should be 	  ${http_code_ok}

	Client can renew the access token
		${new_access_token}    ${new_refresh_token} =    Renew tokens     ${refresh_token}    ${client_id}     ${client_secret}
		Set Global Variable    ${new_access_token}
		Set Global Variable    ${new_refresh_token}
		Status should be 	  ${http_code_ok}

	Client can verify the new access token
		Verify token     ${new_access_token}    ${client_id}     ${client_secret}
		Status should be 	  ${http_code_ok}

	A client can exchange a received token to achieve its own token
		Exchange a token    ${new_access_token}    ${another_client_id}     ${another_client_secret}
		Status should be 	  ${http_code_ok}
		
	Client can retrieve a rpt token
		${rpt} =    Get rpt    ${new_access_token}   ${resource_server}   ${resource}    ${scope}
		Set Global Variable    ${rpt}
		Status should be 	  ${http_code_ok}
		
	Client can verify the rpt token
		Verify rpt    ${rpt}   ${client_id}   ${client_secret} 
		Status should be 	  ${http_code_ok}
	
	Client can send log out request to Keycloak
		Log out    ${new_refresh_token}    ${client_id}     ${client_secret}
		Status should be 	  ${http_code_ok}

	Client cannot verify the access token after log out
		Verify token     ${new_access_token}    ${client_id}     ${client_secret}
		Status should be 	  ${http_code_bad_request}

	
	User who is assigned 'manage-users' role can create a group
	    Create group    ${manager_access_token}    ${group1}    ${group1_att}
		Status should be     ${http_code_created}
				
	User who is assigned 'manage-users' role can retrieve a group
	    Get group    ${manager_access_token}    ${group1}
		Status should be     ${http_code_ok}
		Data should be    ${group1_att_str}
		
	User who is assigned 'manage-users' role can retrieve all group
	    Get all group    ${manager_access_token}
		Status should be     ${http_code_ok}
		
	User who is assigned 'manage-users' role can update a group
	    Update group    ${manager_access_token}    ${group1}    ${group1_new_att}
		Status should be     ${http_code_no_content}
		Get group    ${manager_access_token}    ${group1}
		Data should be    ${group1_new_att_str}

	User who is assigned 'manage-users' role can add a user to a group
	    Assign group user    ${manager_access_token}    ${new_username}   ${group1}
		Status should be     ${http_code_no_content}
	
	User who is assigned 'manage-users' role can revoke a user from a group
	    Revoke group user    ${manager_access_token}    ${new_username}   ${group1}
		Status should be     ${http_code_no_content}

	User who is assigned 'manage-users' role can get all realm roles
	    Get realm roles    ${manager_access_token}
		Status should be     ${http_code_ok}

	User who is assigned 'manage-users' and 'manage-realms' role can assign a role to a user
	    Grant user role    ${manager_access_token}    ${new_username}    ${role}
		Status should be     ${http_code_no_content}
		
	User who is assigned 'manage-users' role can get a user's roles
	    Get user role    ${manager_access_token}    ${new_username}
		Status should be     ${http_code_ok}

	User who is assigned 'manage-users' and 'manage-realms' role can revoke a user's roles
	    Revoke user role    ${manager_access_token}    ${new_username}      ${role}
		Status should be     ${http_code_no_content}
		Get user role    ${manager_access_token}    ${new_username}
		Status should be     ${http_code_ok}
		Should Contain X Times    Data   ${role}   0
		
	Anyone can check health of EMGUM services
		Health   
		Status should be     ${http_code_ok}
		

	User who is assigned 'manage-users' role can delete a user
		Delete user    ${manager_access_token}    ${new_username}
		Status should be    ${http_code_ok}
		Retrieve user    ${manager_access_token}    ${new_username}
		Status should be    ${http_code_ok}
		Data should be    ${not_found_user}
	
	*** Variables ***
	${initial_reg_token}    eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIzYjM3MWU2Ni0zOTFmLTRhMzMtYjM3OC00Mjc0ZmQ5NTExYzcifQ.eyJleHAiOjE2MTg4NjIyNTYsImlhdCI6MTYxODYwMzA1NiwianRpIjoiYzUyYjc5NjktNTE4Yy00Yjc5LWIwODUtMTBkMWRiNDNhY2UzIiwiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwL2F1dGgvcmVhbG1zL2NmZyIsImF1ZCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODA4MC9hdXRoL3JlYWxtcy9jZmciLCJ0eXAiOiJJbml0aWFsQWNjZXNzVG9rZW4ifQ.eP3u0K7qFezzkNUXkd2B4tiEGC2lgiiUNsire5oHdfc
	${invalid_reg_token}           '123'
	${client_name}              test1A
	${new_client_name}          test1B
	@{redirect_uris}             localhost1    localhost2
	${http_code_not_found}       404
	${http_code_created}		 201
	${http_code_bad_request}	 400
	${http_code_ok}              200
	${http_code_no_content}      204
	${shares}					 3
	${threshold}				 2
	${invalid_threshold}		 0   
	@{new_redirect_uris}         localhost3	   localhost4
	${client_id}              emgbc  
	${client_secret}          cf1493eb-ff4a-497f-a2e2-ee7e218ea4b8 
	${another_client_id}     emgsmm
	${another_client_secret}    fd53c3e2-387c-4abd-ac9d-bbe00fcd554e 
	${new_username}                peter
	${firstname}               Pete
	${lastname}                Whit
	${new_password}                peter123
	${email}                   peter@mail.com
	${firstname_update}        'Peter'
	${lastname_update}        'Pan'
	${invalid_client_id}       'abc'
	${super_user_token}      agagaga
	${resource_server}    emgsmm   
	${resource}    credentials 
	${scope}    delete 
	${manager_user_name}    manager
	${manager_password}    123
	${not_found_user}    The user does not exist
	${group1}   test_group1 
	${group1_att}   { "name": ["computer science"],"address": ["uow London"]}
	${group1_att_str}    {u'name': [u'computer science'], u'address': [u'uow London']}
	${group1_new_att}     { "name": ["computer science"],"address": ["New Cavendish, London"]}
	${group1_new_att_str}     {u'name': [u'computer science'], u'address': [u'New Cavendish, London']}
	${role}    developer
	
	
	*** Keywords ***
	Dynamically register client
		[Arguments]    ${initial_reg_token}    ${client_name}     ${redirect_uris}
		${output} =     dynamic_register_a_client    ${initial_reg_token}    ${client_name}    ${redirect_uris}
		[return]    ${output}

	Delete client
		[Arguments]    ${client_id} 	${reg_token}
		delete_a_client    ${client_id} 	${reg_token}

	Retrieve client
		[Arguments]    ${client_id} 	${reg_token}
		retrieve_a_client    ${client_id} 	${reg_token}

	Update client
		[Arguments]    ${client_id} 	${reg_token}      ${new_redirect_uris}    ${new_client_name}
		${output} =     update_a_client    ${client_id} 	${reg_token}     ${new_redirect_uris}    ${new_client_name}
		[return]    ${output}

	Retrieve tokens
		[Arguments]    ${client_id}     ${client_secret}     ${user_name}    ${password}
		${output} =    retrieve_all_tokens    ${client_id}     ${client_secret}     ${user_name}    ${password}
		[return]    ${output}

	Renew tokens
		[Arguments]     ${token}    ${client_id}     ${client_secret}
		${output} =    renew_access_token    ${token}    ${client_id}     ${client_secret}
		[return]    ${output}
	
	Exchange a token
		[Arguments]    ${received_token}   ${client_id}   ${client_secret}
		exchange_token    ${received_token}   ${client_id}   ${client_secret}	
		
	Verify token
		[Arguments]     ${token}    ${client_id}     ${client_secret}
		introspect_access_token        ${token}    ${client_id}     ${client_secret}

	Log out
		[Arguments]     ${token}    ${client_id}     ${client_secret}
		delete_tokens    ${token}    ${client_id}     ${client_secret}

	Add user
		[Arguments]     ${super_user_token}    ${username}       ${password}    ${firstname}    ${lastname}    ${email}
		add_a_user     ${super_user_token}    ${username}       ${password}    ${firstname}    ${lastname}    ${email}

	Retrieve user
		[Arguments]    ${super_user_token}    ${username}
		retrieve_a_user    ${super_user_token}    ${username}

	Delete user
		[Arguments]    ${super_user_token}     ${username}
		delete_a_user   ${super_user_token}    ${username}

	Update user
		[Arguments]    ${super_user_token}    ${username}    ${firstname}    ${lastname}
		update_a_user    ${super_user_token}     ${username}    ${firstname}    ${lastname}
		
	Get rpt
		[Arguments]    ${access_token}   ${resource_server}   ${resource}    ${scope}
		${output} =    retrieve_rpt    ${access_token}   ${resource_server}   ${resource}    ${scope}
		[return]    ${output}	

	Verify rpt
		[Arguments]    ${rpt}   ${client_id}   ${client_secret}
		introspect_rpt    ${rpt}   ${client_id}   ${client_secret}
		
	Create group
		[Arguments]    ${access_token}   ${group_name}   ${group_attributes}
		create_a_group    ${access_token}   ${group_name}   ${group_attributes}

	Get group
		[Arguments]    ${access_token}   ${new_group_name}
		retrieve_a_group    ${access_token}   ${new_group_name}
		
	Get all group
		[Arguments]    ${access_token}
		retrieve_all_group    ${access_token}
		
	Update group
		[Arguments]    ${access_token}   ${group_name}   ${new_group_attributes}
		update_a_group    ${access_token}   ${group_name}   ${new_group_attributes}

	Assign group user
		[Arguments]    ${access_token}   ${username}   ${group_name}
		assign_user_to_group    ${access_token}   ${username}   ${group_name}
		
	Get group members
		[Arguments]    ${access_token}   ${group_name}
		retrieve_group_members    ${access_token}   ${group_name}
		
	Revoke group user
		[Arguments]    ${access_token}   ${username}   ${group_name}
		revoke_user_from_group    ${access_token}    ${username}    ${group_name}
		
	Get realm roles
		[Arguments]    ${access_token}
		retrieve_realm_roles    ${access_token}
		
	Get user role
		[Arguments]    ${access_token}   ${username}
		retrieve_user_role    ${access_token}   ${username}

	Grant user role
		[Arguments]    ${access_token}   ${username}   ${user_role}
		grant_role_to_user    ${access_token}   ${username}   ${user_role}
		
	Revoke user role
		[Arguments]    ${access_token}   ${username}   ${user_role}
		revoke_role_from_user    ${access_token}   ${username}   ${user_role}
		
	Health
		health_check
		