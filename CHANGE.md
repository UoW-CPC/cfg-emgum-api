# v1.2
Add resource /rpt
Add API to exchange token: POST /tokens/<access_token>

# v1.2 - 23 Sep
Remover SUPER_USER_NAME and SUPER_USER_PASSWORD from config.json file
Change to resource /users: add access_token as the header
Add automatic test script for APIs: exchange token, get rpt token, and verify rpt token

# v1.3 - 13 Nov 2019
Dockerize the application
Change the logging mechanism into using logger, which can produce log information into standard stream
Update /users to cover the case of unauthorized token (token from user without appropriate role)
Update test_script and library for test script (cfg_test_lib.py)
Add more details (automatic tests, changing log level, API modification) to README.md