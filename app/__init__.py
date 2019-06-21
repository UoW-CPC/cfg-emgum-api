"""[summary]
Init module
[description]
The init module creates Flask object, databases, and logging handler
"""
from flask import Flask
from flask_restful import reqparse, abort, Api, Resource
import logging
import os
import json
from logging.handlers import RotatingFileHandler


# create application object of class Flask

app = Flask(__name__)


from app import routes
from app import openidc

#if not app.debug:
# initialize the log handler: The handler used is RotatingFileHandler which rotates the log file when the size of the file exceeds a certain limit.
#cfg_path = os.path.abspath(os.path.join(os.path.dirname(__file__),"../../"))
cfg_path = os.path.abspath(os.path.join(os.path.dirname(__file__),".."))
json_path = os.path.join(cfg_path, 'config.json')
with open(json_path,'r') as f:
	config = json.load(f)

error_path = config['DEFAULT']['LOG_FILE']
# error_path = '/tmp/cfg_error.log'

logHandler = RotatingFileHandler(error_path, maxBytes=1000, backupCount=1) 
# set the log handler level
logHandler.setLevel(logging.INFO)
# create formatter and add it to the handlers: date time - name of package - file name (module name) - function name - line number - level (error, infor,...) - message 
formatter = logging.Formatter('%(asctime)s - %(name)s - %(module)s - %(funcName)s - %(lineno)d- %(levelname)s - %(message)s')
logHandler.setFormatter(formatter)

# set the app logger level:  ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'). See http://flask.pocoo.org/docs/0.12/errorhandling/
app.logger.setLevel(logging.INFO)
app.logger.addHandler(logHandler)
