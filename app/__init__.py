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

""" Configure logging """
logging.basicConfig(filename='api-logs.log', level=logging.INFO,format='%(asctime)s - %(name)s - %(module)s - %(funcName)s - %(lineno)d- %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
conlog = logging.StreamHandler()
logger.addHandler(conlog)
logger.info("EMGUM API Server started.")
