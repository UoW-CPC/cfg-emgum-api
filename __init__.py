"""[summary]
Main module.
[description]
The main module starts the web service
"""
from app import app
from parameters import server_port

if __name__ == "__main__":
    """[summary]
    [description]
    The main module defines exception handler and runs the web service
    """
    # app.debug = True
    app.run(host= '0.0.0.0',port=server_port)
