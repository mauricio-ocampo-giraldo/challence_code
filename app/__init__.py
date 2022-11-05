from flask import Flask
from flask_cors import CORS
app = Flask(__name__)
CORS(app)

# Make circular imports it's a not so good practice, but for the correct folder structure of the project
# and the small grow that it will have, we will use them.
import app.routes