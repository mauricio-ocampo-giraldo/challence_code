from pymongo import MongoClient
import os, json

config = json.load(open("./config.json"))
#'print(os.getenv('MONGO_PORT'))
#'client = MongoClient(os.getenv('MONGO_URI'), int(os.getenv('MONGO_PORT')))
client = MongoClient(config["MONGO_URI"], config["MONGO_PORT"])
db = client[config["MONGO_DB_NAME"]]

clientsInfo = db.clientsInfo
sessions = db.sessions
users = db.users
