from flask import Flask, request, jsonify
from flask_cors import CORS
from ariadne import make_executable_schema, graphql_sync
from ariadne.explorer import ExplorerGraphiQL
from .schema import type_defs
from .routes import query, mutation

schema = make_executable_schema(type_defs, [query, mutation])

app = Flask(__name__)
CORS(app)

@app.route("/graphql", methods=["GET"])
def graphql_playground():
    return ExplorerGraphiQL().html(None), 200

@app.route("/graphql", methods=["POST"])
def graphql_server():
    data = request.get_json()
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else None

    context = {"request": request, "token": token}

    success, result = graphql_sync(schema, data, context_value=context)
    status_code = 200 if success else 400
    return jsonify(result), status_code
