from flask import Flask, request

app = Flask(__name__)
app.json.sort_keys = False


@app.route("/unrestricted", methods=["POST"])
def unrestricted():
    return "Unrestricted route"


@app.route("/restricted", methods=["POST"])
def restricted():
    # return 403 error if no Authorization header is present
    return "", 403


@app.route("/introspect")
def introspect():
    return {
        "headers": dict(request.headers),
        "auth": request.headers.get("Authorization"),
        "token": request.headers.get("Authorization").split(" ")[1],
    }
