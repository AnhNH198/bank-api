from flask import Flask, request, jsonify
from flask_restful import Resource, Api
import bcrypt
from pymongo import MongoClient

app = Flask(__name__)
api = Api(app)
client = MongoClient("mongodb://db:27017")
db = client.bankDB
users = db["Users"]


def generate_return_json(status, message):
    ret_json = {
        "Message": message,
        "Status": status
    }
    return jsonify(ret_json)


def user_exists(username):
    if users.find({"Username": username}).count() == 0:
        return False
    else:
        return True


def verify_passwd(username, passwd):
    if not user_exists(username):
        return False

    hashed_passwd = users.find({"Username": username}[0]["Passwd"])

    if bcrypt.hashpw(passwd.encode('utf8'), hashed_passwd) == hashed_passwd:
        return True
    else:
        return False


def verify_credentials(username, passwd):
    if not user_exists(username):
        return generate_return_json(301, "Invalid username"), True

    correct_passwd = verify_passwd(username, passwd)

    if not correct_passwd:
        return generate_return_json(302, "Incorrect password"), True

    return None, False


def check_cash_user(username):
    if not user_exists(username):
        return generate_return_json(301, "Invalid username")
    cash = users.find({"Username": username}[0]["Own"])
    return cash


def check_debt_user(username):
    if not user_exists(username):
        return generate_return_json(301, "Invalid username")

    debt = users.find({"Username": username}[0]["Debt"])
    return debt


def update_cash_user(username, amount):
    users.update({"Username": username}, {
            "$set": {
                "Own": amount
            }
        })


def update_debt_user(username, amount):
    users.update({"Username": username}), {
        "$set": {
            "Debt": amount
        }
    }


class register(Resource):
    def post(self):
        posted_data = request.get_json()
        username = posted_data["Username"]
        passwd = posted_data["Passwd"]

        if user_exists(username):
            return jsonify(generate_return_json(301, "Invalid username"))

        hashed_passwd = bcrypt.hashpw(passwd.encode('utf8'), bcrypt.gensalt())

        users.insert({
            "Username": username,
            "Passwd": hashed_passwd,
            "Own": 0,
            "Debt": 0
        })
        return generate_return_json(200, "Your account has been created")


class add_money(Resource):
    def post(self):
        posted_data = request.get_json()
        username = posted_data["Username"]
        passwd = posted_data["Passwd"]
        money = posted_data["Amount"]

        ret_json, is_error = verify_credentials(username, passwd)

        if is_error:
            return jsonify(ret_json)

        if money < 10000:
            return generate_return_json(304, "Minimum amount is 10000")

        new_money = money - 1000
        current_own = check_cash_user(username)
        bank_cash = check_cash_user("BANK")
        update_cash_user("BANK", bank_cash + 1000)
        update_cash_user(username, current_own + new_money)

        return jsonify(generate_return_json(200, "Added successfully"))


class transfer_money(Resource):
    def post(self):    
        posted_data = request.get_json()
        username = posted_data["Username"]
        passwd = posted_data["Passwd"]
        money = posted_data["Amount"]
        to = posted_data["To"]

        ret_json, is_error = verify_credentials(username, passwd)

        if is_error:
            return ret_json

        if money < 10000:
            return generate_return_json(304, "Minimum amount is 10000 VND")

        if not user_exists(to):
            return generate_return_json(301, "Invalid receiver")

        current_own = check_cash_user(username)
        current_receiver_own = check_cash_user(to)
        bank_cash = check_cash_user("BANK")

        if current_own < money + 1000:
            return generate_return_json(305, "You do not have enough money")

        update_cash_user(username, current_own - money - 1000)
        update_cash_user(to, current_receiver_own + money)
        update_cash_user("BANK", bank_cash + 1000)

        return generate_return_json(200, "Transfer successfully")


class check_balance(Resource):
    def post(self):
        posted_data = request.get_json()
        username = posted_data["Username"]
        passwd = posted_data["Passwd"]

        ret_json, is_error = verify_credentials(username, passwd)

        if is_error:
            return ret_json

        ret_json = users.find({"Username": username}, {
            "Passwd": 0,
            "_id": 0
        })[0]
        return jsonify(ret_json)


class take_loan(Resource):
    def post(self):
        posted_data = request.get_json()
        username = posted_data["Username"]
        passwd = posted_data["Passwd"]
        money = posted_data["Amount"]

        ret_json, is_error = verify_credentials(username, passwd)
        if is_error:
            return ret_json

        if money < 1000:
            return generate_return_json(304, "Invalid amount of money")

        current_own = check_cash_user(username)
        current_debt = check_debt_user(username)
        bank_cash = check_cash_user("BANK")

        update_cash_user(username, current_own + money - 1000)
        update_debt_user(username, current_debt + money)
        update_cash_user("BANK", bank_cash + 1000)


class pay_loan(Resource):
    def post(self):
        posted_data = request.get_json()
        username = posted_data["Username"]
        passwd = posted_data["Passwd"]
        money = posted_data["Amount"]

        ret_json, is_error = verify_credentials(username, passwd)
        if is_error:
            return ret_json

        current_own = check_cash_user(username)
        current_debt = check_debt_user(username)

        if money > current_own:
            return generate_return_json(305, "You do not have enough money")

        update_cash_user(username, current_own - money)
        update_debt_user(username, current_debt - money)


class hello_user(Resource):
    def get(self):
        return generate_return_json(200, "XIN CHAO")

api.add_resource(hello_user, "/hello")
api.add_resource(register, "/register")
api.add_resource(add_money, "/add")
api.add_resource(transfer_money, "/transfer")
api.add_resource(check_balance, "/balance")
api.add_resource(take_loan, "/borrow")
api.add_resource(pay_loan, "/payoff")

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
