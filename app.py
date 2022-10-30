import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    stocks_total = 0
    stocks = db.execute("SELECT * FROM owned WHERE user_id = ?", session["user_id"])
    for stock in stocks:
        stock['user_id'] = int(lookup(stock['symbol'])['price'])
        stocks_total += stock['user_id'] * stock['count']
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]['cash']
    total = cash + stocks_total
    return render_template("index.html", stocks=stocks, cash=cash, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares", type=int)
        if symbol == None or symbol == '':
            return apology("Enter symbol")
        elif shares == None or shares <= 0:
            return apology("Enter positive number")
        else:
            stock = lookup(symbol)
            if stock == None:
                return apology("Invalid symbol")
            price = float(stock['price'])
            cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
            money = float(cash[0]["cash"])
            number = float(price * shares)
            if number > money:
                return apology("You don't have enough money")
            else:
                value = float(money - number)
                db.execute("UPDATE users SET cash = ? WHERE id = ?", value, session["user_id"])
                date1 = db.execute("SELECT datetime('now')")
                date = date1[0]["datetime('now')"]
                db.execute("INSERT INTO history (user_id, price, count, date, operation, symbol) VALUES(?, ?, ?, ?, ?, ?)",
                           session["user_id"], price, shares, date, 1, symbol)

                if db.execute("SELECT * FROM owned WHERE ? IN (SELECT symbol FROM owned WHERE user_id = ?)", symbol, session["user_id"]):
                    current = db.execute("SELECT count FROM owned WHERE user_id = ? and symbol = ?", session["user_id"], symbol)
                    total = int(current[0]["count"] + shares)
                    db.execute("UPDATE owned SET count = ? WHERE user_id = ? AND symbol = ?", total, session["user_id"], symbol)
                else:
                    db.execute("INSERT INTO owned (user_id, symbol, count) VALUES(?, ?, ?)", session["user_id"], symbol, shares)
            return render_template("bought.html", shares=shares, price=price, symbol=symbol, Tprice=number, cash=value)

    else:
        return render_template("buy.html")


@app.route("/history", methods=["GET", "POST"])
@login_required
def history():
    """Show history of transactions"""
    historys = db.execute("SELECT * FROM history WHERE user_id = ?", session["user_id"])
    return render_template("history.html", historys=historys)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if symbol == None or symbol == '':
            return apology("Enter symbol")
        else:
            stock = lookup(symbol)
            if stock == None:
                return apology("Invalid symbol")
            return render_template("quoted.html", stock=stock)

    else:
        return render_template("quote.html")
    """Get stock quote."""


@app.route("/changeP", methods=["GET", "POST"])
def changeP():

    if request.method == "POST":
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if password == None or password == '':
            return apology("Enter Password")
        elif confirmation != password:
            return apology("New Password and Confirmation do not match")
        else:
            rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
            if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("current_password")):
                return apology("Wrong Username and/or Cureent_Password", 403)
            else:
                db.execute("UPDATE users SET hash = ? WHERE username = ?",
                           generate_password_hash(password), request.form.get("username"))
                return redirect("/")

    else:
        return render_template("changeP.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        # TODO: Add the user's entry into the database
        if db.execute("SELECT * FROM users WHERE username = ?", username):
            return apology("Username exists")
        if username == None or username == '':
            return apology("Enter username")
        elif password == None or password == '':
            return apology("Enter Password")
        elif confirmation != password:
            return apology("Password and Confirmation do not match")
        else:
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, generate_password_hash(password))
            return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares", type=int)
        if symbol == None or symbol == '':
            return apology("Enter symbol")
        elif shares == None or shares <= 0:
            return apology("Enter positive number")
        else:
            stock = lookup(symbol)
            if stock == None:
                return apology("Invalid symbol")
            price = stock['price']
            cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
            money = float(cash[0]["cash"])
            number = price * shares
            if shares > db.execute("SELECT count FROM owned WHERE user_id = ? and symbol = ?", session["user_id"], symbol)[0]['count']:
                return apology("You don't have enough stocks")
            else:
                value = money + number
                db.execute("UPDATE users SET cash = ? WHERE id = ?", value, session["user_id"])
                date1 = db.execute("SELECT datetime('now')")
                date = date1[0]["datetime('now')"]
                db.execute("INSERT INTO history (user_id, price, count, date, operation, symbol) VALUES(?, ?, ?, ?, ?, ?)",
                           session["user_id"], price, shares, date, 0, symbol)
                current = db.execute("SELECT count FROM owned WHERE user_id = ? and symbol = ?", session["user_id"], symbol)
                total = float(current[0]["count"]) - shares
                db.execute("UPDATE owned SET count = ? WHERE user_id = ? AND symbol = ?", total, session["user_id"], symbol)
                db.execute("DELETE FROM owned WHERE user_id = ? AND symbol = ? AND count = ?", session["user_id"], symbol, 0)
                return render_template("sold.html", shares=shares, price=price, symbol=symbol, Tprice=number, cash=value)

    else:
        stocks = db.execute("SELECT * FROM owned WHERE user_id = ?", session["user_id"])
        return render_template("sell.html", stocks=stocks)

