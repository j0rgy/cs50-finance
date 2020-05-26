import os
import re

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.globals.update(usd=usd)

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Lookup a user's holdings
    rows = db.execute("SELECT * FROM holdings WHERE user_id=:user_id", user_id=session["user_id"])

    # Update the total share value for each stock

    for row in rows:
        symbol = row["symbol"]
        current_price = float(lookup(symbol)["price"])
        share_value = current_price * row["shares"]
        db.execute("UPDATE holdings SET current_price=:current_price, share_value=:share_value WHERE user_id=:user_id AND symbol=:symbol", current_price=current_price, share_value=share_value, user_id=session["user_id"], symbol=symbol)

    portfolio_value = db.execute("SELECT SUM(share_value) FROM holdings WHERE user_id=:user_id", user_id=session["user_id"])[0]["SUM(share_value)"]

    # Get cash
    cash = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])[0]["cash"]
    account_value = float(cash) + portfolio_value

    # Return view
    return render_template("index.html", rows=rows, cash=usd(cash), portfolio_value=usd(portfolio_value), account_value=usd(account_value))


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # Show the buy page if 'get'
    if request.method == "GET":
        return render_template("sell.html")

    # If 'post'
    else:

        # Confirm entered symbol
        symbol = request.form.get("symbol").upper()
        if not symbol:
            return apology("Must enter symbol.")

        # Confirm symbol matches holding
        rows = db.execute("SELECT * FROM holdings WHERE user_id=:user_id AND symbol=:symbol", user_id=session["user_id"], symbol=symbol)
        if len(rows) != 1:
            return apology("You don't own that stock.")

        # Confirm shares is a positive number


        shares = request.form.get("shares")
        if not shares:
            return apology("Must enter a share amount.")
        if not re.match('^[0-9]*$',shares):
            return apology("You must enter a positive whole number.")
        shares = int(shares)

        # Confirm user has enough shares
        user_shares = db.execute("SELECT shares FROM holdings WHERE user_id=:user_id AND symbol=:symbol", user_id=session["user_id"], symbol=symbol)[0]["shares"]
        if shares > user_shares:
            return apology("You don't own that many shares.")

        # Lookup price
        price = float(lookup(symbol)["price"])
        total = float(shares) * price

        # Add record in transaction table
        db.execute("INSERT INTO transactions (user_id,symbol,price,total,shares,timestamp,type) VALUES (:user_id, :symbol, :price, :total, :shares, :timestamp, 'Sell')", user_id=session["user_id"], symbol=symbol, price=price, total=total, shares=shares, timestamp=datetime.now())

        # Update holdings
        # -- If shares are 0, delete row
        if user_shares - shares == 0:
            db.execute("DELETE FROM holdings WHERE user_id=:user_id AND symbol=:symbol", user_id=session["user_id"], symbol=symbol)
        else:
            db.execute("UPDATE holdings SET shares=:shares WHERE user_id=:user_id AND symbol=:symbol", shares=(user_shares-shares), user_id=session["user_id"], symbol=symbol)

            # Update cash
            cash = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])[0]["cash"]
            cash += total
            db.execute("UPDATE users SET cash=:cash WHERE id=:id", cash=cash, id=session["user_id"])

        # Send back to homepage
        return redirect("/")

    return apology("TODO")

@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    if request.method == "GET":
        return render_template("deposit.html")
    else:
        # Get amount
        amount = request.form.get("amount")
        if not amount:
            return apology("Must enter amount.")

        if re.match('^[0-9\.]*$',amount):
            amount=float(amount)
            if amount <= 0:
                return apology("Must enter positive amount.")

            # Get cash
            cash = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])[0]["cash"]
            cash += amount

            # Update cash
            db.execute("UPDATE users SET cash=:cash WHERE id=:id", cash=cash, id=session["user_id"])

            # Add transaction
            db.execute("INSERT INTO transactions (user_id,symbol,price,total,shares,timestamp,type) VALUES (:user_id, :symbol, :price, :total, :shares, :timestamp, :type)", user_id=session["user_id"], symbol="Cash", price=amount, total=amount, shares=0, timestamp=datetime.now(), type='Deposit')

            # Go back home
            return redirect("/")

        else:

            return apology("Must enter a positive number.")

    return apology("TODO")

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:

        # Confirm symbol exists
        symbol = request.form.get("symbol").upper()
        if not symbol:
            return apology("Must enter symbol.")
        if not lookup(symbol):
            return apology("Symbol does not exist.")

        # Confirm share count is greater than zero
        shares = request.form.get("shares")
        if not shares:
            return apology("Must enter a share count.")

        if re.match('^[0-9]*$',shares):

            shares = int(shares)
            if not shares >=1:
                return apology("Shares must be greater than 0.")

            price = float(lookup(symbol)["price"])
            total = price * shares

            # Check if user has enough cash
            rows = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])
            cash = float(rows[0]["cash"])
            if total > cash:
                return apology("You're too broke.")

            # Buy shares

            # Update cash to subtract cost
            new_cash = cash - total
            db.execute("UPDATE users SET cash=:new_cash WHERE id=:id", new_cash=new_cash, id=session["user_id"])

            # === Update holdings to reflect holdings ===
            # Create new row if user does not currently hold stock
            rows = db.execute("SELECT * FROM holdings WHERE user_id=:id AND symbol=:symbol", id=session["user_id"], symbol=symbol)
            if not rows:
                db.execute("INSERT INTO holdings (user_id,symbol,shares,buy_price) VALUES ( :user_id, :symbol, :shares, :buy_price)", user_id=session["user_id"], symbol=symbol, shares=shares, buy_price=price)

            # If user owns the stock, update row
            else:
                total_shares = rows[0]["shares"] + shares
                buy_price = ((rows[0]["buy_price"] * rows[0]["shares"]) + (price * shares)) / total_shares
                db.execute("UPDATE holdings SET shares=:total_shares, buy_price=:buy_price WHERE symbol=:symbol", total_shares=total_shares, buy_price=buy_price, symbol=symbol)


            # Update transactions to reflect transaction
            timestamp = datetime.now()
            db.execute("INSERT INTO transactions (user_id,symbol,price,total,shares,timestamp,type) VALUES (:user_id, :symbol, :price, :total, :shares, :timestamp, 'Buy')", user_id=session["user_id"], symbol=symbol, price=price, total=total, shares=shares, timestamp=timestamp)

            return redirect("/")

        else:

            return apology("Shares must be a positive whole number.")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Get transactions
    rows = db.execute("SELECT * FROM transactions WHERE user_id=:user_id", user_id=session["user_id"])
    return render_template("history.html", rows=rows)



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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        ticker = request.form.get("ticker")
        if not ticker:
            return apology("Must enter ticker symbol.")
        elif lookup(ticker):
            name = lookup(ticker)["name"]
            price = usd(lookup(ticker)["price"])
            symbol = lookup(ticker)["symbol"]
            return render_template("quoted.html", name=name, price=price, symbol=symbol)
        else:
            return apology("Symbol does not exist.")

    return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:

        # Check username
        username = request.form.get("username")
        if not username:
            return apology("Must enter a username.")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=username)

        # Does name exist?
        if len(rows) != 0:
            return apology("Username already exists")

        # Check password
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not password:
            return apology("Must enter a password.")
        elif not confirmation:
            return apology("Must confirm your password.")
        elif password != confirmation:
            return apology("Passwords do not match.")

        # Hash password
        hash = generate_password_hash(password)

        # Create user in database
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=username, hash=hash)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
