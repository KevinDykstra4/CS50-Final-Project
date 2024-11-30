import os
import io
import csv
import re
from datetime import datetime
import calendar

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

# Configure application
app = Flask(__name__, template_folder='templates')

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///budget.db")

defaultIncomeCategories = {"Salary/Wages"}
defaultExpenseCategories = {"Gas/Transportation", "Entertainment"}

def getCurrentMonthAndYear(user_Id):
    current_selected_month = db.execute("SELECT selectedmonth FROM users WHERE id=?", user_Id)
    current_selected_year = db.execute("SELECT selectedyear FROM users WHERE id=?", user_Id)
    if current_selected_month and current_selected_year:
        current_selected_month = current_selected_month[0]['selectedmonth']
        current_selected_year = current_selected_year[0]['selectedyear']
    return current_selected_month, current_selected_year


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def home():
    """Show budget summary for user"""
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")
    
    # Get the current month/year for the user
    month_name = ""
    selected_month, selected_year = getCurrentMonthAndYear(user_id)
    if selected_month and selected_year:
        month_name = calendar.month_name[selected_month]

    # Get all the user's categories
    income_categories = db.execute("SELECT * FROM categories WHERE user_id=? AND categorytype=?", user_id, 'income')
    expense_categories = db.execute("SELECT * FROM categories WHERE user_id=? AND categorytype=?", user_id, 'expense')
    categories = income_categories + expense_categories

    transactions = db.execute("SELECT * FROM transactions WHERE user_id=? AND month=? AND year=?", user_id, selected_month, selected_year)
    budgets = db.execute("SELECT * FROM monthly_budget WHERE user_id=? AND month=? AND year=?", user_id, selected_month, selected_year)
    
    # For each budget month, get the budgetted amount for each category
    category_budgets = {}
    for budget in budgets:
        category_budgets[budget['category_id']] = budget['budget_amount']

    # How much was earned and spent in each category?
    income_total = 0
    expense_total = 0
    unassigned_total = 0

    category_totals = {}
    for category in categories:
        category_total = 0
        for transaction in transactions:
            if transaction['category_id'] != category['id']:
                continue
            category_total += transaction['amount']
            if category['categorytype'] == "income":
                income_total += transaction['amount']
            else:
                expense_total += transaction['amount']
        category_totals[category['id']] = round(category_total,2)

    # Get the total amount of transactions that don't have categories assigned to them
    for transaction in transactions:
        if transaction['category_id'] is None:
            unassigned_total += transaction['amount']

    #print(transactions)
    return render_template("home.html", unassigned_total=unassigned_total, income_total=income_total, expense_total=expense_total, category_totals=category_totals, transactions=transactions, income_categories=income_categories, expense_categories=expense_categories, selected_month=selected_month, selected_year=selected_year, month_name=month_name, category_budgets=category_budgets)


@app.route("/change_month", methods=["POST"])
@login_required
def changeMonth():
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")
    
    # Get the current month/year for the user
    current_selected_month, current_selected_year = getCurrentMonthAndYear(user_id)
    if not current_selected_month or not current_selected_year:
        return redirect(request.referrer)
    
    # Forward or back
    action = request.form.get("month")
    if action != "forward" and action != "back":
        return redirect(request.referrer)
    
    new_selected_month = current_selected_month
    new_selected_year = current_selected_year

    # If going forward, get the month after the current month
    if action == "forward":
        if current_selected_month >= 12:
            new_selected_month = 1
            new_selected_year += 1
        else:
            new_selected_month += 1
    # If going backward, get the month before the current month
    else:
        if current_selected_month <= 1:
            new_selected_month = 12
            new_selected_year -= 1
        else:
            new_selected_month -= 1

    db.execute("UPDATE users SET selectedmonth=?, selectedyear=? WHERE id=?", new_selected_month, new_selected_year, user_id)
    return redirect(request.referrer)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Missing username or password")
            return render_template("login.html")
        
        #Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        #Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], password
        ):
            flash("Incorrect username or password")
            return render_template("login.html")
        
        #Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        #redirect user to home page
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    flash("You have logged out")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check if username, password, and confirmation exist
        if not username or not password or not confirmation:
            flash("Please fill in all fields")
            return render_template("register.html")
        
        # Check if password == confirmation
        if password != confirmation:
            flash("Passwords do not match. Please try again")
            return render_template("register.html")
        
        # Make sure username doesn't already exists
        username_already_exists = db.execute("SELECT * FROM users WHERE LOWER(username)=?", username.lower())
        if username_already_exists:
            flash(f'Username "{username}" already exists. Please try again')
            return render_template("register.html")

        # Hash the password
        hash = generate_password_hash(password)
        if not hash:
            flash("System error generating password. Please try again")
            return render_template("register.html")

        # Create new user data, using the current month/year as a starting point
        current_date = datetime.now()
        try:
            db.execute("INSERT INTO users (username, hash, selectedmonth, selectedyear) VALUES(?, ?, ?, ?)", username, hash, current_date.month, current_date.year)
        except:
            return render_template("register.html")

        # Get the last inserted ID
        last_id = db.execute("SELECT last_insert_rowid() AS id")[0]["id"]
        print("The new user ID is:", last_id)

        #Save default categories to database for the user
        for category in defaultIncomeCategories:
            db.execute("INSERT INTO categories (user_id, categorytype, name) VALUES(?, ?, ?)",
                       last_id, "income", category)
        
        for category in defaultExpenseCategories:
            db.execute("INSERT INTO categories (user_id, categorytype, name) VALUES(?, ?, ?)",
                       last_id, "expense", category)

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/create_category", methods=["POST"])
@login_required
def newcategory():
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")

    income_category = request.form.get("income_category")
    expense_category = request.form.get("expense_category")
    if not income_category and not expense_category:
        return redirect("/")
    
    category = income_category or expense_category
    categoryType = income_category and "income" or "expense"

    # Validate that the user set a correct starting budget
    starting_budget = request.form.get("starting_budget")
    if not starting_budget:
        return redirect("/")

    try:
        starting_budget = abs(int(starting_budget))
    except:
        return redirect("/")
    
    # Make sure category doesn't already exist
    existing_category = db.execute("SELECT * FROM categories WHERE LOWER(name)=? AND user_id=?", category.lower(), user_id)
    if existing_category:
        print("Category already exists!")
        return redirect("/") 
    
    # Save the new category
    db.execute("INSERT INTO categories (user_id, categorytype, name) VALUES(?, ?, ?)", user_id, categoryType, category)

    # Add category to monthly_budget (note: currently, only adding it for the current month)
    last_id = db.execute("SELECT last_insert_rowid() AS id")[0]["id"]
    print("The new category is:", last_id)

    selected_month, selected_year = getCurrentMonthAndYear(user_id)
    if (not selected_year and not selected_month):
        return redirect("/")
    
    # Does budget info for this category already exist (it shouldn't)?
    budget_exists = db.execute("SELECT * FROM monthly_budget WHERE user_id=? AND category_id = ?", user_id, last_id)
    if budget_exists:
        print("BUDGET ALREADY EXISTS")
        return redirect("/")

    # Insert category into budget for month
    db.execute("INSERT INTO monthly_budget (user_id, month, year, category_id, budget_amount) VALUES(?, ?, ?, ?, ?)", user_id, selected_month, selected_year, last_id, starting_budget)

    return redirect("/")


@app.route("/delete_category", methods=["POST"])
@login_required
def deleteCategory():
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")

    category_id = request.form.get("category")
    if not category_id:
        return redirect("/")
    
    # Make sure no transaction is currently linked to the category; if they are, set their category to NULL
    db.execute("UPDATE transactions SET category_id=NULL WHERE category_id=?", category_id)

    # Delete any budgets across any month/year associated with the category
    # Note: Deleting from budgets before categories to avoid FOREIGN KEY issue
    db.execute("DELETE FROM monthly_budget WHERE user_id=? AND category_id=?", user_id, category_id)

    # Delete category from categories table
    db.execute("DELETE FROM categories WHERE id = ? AND user_id=?", category_id, user_id)

    return redirect("/")


@app.route("/update_budget", methods=["POST"])
@login_required
def updateBudget():
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")

    category_id = request.form.get("category_id")
    budget_amount = request.form.get("budget_amount")
    if not category_id or not budget_amount:
        return redirect("/")

    # Update budget for category for that specific month/year
    selected_month, selected_year = getCurrentMonthAndYear(user_id)
    if (not selected_year and not selected_month):
        return redirect("/")
    
    # Check if budget was already initialized
    # If initialized, simply update it
    budget_exists = db.execute("SELECT * FROM monthly_budget WHERE user_id=? AND month=? AND year=? AND category_id = ?", user_id, selected_month, selected_year, category_id)
    if budget_exists:
        db.execute("UPDATE monthly_budget SET budget_amount=? WHERE user_id=? AND month=? AND year=? AND category_id=?", budget_amount, user_id, selected_month, selected_year, category_id)
    # If not, insert new row
    else:
        db.execute("INSERT INTO monthly_budget (user_id, month, year, category_id, budget_amount) VALUES(?, ?, ?, ?, ?)", user_id, selected_month, selected_year, category_id, budget_amount)
    return redirect("/")


@app.route("/update_name", methods=["POST"])
@login_required
def updateName():
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")
    
    category_id = request.form.get("category_id")
    name = request.form.get("name")
    if not category_id or not name:
        return redirect("/")
    
    # Make sure category name isn't a duplicate
    existing_category = db.execute("SELECT * FROM categories WHERE LOWER(name)=? AND user_id=?", name.lower(), user_id)
    if existing_category:
        return redirect("/")

    # Update the category's name
    db.execute("UPDATE categories SET name=? WHERE id=? AND user_id=?", name, category_id, user_id)
    return redirect("/")


@app.route("/transactions", methods=["GET", "POST"])
@login_required
def transactions():
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")
    
    # Adding manual transactions
    if request.method == "POST":
        dates = request.form.getlist('date')
        descriptions = request.form.getlist('description')
        amounts = request.form.getlist('amount')
        categories = request.form.getlist('category')

        if not dates or not descriptions or not amounts or not categories:
            return redirect("/")
        
        # Make sure we're creating the transaction for the correct month & year:
        ## UPDATE: Now create ALL transactions regardless of month/year
        
        # Process each fieldset
        for i in range(len(dates)):
            date = dates[i]
            description = descriptions[i] and str(descriptions[i])
            amount = amounts[i] and int(amounts[i])
            category = categories[i] and int(categories[i])

            try:
                date_obj = datetime.strptime(date, "%Y-%m-%d")
            except ValueError:
                print(f"Invalid date format: {date}")
                continue

            year = date_obj.year
            month = date_obj.month
            day = date_obj.day

            # Make sure user form is actually within the required month/year
            ## UPDATE: No longer care if it's within the currently-selected month/year
            
            # Make sure description is correct length
            if not description or len(description) > 50:
                continue

            # Make sure amount is within allowable range
            if not amount or amount < 0 or amount > 99999:
                continue

            # Make sure appropriate category id is selected
            validCategory = db.execute("SELECT * FROM categories WHERE user_id=? AND id=?", user_id, category)
            if not validCategory:
                continue

            # Actually add the transaction
            db.execute("INSERT INTO transactions (user_id, category_id, month, day, year, amount, description) VALUES(?, ?, ?, ?, ?, ?, ?)", user_id, category, month, day, year, amount, description)
        
        return redirect("/transactions")
    # Display transactions
    else:
        month_name = ""
        selected_month, selected_year = getCurrentMonthAndYear(user_id)
        if selected_month and selected_year:
            month_name = calendar.month_name[selected_month]
        if not selected_month or not selected_year or not month_name:
            return redirect("/")
        
        # Get the user' transaction settings (whether or not to view all transactions)
        transaction_settings = db.execute("SELECT * FROM transaction_settings WHERE user_id=?", user_id)
        if not transaction_settings:
           db.execute("INSERT INTO transaction_settings(user_id) VALUES(?)", user_id)
           transaction_settings = db.execute("SELECT * FROM transaction_settings WHERE user_id=?", user_id)
        if not transaction_settings:
            return redirect("/")
        
        show_all = transaction_settings[0]["show_all"]
        warn_delete = transaction_settings[0]["warn_delete"]

        categories = db.execute("SELECT * FROM categories WHERE user_id=? ORDER BY categorytype DESC", user_id)
        if categories:          
            if show_all == 0:
                # Show only transactions for the current month/year
                transactions = db.execute(
                    """
                    SELECT transactions.*, categories.name AS category_name, categories.categorytype AS category_type 
                    FROM transactions 
                    LEFT JOIN categories ON transactions.category_id = categories.id
                    WHERE transactions.user_id=? AND transactions.month=? AND transactions.year=? 
                    ORDER BY transactions.year, transactions.month, transactions.day
                    """, user_id, selected_month, selected_year)
            else:
                # Show all transactions
                transactions = db.execute(
                    """
                    SELECT transactions.*, categories.name AS category_name, categories.categorytype AS category_type 
                    FROM transactions 
                    LEFT JOIN categories ON transactions.category_id = categories.id
                    WHERE transactions.user_id=? 
                    ORDER BY transactions.year, transactions.month, transactions.day
                    """, user_id)
                
            return render_template("transactions.html", show_all=show_all, warn_delete=warn_delete, transactions=transactions, categories=categories, month_name=month_name, selected_year=selected_year) #, dates=dates[0])
        return redirect("/")


@app.route("/add_csv_transactions", methods=["POST"])
@login_required
def addCSVTransctions():
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")
    
    date_header_name = request.form.get("date_header_name")
    description_header_name = request.form.get("description_header_name")
    amount_header_name = request.form.get("amount_header_name")

    # print(f"DATE HEADER: {date_header_name}")
    # print(f"DESCRIPTION HEADER: {description_header_name}")
    # print(f"AMOUNT HEADER: {amount_header_name}")

    # Parse transactions
    transactions = {}
    for key, value in request.form.items():
        if not key.startswith("transactions["):
            continue
        
        # Reference: https://www.w3schools.com/python/ref_string_split.asp
        key = key.split("[") #eg ["transactions", "0]", "Account Name]"]

        if len(key) < 3:
            continue

        # Reference: https://www.w3schools.com/python/ref_string_rstrip.asp
        id = key[1].rstrip("]")
        field = key[2].rstrip("]")

        if not id.isdigit() or not field:
            continue
            
        id = int(id)

        # Initialize table
        if id not in transactions:
            transactions[id] = {}

        transactions[id][field] = value                        

    # Print parsed transactions for debugging
    #print("Parsed Transactions:")
    for _, transaction_data in transactions.items():
        #print(f"INDEX: {index}: {transaction_data}")
        date_value = transaction_data[date_header_name]
        amount_value = transaction_data[amount_header_name]
        description_value = transaction_data[description_header_name]
        if not date_value or not description_value or not amount_value:
            continue
        
        try:
            date_obj = datetime.strptime(date_value, "%m/%d/%Y")
        except ValueError:
            print(f"Invalid date format: {date_value}")
            continue

        year = date_obj.year
        month = date_obj.month
        day = date_obj.day

        # Allow for decimals, and make sure number is absolute value
        amount_value = float(amount_value) and abs(float(amount_value))
        if not amount_value:
            continue

        # Reference: https://tutorpython.com/truncate-python-string/
        if len(description_value) > 50:
            description_value = description_value[:50] + "..."

        category = transaction_data["category"]
        validCategory = db.execute("SELECT * FROM categories WHERE user_id=? AND id=?", user_id, category)
        
        # Currently, category is not required
        if category and validCategory:
            db.execute("INSERT INTO transactions (user_id, category_id, month, day, year, amount, description) VALUES(?, ?, ?, ?, ?, ?, ?)", user_id, category, month, day, year, amount_value, description_value)
        else:
            db.execute("INSERT INTO transactions (user_id, month, day, year, amount, description) VALUES(?, ?, ?, ?, ?, ?)", user_id, month, day, year, amount_value, description_value)
    
    return redirect("/transactions")


@app.route("/delete_transaction", methods=["POST"])
@login_required
def deleteTransaction():
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")
    
    transaction_id = request.form.get("transaction")
    if not transaction_id:
        return redirect("/transactions")

    print(f"Transaction id: {transaction_id}")
    db.execute("DELETE FROM transactions WHERE id=? AND user_id=?", transaction_id, user_id)
    return redirect("/transactions")


@app.route("/update_transaction_date", methods=["POST"])
@login_required
def updateTransactionDate():
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")
    
    transaction_id = request.form.get("transaction")
    date = request.form.get("date")
    if not transaction_id or not date:
        return redirect("/transactions")

    try:
        date_obj = datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        print(f"Invalid date format: {date}")
        return redirect("/transactions")

    year = date_obj.year
    month = date_obj.month
    day = date_obj.day

    db.execute("UPDATE transactions SET month=?, day=?, year=? WHERE id=? AND user_id=?", month, day, year, transaction_id, user_id)
    return redirect("/transactions")


@app.route("/update_transaction_description", methods=["POST"])
@login_required
def updateTransactionDescription():
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")
    
    transaction_id = request.form.get("transaction")
    description = request.form.get("description")
    if not transaction_id or not description:
        return redirect("/transactions")
    
    # Make sure description is correct length
    if len(description) > 50:
        return redirect("/transactions")

    db.execute("UPDATE transactions SET description=? WHERE id=? AND user_id=?", description, transaction_id, user_id)
    return redirect("/transactions")


@app.route("/update_transaction_amount", methods=["POST"])
@login_required
def updateTransactionAmount():
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")
    
    transaction_id = request.form.get("transaction")
    amount = request.form.get("amount")
    if not transaction_id or not amount:
        return redirect("/transactions")

    # Make ure amount is an actual number
    amount = float(amount)
    if not amount:
        return redirect("/transactions")
    
    # Make sure amount is within allowable range
    if amount < 0 or amount > 99999:
        return redirect("/transactions")

    db.execute("UPDATE transactions SET amount=? WHERE id=? AND user_id=?", amount, transaction_id, user_id)
    return redirect("/transactions")


@app.route("/update_transaction_category", methods=["POST"])
@login_required
def updateTransactionCategory():
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")
    
    transaction_id = request.form.get("transaction")
    category = request.form.get("category")
    if not transaction_id or not category:
        return redirect("/transactions")

    validCategory = db.execute("SELECT * FROM categories WHERE user_id=? AND id=?", user_id, category)
    if validCategory:
        db.execute("UPDATE transactions SET category_id=? WHERE id=? AND user_id=?", category, transaction_id, user_id)
    
    return redirect("/transactions")


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")
    
    if request.method == "POST":
        file = request.files.get("csv")

        if not file:
            print("NO FILE")
            return redirect("/upload")
        
        # Wrap the binary file in a text mode
        # Reference: ChatGPT
        text_file = io.TextIOWrapper(file, encoding="utf-8")
        reader = csv.DictReader(text_file)
        rows = list(reader)

        categories = db.execute("SELECT * FROM categories WHERE user_id=? ORDER BY categorytype DESC", user_id)
        return render_template("csvtransactions.html", reader=rows, categories=categories)
    else:
        return render_template("upload.html")


@app.route("/toggle_all_transactions", methods=["POST"])
@login_required
def toggleAllTransactions():
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")  
    
    transaction_settings = db.execute("SELECT show_all FROM transaction_settings WHERE user_id=?", user_id)
    if not transaction_settings:
        return redirect("/transactions")
    
    show_all = transaction_settings[0]['show_all']
    if show_all is None:
        return redirect("/transactions")
    
    if show_all == 1:
        show_all = 0
    else:
        show_all = 1

    db.execute("UPDATE transaction_settings SET show_all=? WHERE user_id=?", show_all, user_id)
    
    return redirect("/transactions")


@app.route("/toggle_warn_delete", methods=["POST"])
@login_required
def toggleWarnDelete():
    user_id = session["user_id"]
    if not user_id:
        return render_template("login.html")  
    
    transaction_settings = db.execute("SELECT warn_delete FROM transaction_settings WHERE user_id=?", user_id)
    if not transaction_settings:
        return redirect("/transactions")
    
    warn_delete = transaction_settings[0]['warn_delete']
    if warn_delete is None:
        return redirect("/transactions")
    
    if warn_delete == 1:
        warn_delete = 0
    else:
        warn_delete = 1

    db.execute("UPDATE transaction_settings SET warn_delete=? WHERE user_id=?", warn_delete, user_id)
    
    return redirect("/transactions")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Default to 5000 if no PORT is provided
    app.run(debug=True, host="0.0.0.0", port=port)