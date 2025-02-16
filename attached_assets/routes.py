from vulnscanner import app
from vulnscanner import db
from vulnscanner import render_template, request, redirect, url_for
from vulnscanner.models import Report,User
from vulnscanner.forms import RegisterForm,LoginForm
from vulnscanner import login_required, login_user, logout_user



@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
    result = Report.query.all()
    return render_template('dashboard.html', result=result)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None
    if request.method == 'POST' and form.validate_on_submit():
        username = request.form['username'] 
        password = request.form['password']
        # Retrieve the user from the database
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid username or password. Please try again." 

    return render_template('login.html', form=form, error=error)  



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = request.form['username'] 
        password = request.form['password']  
        confirm_password=request.form['confirm_password']    

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error = "Username already exists. Please choose a different username."
            return render_template('register.html', error=error)


        if password != confirm_password:
            error = "Passwords do not match. Please try again."
            return render_template('register.html', error=error)
        
        new_user=User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))  # Redirect on success
    return render_template('register.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


