from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

app = Flask(__name__)

image = os.path.join('static', 'image')
app.config['UPLOAD_FOLDER'] = image
app.config['SECRET_KEY'] = 'Thisisasecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_BINDS']={'two':'sqlite:///community.db'}
application = app
Bootstrap(app)

#intialize database
db=SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
# what does this do?
login_manager.login_view = 'login'
# db model



class User(UserMixin, db.Model):
    id= db.Column(db.Integer,primary_key=True)
    username= db.Column(db.String(15))
    email = db.Column(db.String(50))
    password = db.Column(db.String(80))
    background= db.Column(db.String(15))
    activities=db.relationship('List',cascade="all, delete-orphan",backref='owner')
    def __repr__(self):
        return '<User %r>' % self.username

class List(db.Model):
    id= db.Column(db.Integer,primary_key=True)
    activity=db.Column(db.String(500),nullable=False)
    owner_id= db.Column(db.Integer,db.ForeignKey('user.id'))

class Community(db.Model):
    __bind_key__='two'
    id= db.Column(db.Integer,primary_key=True)
    activity=db.Column(db.String(500),nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=80)])
    remember = BooleanField('remember me')


class UsernameForm(FlaskForm):
    username = StringField('new username', validators=[InputRequired(), Length(min=4, max=15)])


class PasswordForm(FlaskForm):
    currentpassword = StringField('current password', validators=[InputRequired(), Length(min=4, max=15)])
    newpassword = StringField('new password', validators=[InputRequired(), Length(min=4, max=15)])
    confirm = StringField('re-enter new password', validators=[InputRequired(), Length(min=4, max=15)])


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=80)])

class ActivityForm(FlaskForm):
    activity = StringField('activity', validators=[InputRequired(), Length(min=4, max=500)])
    submit = SubmitField('Add')

class ActivityForm2(FlaskForm):
    activity = StringField('activity', validators=[InputRequired(), Length(min=4, max=500)])
    submit2 = SubmitField('Add')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html',user=current_user) 
    

@app.route('/AboutUs', methods=['GET', 'POST'])
def AboutUs():
    return render_template('AboutUs.html',user=current_user) 

@app.route('/SignUp', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method = 'sha256')
        user = User.query.filter_by(email=form.email.data).first()
        if user: 
            flash('Email address already exists')
            return redirect(url_for('signup'))
        user = User.query.filter_by(username=form.username.data).first()
        if user: 
            flash('Username already exists')
            return redirect(url_for('signup'))
        new_user = User(username=form.username.data, email = form.email.data, password=hashed_password, background="white")
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('SignUp.html', form = form, user=current_user)


@app.route('/Login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user: 
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('profile'))

        flash('Invalid username or password')
    return render_template('login.html', form = form, user=current_user)


@app.route('/Profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ActivityForm()
    form2 = ActivityForm2()
    if form.submit.data and form.validate():
        activity= form.activity.data
        user_to_add_to=User.query.get_or_404(current_user.id)
        new_activity=List(activity=activity, owner=user_to_add_to)
        try:
            db.session.add(new_activity)
            db.session.commit()
            return redirect('/Profile')
        except:
            return "There was an error adding User"
    elif form2.submit2.data and form2.validate():
        print("here")
        activity= form2.activity.data
        new_activity=Community(activity=activity)
        try:
            db.session.add(new_activity)
            db.session.commit()
            return redirect('/Profile')
        except:
            return "There was an error adding Activity"
    else:
        all_activities=current_user.activities
        c_all_activities=Community.query
        return render_template('profile.html', user = current_user,form=form,all_activities= all_activities,form2=form2,c_all_activities=c_all_activities)


@app.route('/update/<int:id>', methods=['GET', 'POST'])
def aupdate(id):
    form = ActivityForm()
    activity_to_update= List.query.get_or_404(id)
    if form.validate_on_submit():
        activity_to_update.activity=form.activity.data
        try:
            db.session.commit()
            return redirect('/Profile')
        except:
            return "There was an error updating your activity"
         
    else:
        return render_template('update.html',activity_to_update=activity_to_update,form=form)


@app.route('/delete/<int:id>')
def adelete(id):
    activity_to_delete= List.query.get_or_404(id)
    try:
        db.session.delete(activity_to_delete)
        db.session.commit()
        return redirect('/Profile')
    except:
        return "There was a problem deleting that activity"

@app.route('/cupdate/<int:id>', methods=['GET', 'POST'])
def cupdate(id):
    form = ActivityForm()
    activity_to_update= Community.query.get_or_404(id)
    if form.validate_on_submit():
        activity_to_update.activity=form.activity.data
        try:
            db.session.commit()
            return redirect('/Profile')
        except:
            return "There was an error updating your activity"
         
    else:
        return render_template('cupdate.html',activity_to_update=activity_to_update,form=form)


@app.route('/cdelete/<int:id>')
def cdelete(id):
    activity_to_delete= Community.query.get_or_404(id)
    try:
        db.session.delete(activity_to_delete)
        db.session.commit()
        return redirect('/Profile')
    except:
        return "There was a problem deleting that activity"


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/settings', methods = ['GET', 'POST'])
@login_required
def settings():
    form = UsernameForm()
    form2 = PasswordForm()

    user_to_update= User.query.get_or_404(current_user.id)
    if form2.validate_on_submit():
        if check_password_hash(user_to_update.password,form2.currentpassword.data):
            if (form2.newpassword.data==form2.confirm.data):
                user_to_update.password = generate_password_hash(form2.newpassword.data, method = 'sha256')
                try:
                    db.session.commit()
                    return redirect(url_for('settings'))
                except: 
                    return "error updating username"
            else: 
                flash('Passwords do not match', "pass")
        else:
            flash('Current password incorrect', "pass")    
    if form.is_submitted():
        if (form.data['username']):

            user_to_update.username= form.username.data
            try:
                db.session.commit()
                return redirect(url_for('settings'))
            except: 
                return "error updating username"
    user_to_update= User.query.get_or_404(current_user.id)
    return render_template('settings.html', form = form, form2= form2, username = user_to_update.username, test=form.username.data, user=current_user)

@app.route('/background',methods = ['GET', 'POST'])
def background():
    if request.method == 'POST':
        current_user.background=request.form['btn']
        try:
            db.session.commit()
            return redirect(url_for('settings'))
        except: 
            return "error updating background"

if __name__=='main':
    app.run(debug=True)





