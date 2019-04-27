import functools

from flask import Flask, flash, render_template, request, redirect, session, url_for
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
from flask_wtf import Form
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, Email
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method

from datetime import datetime


ADMIN_PASSWORD = 'secret'

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'joseas'
db = SQLAlchemy()

login_manager = LoginManager()
login_manager.login_view = "login"


@app.before_first_request
def create_tables():
    db.create_all()


class Blogpost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    subtitle = db.Column(db.String(50))
    author = db.Column(db.String(20))
    date_posted = db.Column(db.DateTime)
    content = db.Column(db.Text)


class Users(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password_plaintext = db.Column(db.String, nullable=False)  # TEMPORARY - TO BE DELETED IN FAVOR OF HASHED PASSWORD
    authenticated = db.Column(db.Boolean, default=False)

    def __init__(self, username, password_plaintext):
        self.username = username
        self.password_plaintext = password_plaintext
        self.authenticated = False

    @hybrid_method
    def is_correct_password(self, plaintext_password):
        return self.password_plaintext == plaintext_password

    @property
    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    @property
    def is_active(self):
        """Always True, as all users are active."""
        return True

    @property
    def is_anonymous(self):
        """Always False, as anonymous users aren't supported."""
        return False

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        """Requires use of Python 3"""
        return str(self.id)

    def __repr__(self):
        return '<User {0}>'.format(self.name)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.filter(Users.id == int(user_id)).first()


class BlogpostForm(Form):
    title = StringField('Title', validators=[DataRequired(), Length(min=6, max=40)])
    subtitle = StringField('Subtitle', validators=[DataRequired(), Length(min=6, max=40)])
    content = TextAreaField('Enter your blog post here', validators=[DataRequired()])


class LoginForm(Form):
    username = StringField('Username', validators=[DataRequired(), Length(min=6, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=20)])


class RegisterForm(Form):
    username = StringField('Username', validators=[DataRequired(), Length(min=6, max=40)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=40)])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])


@app.route('/')
def index():

    page = request.args.get('page', 1, type=int)
    posts = Blogpost.query.order_by(Blogpost.date_posted.desc()).paginate(page, 5, False)
    next_url = url_for('index', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('index', page=posts.prev_num) \
        if posts.has_prev else None

    return render_template('index.html', posts=posts.items, next_url=next_url, prev_url=prev_url)


@app.route('/register', methods=['GET', 'POST'])
def signup():
    form = RegisterForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                new_user = Users(form.username.data, form.password.data)
                new_user.authenticated = True
                db.session.add(new_user)
                db.session.commit()
                flash('Thanks for registering!', 'success')
                return redirect(url_for('index'))
            except IntegrityError:
                db.session.rollback()
                flash('ERROR! Username ({}) already exists.'.format(form.username.data), 'error')
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit():
            user = Users.query.filter_by(username=form.username.data).first()
            if user is not None and user.is_correct_password(form.password.data):
                user.authenticated = True
                db.session.add(user)
                db.session.commit()
                login_user(user)
                flash('Thanks for logging in, {}'.format(current_user.username))
                return redirect(url_for('index'))
            else:
                flash('ERROR! Incorrect login credentials.', 'error')
    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    if request.method == 'POST':
        user = current_user
        user.authenticated = False
        db.session.add(user)
        db.session.commit()
        logout_user()
        flash('Goodbye!', 'info')
        return redirect(url_for('index'))
    return render_template('logout.html')


@app.route('/search/', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        page = request.args.get('page', 1, type=int)
        search = request.form['search']
        posts = Blogpost.query.order_by(Blogpost.date_posted.desc()).filter(
            or_(
                Blogpost.content.contains(search),
                Blogpost.author.contains(search),
                Blogpost.title.contains(search)
            )
        ).paginate(page, 5, False)

        next_url = url_for('search', page=posts.next_num) \
            if posts.has_next else None
        prev_url = url_for('search', page=posts.prev_num) \
            if posts.has_prev else None

        return render_template('search.html', posts=posts.items, next_url=next_url, prev_url=prev_url)
    return redirect(url_for('index'))


@app.route('/pages/<int:page_num>')
def pages(page_num):
    posts = Blogpost.query.order_by(Blogpost.date_posted.desc()).paginate(per_page=5, page=page_num, error_out=True)

    return render_template('pages.html', posts=posts)


@app.route('/post/<int:post_id>')
def post(post_id):
    post = Blogpost.query.filter_by(id=post_id).one()

    return render_template('post.html', post=post)


@app.route('/add')
@login_required
def add():
    form = BlogpostForm()
    return render_template('add.html', form=form)


@app.route('/addpost', methods=['POST'])
@login_required
def addpost():
    form = BlogpostForm()

    if request.method == 'POST':
        if not form.validate():
            flash('All fields are required.')
            return render_template('add.html', form=form)
        else:
            title = form.title.data
            subtitle = form.subtitle.data
            author = current_user.username
            content = form.content.data

            post = Blogpost(title=title, subtitle=subtitle, author=author, content=content, date_posted=datetime.now())

            db.session.add(post)
            db.session.commit()
            return redirect(url_for('index'))
    return render_template('home.html')


if __name__ == '__main__':
    db.init_app(app)
    login_manager.init_app(app)
    app.run(debug=True)
