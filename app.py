from flask import Flask, flash, render_template, request, redirect, session, url_for
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, Email
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
from datetime import datetime

# Blog Configuration values.
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = '|ezulJ_OJC_*;cA'
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
    _password = db.Column(db.String, nullable=False)
    authenticated = db.Column(db.Boolean, default=False)

    def __init__(self, username, password_plaintext):
        self.username = username
        self.password = password_plaintext
        self.authenticated = False

    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, password_plaintext):
        self._password = bcrypt.generate_password_hash(password_plaintext)

    @hybrid_method
    def is_correct_password(self, password_plaintext):
        return bcrypt.check_password_hash(self.password, password_plaintext)

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
        """Return the username to satisfy Flask-Login's requirements."""
        return str(self.id)

    def __repr__(self):
        return '<User {0}>'.format(self.name)


# This callback is used to reload the user object from the user ID stored in the session.
@login_manager.user_loader
def load_user(user_id):
    return Users.query.filter(Users.id == int(user_id)).first()


class BlogpostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=6, max=40)])
    subtitle = StringField('Subtitle', validators=[DataRequired(), Length(min=6, max=40)])
    content = TextAreaField('Enter your blog post here', render_kw={"rows": 11, "cols": 70}, validators=[DataRequired()])


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=6, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=20)])


class RegisterForm(FlaskForm):
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

    return render_template('index.html',
                           posts=posts.items,
                           next_url=next_url,
                           prev_url=prev_url)


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


@app.route('/user/<username>')
def user(username):
    page = request.args.get('page', 1, type=int)
    posts = Blogpost.query.order_by(Blogpost.date_posted.desc()).filter(Blogpost.author == username)\
        .paginate(page, 5, False)

    next_url = url_for('user', page=posts.next_num, username=username) \
        if posts.has_next else None
    prev_url = url_for('user', page=posts.prev_num, username=username) \
        if posts.has_prev else None

    return render_template('index.html',
                           posts=posts.items,
                           next_url=next_url,
                           prev_url=prev_url)


@app.route('/userposts/<string:user_id>')
def userposts(user_id):
    if user_id != current_user.get_id():
        return redirect(url_for('index'))

    page = request.args.get('page', 1, type=int)
    user = Users.query.filter(Users.id == user_id).first()
    posts = Blogpost.query.order_by(Blogpost.date_posted.desc()).filter(Blogpost.author == user.username).\
        paginate(page, 5, False)

    next_url = url_for('userposts', page=posts.next_num, user_id=user_id) \
        if posts.has_next else None
    prev_url = url_for('userposts', page=posts.prev_num, user_id=user_id) \
        if posts.has_prev else None

    return render_template('userposts.html',
                           posts=posts.items,
                           next_url=next_url,
                           prev_url=prev_url)


@app.route('/search/', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        page = request.args.get('page', 1, type=int)
        search = request.form['search']
        return redirect((url_for('pages', query=search, page=page)))

    return redirect(url_for('index'))


@app.route('/pages/<query>')
def pages(query):
    page = request.args.get('page', 1, type=int)
    posts = Blogpost.query.order_by(Blogpost.date_posted.desc()).filter(
        or_(
            Blogpost.content.contains(query),
            Blogpost.author.contains(query),
            Blogpost.title.contains(query),
            Blogpost.subtitle.contains(query)
        )
    ).paginate(page, 5, False)

    next_url = url_for('pages', page=posts.next_num, query=query) \
        if posts.has_next else None
    prev_url = url_for('pages', page=posts.prev_num, query=query) \
        if posts.has_prev else None

    return render_template('index.html', posts=posts.items, next_url=next_url, prev_url=prev_url)


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

            post = Blogpost(title=title,
                            subtitle=subtitle,
                            author=author,
                            content=content,
                            date_posted=datetime.now())

            db.session.add(post)
            db.session.commit()
            return redirect(url_for('index'))

    return render_template('home.html')


@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
def edit(post_id):
    form = BlogpostForm(request.form)
    if request.method == 'POST':
        form = BlogpostForm(request.form)
        if form.validate_on_submit():
            title = form.title.data
            subtitle = form.subtitle.data
            content = form.content.data

            update_post = Blogpost.query.filter_by(id=post_id).first()
            update_post.title = title
            update_post.subtitle = subtitle
            update_post.content = content
            db.session.commit()
            flash('Your post has been updated!', 'success')
            return redirect(url_for('post', post_id=post_id))

    post = Blogpost.query.filter(Blogpost.id == post_id).first()
    if post.author != current_user.username:
        return redirect(url_for('index'))

    form.title.data = post.title
    form.subtitle.data = post.subtitle
    form.content.data = post.content

    return render_template('edit.html',
                           post=post,
                           form=form,
                           post_id=post_id)


@app.route('/delete/<int:post_id>')
def delete(post_id):
    delete_post = Blogpost.query.filter_by(id=post_id).first()
    if delete_post.author != current_user.username:
        return redirect(url_for('index'))

    db.session.delete(delete_post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return render_template('userposts.html')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt = Bcrypt(app)
    app.run(debug=True)
