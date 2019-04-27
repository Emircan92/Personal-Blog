import functools

from flask import Flask, flash, render_template, request, redirect, session, url_for
from flask_wtf import Form
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, Email
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_

from datetime import datetime


ADMIN_PASSWORD = 'secret'

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'joseas'
db = SQLAlchemy()


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


class BlogpostForm(Form):
    title = StringField('Title', validators=[DataRequired(), Length(min=6, max=40)])
    subtitle = StringField('Subtitle', validators=[DataRequired(), Length(min=6, max=40)])
    author = StringField('Author', validators=[DataRequired(), Length(min=6, max=20)])
    content = TextAreaField('Enter your blog post here', validators=[DataRequired()])


@app.route('/')
def index():

    page = request.args.get('page', 1, type=int)
    posts = Blogpost.query.order_by(Blogpost.date_posted.desc()).paginate(page, 5, False)
    next_url = url_for('index', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('index', page=posts.prev_num) \
        if posts.has_prev else None

    return render_template('index.html', posts=posts.items, next_url=next_url, prev_url=prev_url)


def login_required(fn):
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        if session.get('logged_in'):
            return fn(*args, **kwargs)
        return redirect(url_for('login', next=request.path))
    return inner


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and request.form.get('password'):
        password = request.form.get('password')
        # TODO: If using a one-way hash, you would also hash the user-submitted
        # password and do the comparison on the hashed versions.
        if password == ADMIN_PASSWORD:
            session['logged_in'] = True
            session.permanent = True  # Use cookie to store session.
            flash('You are now logged in.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Incorrect password.', 'danger')
    return render_template('login.html')


@app.route('/logout/', methods=['GET', 'POST'])
@login_required
def logout():
    if request.method == 'POST':
        session.clear()
        flash('You are no longer logged in.', 'success')
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
            author = form.author.data
            content = form.content.data

            post = Blogpost(title=title, subtitle=subtitle, author=author, content=content, date_posted=datetime.now())

            db.session.add(post)
            db.session.commit()
            return redirect(url_for('index'))
    return render_template('home.html')


if __name__ == '__main__':
    db.init_app(app)
    app.run(debug=True)
