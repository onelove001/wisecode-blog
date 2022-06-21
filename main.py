from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import *
from functools import wraps
from sqlalchemy import Integer, ForeignKey
from flask_gravatar import Gravatar
import datetime
import os
import re

app = Flask(__name__)
# app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")

ckeditor = CKEditor(app)
Bootstrap(app)

uri = os.getenv("DATABASE_URL")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri


app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="blog_post_article")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment_author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    comment_text = db.Column(db.String(1000), nullable=False)
    blog_post_article_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    blog_post_article = relationship("BlogPost", back_populates="comments")


db.drop_all()
db.create_all()


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return wrapper


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    year = datetime.datetime.now().year
    posts = BlogPost.query.all()
    is_admin = False
    if current_user.is_authenticated and current_user.id == 1:
        is_admin = True
    return render_template("index.html", all_posts=posts, is_admin=is_admin, year=year)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    year = datetime.datetime.now().year
    if form.validate_on_submit():
        hashed_password = generate_password_hash(password=form.password.data, method="pbkdf2:sha256", salt_length=8)
        email = form.email.data
        if User.query.filter_by(email=email).first():
            flash("Email already exists!")
            return redirect(url_for('register'))
        else:
            new_user = User(email=email, password=hashed_password, name=form.name.data)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, year=year)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    year = datetime.datetime.now().year
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash("Invalid email address, Please try again")
            return redirect(url_for("login"))
        elif not check_password_hash(user.password, form.password.data):
            flash("Invalid password, please try again")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=form, year=year)


@login_required
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    year = datetime.datetime.now().year
    requested_post = BlogPost.query.get(post_id)
    post_comments = Comment.query.filter_by(blog_post_article_id=requested_post.id)
    form = CommentForm()
    is_admin = False
    if current_user.is_authenticated and current_user.id == 1:
        is_admin = True
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to register or login before you can make a comment!")
            return redirect(url_for('login'))
        new_comment = Comment(
            comment_author=current_user,
            blog_post_article=requested_post,
            comment_text=form.comment_body.data
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template("post.html", post=requested_post, form=form, is_admin=is_admin, post_comments=post_comments,
                           year=year)


@app.route("/about")
def about():
    year = datetime.datetime.now().year
    return render_template("about.html", year=year)


@app.route("/contact")
def contact():
    year = datetime.datetime.now().year
    return render_template("contact.html", year=year)


@app.route("/new-post", methods=["POST", "GET"])
@admin_required
def add_new_post():
    year = datetime.datetime.now().year
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, year=year)


@admin_required
@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
def edit_post(post_id):
    year = datetime.datetime.now().year
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author.name,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, year=year)


@admin_required
@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
