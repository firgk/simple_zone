from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from markupsafe import Markup
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
import uuid

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = 'mjqqsssaaawwwkwwwss' # 加密密钥
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # 图片上传目录
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 限制上传文件大小为16MB

# 确保上传目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_image', methods=['POST'])
@login_required
def upload_image():
    if 'image' not in request.files:
        return jsonify({'error': '没有文件被上传'}), 400
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'}), 400
    
    if file and allowed_file(file.filename):
        # 生成唯一的文件名
        filename = str(uuid.uuid4()) + '.' + file.filename.rsplit('.', 1)[1].lower()
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        # 返回可访问的URL
        return jsonify({
            'url': url_for('static', filename=f'uploads/{filename}', _external=True)
        })
    
    return jsonify({'error': '不支持的文件类型'}), 400

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    
    # Add cascade delete to both likes and comments
    likes = db.relationship('Like', backref='post', lazy=True, cascade="all, delete-orphan")
    comments = db.relationship('Comment', backref='post', lazy=True, cascade="all, delete-orphan")



class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    posts = Post.query.order_by(Post.date.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_post():
    if not current_user.is_admin:
        flash("Only admins can add posts!", "danger")
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        # title = request.form['title']
        content = request.form['content']
        new_post = Post(title='title', username=current_user.username, content=content)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('index'))
    
    # 如果请求方法是 GET，渲染添加文章的模板页面
    return render_template('add_post.html')

@app.route('/comment/<int:post_id>', methods=['POST'])
def add_comment(post_id):
    comment_text = request.form.get('comment_text')

    if not comment_text:
        flash("Comment cannot be empty!", "danger")
        return redirect(url_for('index'))

    # If user is logged in, use their username; otherwise, set as 'Anonymous'
    username = current_user.username if current_user.is_authenticated else "Anonymous"

    comment = Comment(post_id=post_id, username=username, content=comment_text)
    db.session.add(comment)
    db.session.commit()
    
    flash("Comment added successfully!", "success")
    return redirect(url_for('index'))




from flask_login import current_user

@app.route('/like/<int:post_id>', methods=['POST'])
def like_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Assign a default user_id for anonymous users (e.g., -1 for guest likes)
    user_id = current_user.id if current_user.is_authenticated else -1

    like = Like.query.filter_by(post_id=post_id, user_id=user_id).first()

    if like:
        db.session.delete(like)  # Unlike if already liked
        liked = False
    else:
        new_like = Like(post_id=post_id, user_id=user_id)
        db.session.add(new_like)
        liked = True

    db.session.commit()

    return jsonify({'success': True, 'likes': len(post.likes), 'liked': liked})



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid credentials!", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for('index'))

@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if not current_user.is_admin:
        flash("Only admins can edit posts!", "danger")
        return redirect(url_for('index'))
    if request.method == 'POST':
        # post.title = request.form['title']
        post.title = 'title'
        post.content = request.form['content']
        db.session.commit()
        flash("Post updated successfully!", "success")
        return redirect(url_for('index'))
    return render_template('edit_post.html', post=post)

@app.route('/delete/<int:post_id>', methods=['GET', 'POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    if not current_user.is_admin:
        flash("Only admins can delete posts!", "danger")
        return redirect(url_for('index'))
    # Delete comments first (if cascade doesn't work)
    Comment.query.filter_by(post_id=post.id).delete()
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully!", "success")
    return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        if not User.query.first():
            # 示例邮箱和密码
            email = 'firgk'
            password = 'yourpassword'
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username='firgk', email=email, password=hashed_password, is_admin=True)
            db.session.add(new_user)
            db.session.commit()

    app.run(debug=True)


