from flask import Flask, request, redirect, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    urls = db.relationship('URL', backref='user', lazy=True)

class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(500), nullable=False)
    short_url = db.Column(db.String(10), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    click_count = db.Column(db.Integer, default=0)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template_string('''
        <h1>URL Shortener</h1>
        <form action="/shorten" method="POST">
            <input type="text" name="original_url" placeholder="Enter URL to shorten" required>
            <button type="submit">Shorten</button>
        </form>
        {% if short_url %}
        <p>Shortened URL: <a href="{{ short_url }}">{{ short_url }}</a></p>
        {% endif %}
        <a href="/login">Login</a> | <a href="/register">Register</a>
    ''', short_url=short_url())

@app.route('/shorten', methods=['POST'])
@login_required
def shorten_url():
    original_url = request.form['original_url']
    short_url = generate_short_url()
    new_url = URL(original_url=original_url, short_url=short_url, user_id=current_user.id)
    db.session.add(new_url)
    db.session.commit()
    return render_template_string('''
        <h1>URL Shortener</h1>
        <form action="/shorten" method="POST">
            <input type="text" name="original_url" placeholder="Enter URL to shorten" required>
            <button type="submit">Shorten</button>
        </form>
        <p>Shortened URL: <a href="{{ url_for('redirect_url', short_url=short_url) }}">{{ url_for('redirect_url', short_url=short_url) }}</a></p>
        <a href="/dashboard">Dashboard</a> | <a href="/logout">Logout</a>
    ''', short_url=url_for('redirect_url', short_url=short_url))

@app.route('/<short_url>')
def redirect_url(short_url):
    url = URL.query.filter_by(short_url=short_url).first_or_404()
    url.click_count += 1
    db.session.commit()
    return redirect(url.original_url)

@app.route('/dashboard')
@login_required
def dashboard():
    urls = URL.query.filter_by(user_id=current_user.id).all()
    return render_template_string('''
        <h1>Dashboard</h1>
        <table>
            <thead>
                <tr>
                    <th>Original URL</th>
                    <th>Short URL</th>
                    <th>Click Count</th>
                </tr>
            </thead>
            <tbody>
                {% for url in urls %}
                <tr>
                    <td>{{ url.original_url }}</td>
                    <td><a href="{{ url_for('redirect_url', short_url=url.short_url) }}">{{ url_for('redirect_url', short_url=url.short_url) }}</a></td>
                    <td>{{ url.click_count }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        <a href="/logout">Logout</a>
    ''', urls=urls)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')
    return render_template_string('''
        <h1>Register</h1>
        <form action="/register" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Register</button>
        </form>
        <a href="/login">Login</a>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect('/dashboard')
    return render_template_string('''
        <h1>Login</h1>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <a href="/register">Register</a>
    ''')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

def generate_short_url():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
