from flask import Flask, render_template, redirect, url_for, request, session, flash
from passlib.hash import bcrypt
from flask_sqlalchemy import SQLAlchemy

# Инициализация приложения
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Замените на уникальный ключ
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# Модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


# Маршрут для главной страницы
@app.route('/')
def home():
    return render_template('index.html')


# Маршрут для регистрации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.hash(password)

        new_user = User(username=username, email=email, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('Error: User with this email already exists.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')


# Маршрут для входа в систему
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.verify(password, user.password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('You have successfully logged in!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')


# Маршрут для выхода из системы
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# Маршрут для редактирования профиля пользователя
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('You must be logged in to access this page.', 'warning')
        return redirect(url_for('login'))

    user = User.query.filter_by(id=session['user_id']).first()

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        new_password = request.form['password']

        # Проверяем, был ли введен новый пароль
        if new_password:
            user.password = bcrypt.hash(new_password)

        try:
            db.session.commit()
            flash('Profile updated successfully.', 'success')
        except:
            db.session.rollback()  # Откатываем изменения в случае ошибки
            flash('An error occurred. Please try again.', 'danger')

    return render_template('profile.html', user=user)


# Создаем базу данных и запускаем приложение
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
