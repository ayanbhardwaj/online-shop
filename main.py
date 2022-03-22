from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegisterForm, LoginForm, AddItemForm
from functools import wraps
import stripe
stripe.api_key = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"

app = Flask(__name__)
app.config['SECRET_KEY'] = "rhdneriuvnsejrhfsskddjfseff457"
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cart.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Configure tables
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    item = relationship("Item", secondary="carts", back_populates="user")


class Item(db.Model):
    __tablename__ = "items"
    id = db.Column(db.Integer, primary_key=True)
    product_serial = db.Column(db.Integer, unique=True)
    product_name = db.Column(db.String(250), nullable=False)
    product_price = db.Column(db.Float, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    details = db.Column(db.Text, nullable=False)
    user = relationship("User", secondary="carts", back_populates="item")


class Cart(db.Model):
    __tablename__ = "carts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    item_id = db.Column(db.Integer, db.ForeignKey('items.id'))


db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_items():
    items = Item.query.all()
    c_items = 0
    if current_user.is_authenticated:
        c_items = len(Cart.query.filter_by(user_id=current_user.id).all())
    return render_template('index.html', items=items, c_items=c_items)


@app.route('/item/<int:item_id>', methods=['GET', 'POST'])
def item_detail(item_id):
    requested_item = Item.query.filter_by(id=item_id).first()
    c_items = 0
    if current_user.is_authenticated:
        c_items = len(Cart.query.filter_by(user_id=current_user.id).all())
    return render_template('item_detail.html', item=requested_item, c_items=c_items)


@app.route("/edit/<int:item_id>", methods=['GET', 'POST'])
@admin_only
def edit_item(item_id):
    c_items = 0
    if current_user.is_authenticated:
        c_items = len(Cart.query.filter_by(user_id=current_user.id).all())
    item = Item.query.get(item_id)
    edit_form = AddItemForm(
        product_serial=item.product_serial,
        product_name=item.product_name,
        product_price=item.product_price,
        img_url=item.img_url,
        details=item.details,
    )
    if edit_form.validate_on_submit():
        item.product_serial = edit_form.product_serial.data
        item.product_name = edit_form.product_name.data
        item.product_price = edit_form.product_price.data
        item.img_url = edit_form.img_url.data
        item.details = edit_form.details.data
        db.session.commit()
        return redirect(url_for("item_detail", item_id=item.id))
    return render_template("add_item.html", form=edit_form, c_items=c_items)


@app.route("/delete/<int:item_id>", methods=['GET'])
@admin_only
def delete_item(item_id):
    item_to_delete = Item.query.get(item_id)
    db.session.delete(item_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_items'))


@app.route("/add/cart/<int:item_id>", methods=['GET', 'POST'])
def add_to_cart(item_id):
    if current_user.is_authenticated:
        item = Item.query.get(item_id)
        item.user.append(current_user)
        db.session.commit()
    else:
        return redirect(url_for('login'))
    return redirect(url_for('get_all_items'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    c_items = 0
    if current_user.is_authenticated:
        c_items = len(Cart.query.filter_by(user_id=current_user.id).all())
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        email_check = User.query.filter_by(email=email).first()
        if email_check:
            flash("The email is already registered. Try log in instead.")
            return redirect(url_for('login'))
        salted_hashed_password = generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=8)
        name = form.name.data
        new_user = User(
            email=email,
            password=salted_hashed_password,
            name=name
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_items'))
    return render_template("register.html", form=form, c_items=c_items)


@app.route('/login', methods=['GET', 'POST'])
def login():
    c_items = 0
    if current_user.is_authenticated:
        c_items = len(Cart.query.filter_by(user_id=current_user.id).all())
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # Find user by email entered.
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Email is not registered. Enter correct email or register")
            return redirect(url_for('login'))

        # Check stored password hash against entered password hashed.
        if check_password_hash(pwhash=user.password, password=password):
            login_user(user)
            return redirect(url_for('get_all_items'))
        else:
            flash("Password incorrect. Please try again")
            return redirect(url_for('login'))

    return render_template("login.html", form=form, c_items=c_items)


@app.route("/new-item", methods=['GET', 'POST'])
@admin_only
def add_new_item():
    c_items = 0
    if current_user.is_authenticated:
        c_items = len(Cart.query.filter_by(user_id=current_user.id).all())
    form = AddItemForm()
    if form.validate_on_submit():
        new_item = Item(
            product_serial=form.product_serial.data,
            product_name=form.product_name.data,
            product_price=form.product_price.data,
            img_url=form.img_url.data,
            details=form.details.data,
        )
        db.session.add(new_item)
        db.session.commit()
        return redirect(url_for('get_all_items'))
    return render_template("add_item.html", form=form, c_items=c_items)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_items'))


@app.route('/showcart')
def cart():
    c_items = 0
    if current_user.is_authenticated:
        c_items = len(Cart.query.filter_by(user_id=current_user.id).all())
        all_items = Cart.query.filter_by(user_id=current_user.id).all()
        buy_items = []
        amount = 0
        for item in all_items:
            n = Item.query.get(item.item_id)
            buy_items.append(n)
            amount += n.product_price
    else:
        return redirect(url_for('login'))
    return render_template('cart.html', c_items=c_items, items=buy_items, amount=amount)


@app.route('/remove/<int:item_id>')
@login_required
def cart_item_remove(item_id):
    item_to_remove = Cart.query.filter_by(item_id=item_id).first()
    db.session.delete(item_to_remove)
    db.session.commit()
    return redirect(url_for('cart'))


@app.route('/create-checkout-session/<float:amount>', methods=['POST'])
def create_checkout_session(amount):
    rs = "{:.2f}".format(amount)
    new_amount = str(rs)
    value = new_amount.split('.')
    if int(value[1]) != 0:
        amt = value[0] + value[1]
    else:
        amt = value[0] + '00'
    session = stripe.checkout.Session.create(
        line_items=[{
            'price_data': {
                'currency': 'INR',
                'product_data': {
                    'name': 'Products',
                },
                'unit_amount': amt,
            },
            'quantity': 1,
        }],
        mode='payment',
        success_url=url_for('success', _external=True),
        cancel_url=url_for('failure', _external=True),
    )

    return redirect(session.url, code=303)


@app.route('/success')
def success():
    c_items = 0
    all_items = Cart.query.filter_by(user_id=current_user.id).all()
    for item in all_items:
        db.session.delete(item)
    db.session.commit()
    return render_template('success.html', c_items=c_items)


@app.route('/failure')
def failure():
    c_items = 0
    if current_user.is_authenticated:
        c_items = len(Cart.query.filter_by(user_id=current_user.id).all())
    return render_template('failure.html', c_items=c_items)


if __name__ == "__main__":
    app.run(debug=True)
