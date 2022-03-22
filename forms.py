from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


# register wtf form
class RegisterForm(FlaskForm):
    email = EmailField(label="Email", validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    name = StringField(label="Name", validators=[DataRequired()])
    submit = SubmitField(label="SIGN ME UP")


# login wtf form
class LoginForm(FlaskForm):
    email = EmailField(label="Email", validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    submit = SubmitField(label="LOG IN")


class AddItemForm(FlaskForm):
    product_serial = StringField("Product Serial", validators=[DataRequired()])
    product_name = StringField("Product Name", validators=[DataRequired()])
    product_price = StringField("Price", validators=[DataRequired()])
    img_url = StringField("Product Image URL", validators=[DataRequired(), URL()])
    details = CKEditorField("Product Details", validators=[DataRequired()])
    submit = SubmitField("Add Item")