from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, validators
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField
from flask_wtf.recaptcha import RecaptchaField
from flask_wtf.file import FileField, FileAllowed


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    image = FileField("Blog Image", validators=[DataRequired(), FileAllowed(['jpg', 'png', 'jpeg'])])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    firstname = StringField("Firstname", validators=[DataRequired()])
    lastname = StringField("Lastname", validators=[DataRequired()])
    username = StringField("Set Username:", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    # recaptcha = RecaptchaField()
    submit = SubmitField("Sign Up!")

class ForgotForm(FlaskForm):
    email = StringField("Enter your Email", validators=[DataRequired()])
    submit = SubmitField("Send Code")

class EditForm(FlaskForm):
    firstname = StringField("Firstname", validators=[DataRequired()])
    lastname = StringField("Lastname", validators=[DataRequired()])
    username = StringField("Set Username:", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    submit = SubmitField("Edit Form")

class ResetForm(FlaskForm):
    new_password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm_password', message='Passwords must match')
    ])
    
    confirm_password = PasswordField('Confirm Password', [validators.DataRequired()])
    reset_code = StringField('', validators=[DataRequired()])
    submit = SubmitField("Reset Password")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class FreeSignalForm(FlaskForm):
    entry_point = StringField("Entry Point", validators=[DataRequired()])
    stop_loss = StringField("Stop Loss", validators=[DataRequired()])
    take_profit = StringField("Take Profit", validators=[DataRequired()])
    coin_symbol = StringField("Coin Symbol", validators=[DataRequired()])
    submit = SubmitField("Submit")

class VerifyForm(FlaskForm):
    reset_code = StringField("Verify Code", validators=[DataRequired()])
    submit = SubmitField("Verify")

class VipSignalForm(FlaskForm):
    entry_point = StringField("Entry Point", validators=[DataRequired()])
    stop_loss = StringField("Stop Loss", validators=[DataRequired()])
    take_profit = StringField("Take Profit", validators=[DataRequired()])
    coin_symbol = StringField("Coin Symbol", validators=[DataRequired()])
    submit = SubmitField("Submit")


class CommentForm(FlaskForm):
    comment_text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")

# class SubscribeForm(FlaskForm):

