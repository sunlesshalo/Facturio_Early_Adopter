from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length

class OnboardingForm(FlaskForm):
    smartbill_email = StringField('SmartBill Email', validators=[DataRequired(), Email()])
    smartbill_token = StringField('SmartBill Token', validators=[DataRequired()])
    cif = StringField('CIF', validators=[DataRequired()])
    default_series = StringField('Default Invoice Series', validators=[DataRequired()])
    stripe_api_key = StringField('Stripe API Key', validators=[DataRequired()])
    submit = SubmitField('Conectare la SmartBill', render_kw={"id": "connect-smartbill-btn"})

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ChangePasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Change Password')
