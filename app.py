import os
from datetime import datetime, date, timedelta
import datetime as dt
from calendar import monthrange, Calendar
from flask import Flask, render_template, url_for, flash, redirect, request, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import g
from flask import session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import webview
import threading
import time
from flask_session import Session  # pip install Flask-Session
import bcrypt  # pip install bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, TimeField, TextAreaField, SelectField, HiddenField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_wtf.file import FileAllowed, FileField
from PIL import Image
import secrets



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///company.db'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))  # Environment variable for security
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

csrf = CSRFProtect(app)  # Initialize CSRF protection
app.config['CSRF_ENABLED'] = True  # Enable CSRF protection

db = SQLAlchemy(app)
Session(app)  # Initialize Flask-Session

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Where to redirect unauthenticated users

# --- Database Models ---
class Employee(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)  # Store hash, not plaintext!
    role = db.Column(db.String(20), default='employee')  # 'admin' or 'employee'
    profile_picture = db.Column(db.String(255), nullable=True)
    mobile_number = db.Column(db.String(20))  # New mobile_number column
    attendance = db.relationship('Attendance', backref='employee', lazy=True)
    messages_sent = db.relationship('Message', backref='sender', foreign_keys='[Message.sender_id]', lazy=True)
    messages_received = db.relationship('Message', backref='recipient', foreign_keys='[Message.recipient_id]', lazy=True)
    meetings = db.relationship('Meeting', backref='employee', lazy=True)

    def __repr__(self):
        return f"Employee('{self.name}', '{self.email}')"

    def set_password(self, password):
        """Hashes the password using bcrypt."""
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

    def is_admin(self):
        return self.role == 'admin'


class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=True)  # Nullable for "everyone"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    content = db.Column(db.Text, nullable=False)

    sender = db.relationship('Employee', foreign_keys=[sender_id], backref='chats_sent')
    recipient = db.relationship('Employee', foreign_keys=[recipient_id], backref='chats_received')


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time_in = db.Column(db.Time)
    time_out = db.Column(db.Time)

    def __repr__(self):
        return f"Attendance('{self.date}', '{self.time_in}', '{self.time_out}')"

class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(100))
    description = db.Column(db.Text)
    event_type = db.Column(db.String(20), default='personal')  # Add event_type column

    def __repr__(self):
        return f"Meeting('{self.title}', '{self.date}')"

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    content = db.Column(db.Text, nullable=False)

# --- Forms ---

class ChatForm(FlaskForm):
    content = TextAreaField('Message', validators=[DataRequired()])
    recipient_id = SelectField('Send To', coerce=int, choices=[(0, 'Everyone')], validators=[DataRequired()])
    submit = SubmitField('Send')

class LoginForm(FlaskForm):
    employee_id = StringField('Employee ID', validators=[DataRequired()],render_kw={'placeholder': 'Employee ID'})
    password = PasswordField('Password', validators=[DataRequired()],render_kw={'placeholder': 'Password'})
    # remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class MeetingForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()])
    time = TimeField('Time', validators=[DataRequired()])
    location = StringField('Location')
    description = TextAreaField('Description')
    event_type = SelectField('Event Type', choices=[('personal', 'Personal'), ('business', 'Business'), ('family', 'Family'), ('holiday', 'Holiday'), ('etc', 'ETC')])
    submit = SubmitField('Create Meeting')

class EmployeeForm(FlaskForm):
    employee_id = StringField('Employee ID', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8,message="Password must be atleast 8 characters long")])
    role = SelectField('Role', choices=[('employee', 'Employee'), ('admin', 'Admin')], validators=[DataRequired()])
    mobile_number = StringField('Mobile Number')  # New mobile_number field
    submit = SubmitField('Create Employee')

    def validate_employee_id(self, employee_id):
        employee = Employee.query.filter_by(employee_id=employee_id.data).first()
        if employee:
            raise ValidationError('That employee ID is already taken.')

    def validate_email(self, email):
        employee = Employee.query.filter_by(email=email.data).first()
        if employee:
            raise ValidationError('That email is already taken.')
    
    

class MessageForm(FlaskForm):
    content = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send Message')

class AttendanceForm(FlaskForm):
    date = HiddenField('Date', validators=[DataRequired()])

class EditProfileForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    mobile_number = StringField('Mobile Number')
    profile_picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'jpeg', 'png'], 'Images only!')])
    submit = SubmitField('Update Profile')

    def validate_email(self, email):
        employee = Employee.query.filter_by(email=email.data).first()
        if employee is not None and employee.id != current_user.id:
            raise ValidationError('That email is already taken.')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')


def save_picture(form_picture):
    # 1. Open the image using Pillow
    try:
        img = Image.open(form_picture)
    except Exception as e:
        print(f"Error opening image: {e}")
        return None  # Or raise the exception, depending on how you want to handle it
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static','profile_pics', picture_fn)

    try:
        img.save(picture_path) # This saves to filepath rather than raw bytes into the databas
        return picture_fn # only return the filename
    except Exception as e:
        print(f"Error saving image: {e}")
        return None

    return picture_path #return file path


@app.context_processor
def inject_user():
    return dict(current_user=current_user)


#Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return Employee.query.get(int(user_id))
# --- Authentication Routes ---
@app.route("/", methods=['GET', 'POST'])
@app.route("/login", methods=['GET', 'POST'])
@csrf.exempt
def login():
    form = LoginForm()
    if form.validate_on_submit():
        employee = Employee.query.filter_by(employee_id=form.employee_id.data).first()
        if employee and employee.check_password(form.password.data):
            login_user(employee)
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')
    return render_template('login.html', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# --- Employee Routes ---

@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
    employee = current_user
    form = AttendanceForm()
    today = date.today()  # Get today's date
    #check if Attendance is already marked or not
    attendance_marked = Attendance.query.filter_by(employee_id=employee.id, date=today).first()

    return render_template('dashboard.html',employee = current_user, form=form, attendance_marked = attendance_marked )


@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    employee = current_user
    attendance = AttendanceForm()
    today = date.today()  # Get today's date
    #check if Attendance is already marked or not
    attendance_marked = Attendance.query.filter_by(employee_id=employee.id, date=today).first()

    # Fetch upcoming meetings
    now = datetime.now(dt.UTC)
    meetings = Meeting.query.filter_by(employee_id=employee.id).filter(Meeting.date >= now).order_by(Meeting.date).limit(5).all()# Limit to 5 upcoming meetings
    
    
    form = EditProfileForm(obj=current_user)  # Initialize form with current user data
    users = Employee.query.all()
    if form.validate_on_submit():
        if form.profile_picture.data: # Check if the image has been changed
            picture_file = save_picture(form.profile_picture.data)
            if picture_file:
                current_user.profile_picture = picture_file #save filename to db

        current_user.name = form.name.data
        current_user.email = form.email.data
        current_user.mobile_number = form.mobile_number.data
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', employee=employee, meetings=meetings, form=form, attendance_marked = attendance_marked, users = users, attendance = attendance)

#@login_required
@app.route("/mark_attendance/<int:employee_id>", methods=['POST'])
@login_required
def mark_attendance(employee_id):
    if current_user.id != employee_id:
        return jsonify({'message': 'Unauthorized', 'status': 'error'}), 403
    try:
        today = date.today()
        user = Employee.query.get(employee_id)

        if not user:
            return jsonify({'message': 'Invalid employee ID!', 'status': 'error'}), 400

        employee_id = user.id
        attendance_marked = Attendance.query.filter_by(employee_id=employee_id, date=today).first()

        if not attendance_marked:
            new_attendance = Attendance(
                employee_id=employee_id,
                date=today,
                time_in=datetime.now().time() # Adjusted datetime handling
            )
            db.session.add(new_attendance)
            db.session.commit()
            return jsonify({'message': 'Attendance marked successfully!', 'status': 'success'})
        else:
            return jsonify({'message': 'Attendance already marked!', 'status': 'info'})
    except Exception as e:
        print('Error:', e)  # Log error for debugging
        return jsonify({'message': 'An error occurred.', 'status': 'error'}), 500

@app.route("/attendance")
@login_required
def attendance():
    employee = current_user
    attendances = Attendance.query.filter_by(employee_id=employee.id).all()
    return render_template('attendance.html', attendances=attendances)

@app.route("/meetings")
@login_required
def meetings():
    employee = current_user
    meetings = Meeting.query.filter_by(employee_id=employee.id).all()
    return render_template('meetings.html', meetings=meetings)

@app.route("/inbox")
@login_required
def inbox():
    employee = current_user
    messages = Message.query.filter(Message.recipient_id == employee.id).order_by(Message.timestamp.desc()).all()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':  # Detect AJAX request
        return render_template('message_list.html', messages=messages)  # Render only the message list
    else:
        return render_template('inbox.html', messages=messages)  # Render the full page

@app.route("/send_message/<int:recipient_id>", methods=['POST'])
@login_required
def send_message(recipient_id):
    if not current_user.is_admin():
         return jsonify({'message': 'You are not allowed', 'status': 'error'})
    form = MessageForm()
    recipient = Employee.query.get_or_404(recipient_id)
    print(recipient_id)
    print(form.content.data)
    print(form.validate())
    print(form.errors)  # Print form errors to understand why validation is failing
    if form.validate():
        sender_id = current_user.id
        new_message = Message(sender_id=sender_id, recipient_id=recipient_id, content=form.content.data)
        db.session.add(new_message)
        db.session.commit()
        return jsonify({'message': 'sent', 'status': 'success'})
        #return redirect(url_for('admin'))
    else:
        return jsonify({'message': 'some Error', 'status': 'error'})

# --- Admin Routes ---
@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin():
        flash("You are not authorized to access this page.", "danger")
        return redirect(url_for("profile"))
    employees = Employee.query.all()
    return render_template('admin.html', employees=employees)

@app.route("/admin/employee/<int:employee_id>")
@login_required
def view_employee_profile(employee_id):
    if not current_user.is_admin():
        flash("You are not authorized to view employee profiles.", "danger")
        return redirect(url_for("profile"))

    employee = Employee.query.get_or_404(employee_id)
    now = datetime.now(dt.UTC)
    meetings = Meeting.query.filter_by(employee_id=employee.id).filter(Meeting.date >= now).order_by(Meeting.date).limit(5).all()
    return render_template('profile.html', employee=employee, meetings=meetings)  # Reuse the profile template

@app.route("/admin/employee/new", methods=['GET', 'POST'])
@login_required
def create_employee():
    if not current_user.is_admin():
        return jsonify({'message': 'Unauthorized', 'status': 'error'})

    form = EmployeeForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        employee = Employee(employee_id=form.employee_id.data, name=form.name.data, email=form.email.data, password=hashed_password, role=form.role.data, mobile_number=form.mobile_number.data )
        db.session.add(employee)
        db.session.commit()
        employees = Employee.query.all()  # Fetch updated employee list
        return jsonify({'message': 'Employee created successfully!', 'status': 'success',
                        'html': render_template('employee_list.html', employees=employees)})
    return jsonify({'html': render_template('create_employee.html', form=form), 'status': 'form'})

@app.route("/admin/employee/<int:employee_id>/delete", methods=['POST'])
@login_required
def delete_employee(employee_id):
    if not current_user.is_admin():
        return jsonify({'message': 'Unauthorized', 'status': 'error'})

    employee = Employee.query.get_or_404(employee_id)
    if employee.role == 'admin' and employee.employee_id == 'admin':
        return jsonify({'message': 'Cannot delete the default admin!', 'status': 'error'})
    Attendance.query.filter_by(employee_id=employee.id).delete()
    Message.query.filter((Message.sender_id == employee.id) | (Message.recipient_id == employee.id)).delete()
    db.session.delete(employee)
    db.session.commit()
    employees = Employee.query.all()
    return jsonify({'message': 'Employee deleted successfully!', 'status': 'success',
                    'html': render_template('employee_list.html', employees=employees)})

@app.route("/admin/employee/<int:employee_id>/attendance", methods=['GET'])
@login_required
def view_employee_attendance(employee_id):
    if not current_user.is_admin():
        flash("You are not authorized to view attendance.", "danger")
        return redirect(url_for("profile"))

    employee = Employee.query.get_or_404(employee_id)
    attendances = Attendance.query.filter_by(employee_id=employee.id).all()
    return render_template('employee_attendance.html', employee=employee, attendances=attendances)

@app.route("/meetings_calender", methods=['GET', 'POST'])
@login_required
def meetings_calender():
     employee = current_user
     today = date.today()

     # Get the year and month from the request arguments, if provided.
     year = int(request.args.get('year', today.year))
     month = int(request.args.get('month', today.month))

     # Handle next and previous month navigation
     if request.form.get('action') == 'prev':
         month -= 1
         if month < 1:
             month = 12
             year -= 1
     elif request.form.get('action') == 'next':
         month += 1
         if month > 12:
             month = 1
             year += 1

     # Get the first day of the month and number of days in the month
     first_day = date(year, month, 1)
     num_days = monthrange(year, month)[1]

     # Get meetings for the month
     first = date(year,month,1)
     lastDay = date(year, month, num_days)
     meetings = Meeting.query.filter_by(employee_id=employee.id).filter(Meeting.date >= first).filter(Meeting.date <= lastDay).all()

     # Create a calendar instance
     cal = Calendar()

     # Group meetings by day
     meetings_by_day = {}
     for meeting in meetings:
         day = meeting.date.day
         if day not in meetings_by_day:
             meetings_by_day[day] = []
         meetings_by_day[day].append(meeting)

     # Generate the calendar days
     days = [d for d in cal.itermonthdates(year, month)]

     return render_template('calendar.html',
                           year=year,
                           month=month,
                           monthrange=monthrange, #Pass also Month Range
                           first_day=first_day,
                           days=days,
                           meetings_by_day=meetings_by_day,
                           range = range, #For Iterations in loops
                           num_days = num_days,
                           employee=employee,
                           today=today)
     
@app.route("/meetings/new", methods=['GET', 'POST'])
@login_required
def create_meeting():
    form = MeetingForm()
    if form.validate_on_submit():
        employee_id = current_user.id
        meeting_date = datetime.combine(form.date.data, form.time.data)
        new_meeting = Meeting(employee_id=employee_id, title=form.title.data, date=meeting_date, location=form.location.data, description=form.description.data, event_type=form.event_type.data)
        db.session.add(new_meeting)
        db.session.commit()
        flash('Meeting created successfully!', 'success')
        return redirect(url_for('meetings'))
    return render_template('create_meeting.html', form=form)

@app.route("/meetings/<int:meeting_id>/delete", methods=['POST'])
@login_required
def delete_meeting(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)
    db.session.delete(meeting)
    db.session.commit()
    flash('Meeting deleted successfully!', 'success')
    return redirect(url_for('meetings'))

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(obj=current_user)  # Initialize form with current user data
    users = Employee.query.all()
    if form.validate_on_submit():
        if form.profile_picture.data: # Check if the image has been changed
            picture_file = save_picture(form.profile_picture.data)
            if picture_file:
                current_user.profile_picture = picture_file #save filename to db

        current_user.name = form.name.data
        current_user.email = form.email.data
        current_user.mobile_number = form.mobile_number.data
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))  # Redirect back to profile page
    return render_template('edit_profile.html', form=form, users = users)


@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    form = ChatForm()
    # Populate recipient choices (exclude current user)
    form.recipient_id.choices = [(0, 'Everyone')] + [(e.id, e.name) for e in Employee.query.filter(Employee.id != current_user.id).all()]
    messages = Chat.query.order_by(Chat.timestamp.desc()).limit(50).all() # change limit and add filter

    if form.validate_on_submit():
        recipient_id = form.recipient_id.data if form.recipient_id.data != 0 else None
        new_message = Chat(sender_id=current_user.id, recipient_id=recipient_id, content=form.content.data)
        db.session.add(new_message)
        db.session.commit()
        return redirect(url_for('chat'))  # Or use AJAX to update the display
    
    return render_template('chat.html', form=form, messages=messages)

@app.route('/get_messages', methods=['GET'])
@login_required
def get_messages():
    messages = Chat.query.order_by(Chat.timestamp.desc()).limit(50).all() #Add query parameters

    messages_list = []
    for message in messages:
         messages_list.append({
               'sender': message.sender.name,
               'content': message.content,
               'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
          })

    return jsonify(messages_list)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.old_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Your password has been changed!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid old password.', 'danger')
    return render_template('change_password.html', form=form)


def start_server():
    app.run(debug=True, host='0.0.0.0', port=5001)  # Be explicit about host and port

if __name__ == '__main__':
    # --- Database setup ---
    with app.app_context():
        db.create_all()
        # Create admin user if it doesn't exist
        admin_user = Employee.query.filter_by(employee_id='admin').first()
        if not admin_user:
            admin_user = Employee(employee_id='admin', name='Harsh Raj Jaiswal', email='jaiswal.harshraj1601@gmail.com', role='admin')
            admin_user.set_password('password')  # USE A STRONG PASSWORD!
            db.session.add(admin_user)
            db.session.commit()
        start_server()
    # --- Start Flask server in a thread ---
    # t = threading.Thread(target=start_server)
    # t.daemon = True
    # t.start()
    # time.sleep(1)  # Give the server a moment to start

    # --- Create and run WebView window ---
    # webview.create_window("Company App", "http://127.0.0.1:5000/",maximized=True, resizable=False)
    # webview.start()