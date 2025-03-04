import os
import time
import requests
import psutil
import pandas as pd
import sqlite3
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import socket
import smtplib
from twilio.rest import Client
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
from threading import Thread

app = Flask(__name__)
app.secret_key = 'supersecretkey'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Twilio credentials (update with your own)
account_sid = 'ACd9392596d8afb62c3fdd2c09ff9db993'
auth_token = '635eb3331748135d23160e03aec3aa26'
twilio_number = '+13313168917'
my_phone_number = '+918618815497'

# Email credentials (update with your own)
MODERATOR_EMAIL = "deekshajagadeesh13@gmail.com" #add receiver email
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USERNAME = "" #add your email
EMAIL_PASSWORD = "" #add your email pwd

# Central server details
CENTRAL_SERVER_IP = "192.168.19.228"  # Replace with the actual IP address or hostname
CENTRAL_SERVER_PORT = 5000

DOWNLOAD_DIRECTORY = r"C:\Users\Admin\Downloads"  # Using raw string
ANOMALY_THRESHOLD = 1024 * 1024 * 1024  # 1GB threshold in bytes

# Define roles and access policies
roles = {
    'Admin': ['EmployeeData', 'PerformanceReports', 'TechnicalLogs', 'HRRecords'],
    'Manager': ['EmployeeData', 'PerformanceReports'],
    'Employee': ['EmployeeData'],
    'HR': ['EmployeeData', 'HRRecords'],
    'ITSupport': ['TechnicalLogs']
}

# Default role for the single user
default_role = 'Admin'  # Change this based on the required role

# Function to initialize the database
def init_db():
    conn = sqlite3.connect('rbac.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

    # Insert test users with different roles
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password, role) 
        VALUES ('admin', 'admin', 'Admin'),
               ('manager', 'manager', 'Manager'),
               ('employee', 'employee', 'Employee'),
               ('viewer', 'viewer', 'Viewer')
    ''')

    conn.commit()
    conn.close()

# Create sample datasets
employee_data = pd.DataFrame({
    'EmployeeID': [1, 2, 3],
    'Name': ['Alice', 'Bob', 'Charlie'],
    'Role': ['Manager', 'Employee', 'HR'],
    'Department': ['Sales', 'Engineering', 'HR']
})

performance_reports = pd.DataFrame({
    'ReportID': [1, 2],
    'EmployeeID': [1, 2],
    'Performance': ['Excellent', 'Good']
})

technical_logs = pd.DataFrame({
    'LogID': [1, 2],
    'System': ['Server1', 'Database'],
    'Message': ['Error', 'Access Denied']
})

hr_records = pd.DataFrame({
    'RecordID': [1, 2],
    'EmployeeID': [1, 3],
    'Details': ['Salary', 'Address']
})

# Save datasets to SQLite
conn = sqlite3.connect('rbac.db')

employee_data.to_sql('EmployeeData', conn, if_exists='replace', index=False)
performance_reports.to_sql('PerformanceReports', conn, if_exists='replace', index=False)
technical_logs.to_sql('TechnicalLogs', conn, if_exists='replace', index=False)
hr_records.to_sql('HRRecords', conn, if_exists='replace', index=False)

conn.close()

# Function to check access
def check_access(role, dataset):
    if dataset in roles.get(role, []):
        return True
    else:
        return False

# Function to get data
def get_data(role, dataset):
    if check_access(role, dataset):
        conn = sqlite3.connect('rbac.db')
        query = f"SELECT * FROM {dataset}"
        data = pd.read_sql_query(query, conn)
        conn.close()
        return data
    else:
        return None

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('rbac.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(id=user[0], username=user[1], role=user[3])
    return None

# Forms for login
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Forms for registration
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[('Admin', 'Admin'), ('Manager', 'Manager'), ('Employee', 'Employee'), ('HR', 'HR'), ('ITSupport', 'ITSupport')], validators=[DataRequired()])
    submit = SubmitField('Register')

# Function to get IP address
def get_ip_address():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

# Function to send email
def send_email(subject, message):
    ip_address = get_ip_address()  # Get the IP address
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USERNAME
    msg['To'] = MODERATOR_EMAIL
    msg['Subject'] = f"Anomalies Detected on {ip_address}" 

    # Create HTML content for the email
    html_content = f"""
    <html>
    <body>
        <h2>{subject}</h2>
        <p>{message}</p>
    </body>
    </html>
    """
    
    # Attach HTML content to the email
    msg.attach(MIMEText(html_content, 'html'))

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
    text = msg.as_string()
    server.sendmail(EMAIL_USERNAME, MODERATOR_EMAIL, text)
    server.quit()

# Function to send log data to central server
def send_log_to_central_server(log_data):
    try:
        response = requests.post(f"http://{CENTRAL_SERVER_IP}:{CENTRAL_SERVER_PORT}/log", json=log_data)
        response.raise_for_status()
        print("Log sent to central server successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send log to central server: {e}")

# Function to collect system metrics
def get_system_metrics():
    cpu_usage = psutil.cpu_percent(interval=1)  # Get CPU usage percentage
    memory_info = psutil.virtual_memory()
    memory_usage = memory_info.used / (1024 ** 2)  # Convert bytes to MB
    disk_io = psutil.disk_io_counters()
    disk_io_operation = disk_io.read_count + disk_io.write_count
    
    return {
        "timestamp": datetime.now(),
        "CPU Usage": cpu_usage,
        "Memory Usage": memory_usage,
        "Disk I/O Operation": disk_io_operation
    }

# Function to collect metrics over time and save to a CSV file
def collect_metrics_over_time(duration=60, interval=1):
    metrics_list = []
    end_time = datetime.now() + timedelta(seconds=duration)
    while datetime.now() < end_time:
        metrics = get_system_metrics()
        metrics_list.append(metrics)
        # Keep only the last 20 entries
        if len(metrics_list) > 20:
            metrics_list.pop(0)
        time.sleep(interval)
    
    df = pd.DataFrame(metrics_list)
    df.to_csv('new_log_data.csv', index=False)
    
    return df

# Function to perform anomaly detection
def detect_anomalies():
    # Load the log data from CSV file
    log_data = pd.read_csv("log_data.csv")

    # Convert timestamp to datetime format
    log_data['timestamp'] = pd.to_datetime(log_data['timestamp'])

    # Set the datetime column as the index
    log_data.set_index('timestamp', inplace=True)

    # Extract relevant features from log data
    features = ['CPU Usage', 'Memory Usage', 'Disk I/O Operation']
    X_train = log_data[features]

    # Train an Isolation Forest model
    iforest = IsolationForest(contamination=0.1)  # adjust contamination parameter as needed
    iforest.fit(X_train)

    # Load new log data from CSV file
    new_log_data = pd.read_csv("new_log_data.csv")

    # Convert timestamp to datetime format
    new_log_data['timestamp'] = pd.to_datetime(new_log_data['timestamp'])

    # Set the datetime column as the index
    new_log_data.set_index('timestamp', inplace=True)

    # Extract relevant features from new log data
    X_new = new_log_data[features]

    # Make predictions on the new log data
    anomaly_score = iforest.decision_function(X_new)

    # Filter the new log data based on anomaly scores
    anomaly_threshold = 0 # Adjust the threshold as needed
    anomaly_indices = anomaly_score < anomaly_threshold
    anomalous_data = new_log_data[anomaly_indices]

    # Send email with anomalies
    if not anomalous_data.empty:
        # Format anomalies as an HTML table
        anomalies_html = anomalous_data.to_html()
        send_email("Anomalies Detected", anomalies_html)
        print("Email sent with anomalies.")
    else:
        print("No anomalies detected.")

    # Display the anomalous data and their corresponding anomaly scores
    print("Anomalous Data and Anomaly Scores:")
    print(anomalous_data)
    print("Anomaly Scores:")
    print(anomaly_score[anomaly_indices])

# Function to monitor USB and downloads
def monitor_usb_downloads():
    ip_address = get_ip_address()
    if not os.path.exists(DOWNLOAD_DIRECTORY):
        os.makedirs(DOWNLOAD_DIRECTORY)
    
    anomalies = []  # List to store detected anomalies

    while True:
        # Get list of files in the download directory
        files = os.listdir(DOWNLOAD_DIRECTORY)
        
        for file in files:
            file_path = os.path.join(DOWNLOAD_DIRECTORY, file)
            # Check if the file is a regular file
            if os.path.isfile(file_path):
                # Check if the file size exceeds the threshold or if it's an .exe file
                if os.path.getsize(file_path) > ANOMALY_THRESHOLD or file.endswith('.exe'):
                    print(f"Potential data leakage detected: {file}")
                    anomalies.append(f"Potential data leakage detected: {file}")
                    
                    # Send alert via Twilio
                    client = Client(account_sid, auth_token)
                    message_body = f"Potential data leakage detected: {file} at {ip_address}"
                    message = client.messages.create(
                        body=message_body,
                        from_=twilio_number,
                        to=my_phone_number
                    )

        # Check if anomalies were detected
        if anomalies:
            # Send an email with the summary of anomalies
            summary_message = "\n".join(anomalies)
            send_email("Anomalies Detected", summary_message)
            # Send the log to the central server
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_data = {"timestamp": timestamp, "ip_address": ip_address, "data": anomalies}
            send_log_to_central_server(log_data)
            anomalies = []  # Clear the list after sending the summary

        # Check for USB devices
        for partition in psutil.disk_partitions():
            if 'removable' in partition.opts:
                print("USB connected")
                send_email("USB Connected", "A USB device was connected to the system.")
                # Send alert via Twilio
                client = Client(account_sid, auth_token)
                message_body = f"USB Connected at {ip_address}"
                message = client.messages.create(
                    body=message_body,
                    from_=twilio_number,
                    to=my_phone_number
                )

        print("Recheck in progress....")
        # Sleep for some time before checking again
        time.sleep(10)  # Check every 10 seconds

# Route to display datasets
@app.route('/')
@login_required
def index():
    role = current_user.role
    datasets = roles.get(role, [])
    return render_template('index.html', roles=roles.keys(), datasets=datasets, role=role)

# Route to handle access requests
@app.route('/access', methods=['POST'])
@login_required
def access():
    role = current_user.role
    dataset = request.form['dataset']
    if check_access(role, dataset):
        data = get_data(role, dataset)
        if data is not None:
            return render_template('index.html', roles=roles.keys(), datasets=roles.get(role, []), data=data.to_html(index=False), role=role, dataset=dataset)
        else:
            flash(f"Access Denied for role {role} to dataset {dataset}")
            return redirect(url_for('index'))
    else:
        flash(f"Access Denied for role {role} to dataset {dataset}")
        return redirect(url_for('index'))

# Route to run anomaly detection
@app.route('/anomaly_detection')
@login_required
def anomaly_detection():
    if current_user.role not in ['Admin', 'Manager']:
        flash('Access Denied')
        return redirect(url_for('index'))
    
    # Collect new system metrics before running anomaly detection
    collect_metrics_over_time()
    detect_anomalies()
    return render_template('index.html', roles=roles.keys(), datasets=roles.get(current_user.role, []), anomaly_detection=True)

# Route to start USB and download anomaly monitoring
@app.route('/usb_download_monitoring')
@login_required
def usb_download_monitoring():
    if current_user.role not in ['Admin', 'Manager']:
        flash('Access Denied')
        return redirect(url_for('index'))
    
    # Start a new thread for monitoring USB and downloads
    thread = Thread(target=monitor_usb_downloads)
    thread.start()
    return render_template('index.html', roles=roles.keys(), datasets=roles.get(current_user.role, []), usb_download_monitoring=True)

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        role = form.role.data

        conn = sqlite3.connect('rbac.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if user:
            flash('Username already exists. Please choose a different username.')
            return redirect(url_for('register'))

        cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, password, role))
        conn.commit()
        conn.close()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        conn = sqlite3.connect('rbac.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            user_obj = User(id=user[0], username=user[1], role=user[3])
            login_user(user_obj)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template('login.html', form=form)

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)