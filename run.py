
from flask import Flask, render_template, request, redirect, url_for, session
from functools import wraps
import hashlib
import requests
import sqlite3
from datetime import datetime
import os

# Correct datetime adapter registration
sqlite3.register_adapter(datetime, lambda val: val.isoformat())
sqlite3.register_converter('datetime', lambda val: datetime.fromisoformat(val.decode()))


app = Flask(__name__)

# Initialize SQLite database for tracking
def init_db():
    conn = sqlite3.connect('visitor_tracking.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS visitors 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp DATETIME,
                  ip_address TEXT,
                  user_agent TEXT,
                  referrer TEXT,
                  country TEXT,
                  city TEXT,
                  browser TEXT,
                  os TEXT,
                  device_type TEXT)''')
    conn.commit()
    conn.close()



def get_geolocation(ip_address):
    if ip_address in ['127.0.0.1', '::1']:  # local development IPs
        return 'Local', 'Localhost'
    
    try:
        # Use ipapi.co for free geolocation lookup
        response = requests.get(f'https://ipapi.co/{ip_address}/json/').json()
        
        country = response.get('country_name', 'Unknown')
        city = response.get('city', 'Unknown')
        
        return country, city
    except Exception as e:
        print(f"Geolocation lookup failed: {e}")
        return 'Unknown', 'Unknown'

def send_telegram_notification(visitor_info):
    # Replace with your Telegram bot token
    BOT_TOKEN = '7102832474:AAEi07X_rdk45irD7uoyUYyKbVVgiYeaE1M'
    
    # Replace with your Telegram chat ID
    CHAT_ID = '999186130'
    
    message = f"""🌐 New Visitor Detected!
        IP: {visitor_info['ip_address']}
        Browser: {visitor_info['browser']}
        OS: {visitor_info['os']}
        Device: {visitor_info['device_type']}
        Country: {visitor_info['country']}
        City: {visitor_info['city']}
        Referrer: {visitor_info['referrer']}
        Timestamp: {visitor_info['timestamp']}
            """
    
    url = f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage'
    params = {
        'chat_id': CHAT_ID,
        'text': message
    }
    
    try:
        response = requests.post(url, params=params)
        print(response.json())
        return response.json()
    except Exception as e:
        print(f"Failed to send Telegram notification: {e}")
        return None

# Modify log_visitor function
def log_visitor():
    conn = sqlite3.connect('visitor_tracking.db')
    c = conn.cursor()
    
    # Get visitor information
    timestamp = datetime.now()
    ip_address = request.remote_addr
    user_agent_string = request.user_agent.string
    referrer = request.referrer or 'Direct'
    
    # Extract additional information
    from user_agents import parse
    user_agent = parse(user_agent_string)
    
    browser = f"{user_agent.browser.family} {user_agent.browser.version_string}"
    os = f"{user_agent.os.family} {user_agent.os.version_string}"
    device_type = user_agent.device.family
    
    # Get geolocation
    country, city = get_geolocation(ip_address)
    
    # Prepare visitor info dictionary
    visitor_info = {
        'timestamp': str(timestamp),
        'ip_address': ip_address,
        'browser': browser,
        'os': os,
        'device_type': device_type,
        'country': country,
        'city': city,
        'referrer': referrer
    }
    
    # Send Telegram notification
    send_telegram_notification(visitor_info)
    
    # Insert visitor information
    c.execute('''INSERT INTO visitors 
                 (timestamp, ip_address,  referrer, 
                  country, city, browser, os, device_type) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
              (timestamp, ip_address,  referrer, 
               country, city, browser, os, device_type))
    
    # Get total visitor count
    c.execute('SELECT COUNT(*) FROM visitors')
    total_visitors = c.fetchone()[0]
    
    conn.commit()
    conn.close()
    
    return total_visitors


@app.route('/')
def index():
    # Initialize database if not exists
    if not os.path.exists('visitor_tracking.db'):
        init_db()
    
    # Log visitor and get total count
    total_visitors = log_visitor()
    
    return render_template('index.html')

# Additional route to get visitor statistics
@app.route('/visitor_stats')
def visitor_stats():
    conn = sqlite3.connect('visitor_tracking.db')
    c = conn.cursor()
    
    # Get full table of visitors with all details
    c.execute('''SELECT * FROM visitors ORDER BY timestamp DESC''')
    full_visitor_table = c.fetchall()
    
    # Comprehensive referrer statistics
    c.execute('''SELECT referrer, 
                        COUNT(*) as count, 
                        ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM visitors), 2) as percentage
                 FROM visitors 
                 GROUP BY referrer 
                 ORDER BY count DESC''')
    referrer_stats = c.fetchall()
    
    # Daily visitor breakdown
    c.execute('''SELECT DATE(timestamp) as date, 
                        COUNT(*) as daily_visitors,
                        COUNT(DISTINCT ip_address) as unique_visitors
                 FROM visitors 
                 GROUP BY date 
                 ORDER BY date DESC 
                 LIMIT 30''')
    daily_stats = c.fetchall()
    
    # Browser breakdown
    c.execute('''SELECT browser, 
                        COUNT(*) as count, 
                        ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM visitors), 2) as percentage
                 FROM visitors 
                 GROUP BY browser 
                 ORDER BY count DESC''')
    browser_stats = c.fetchall()
    
    # OS breakdown
    c.execute('''SELECT os, 
                        COUNT(*) as count, 
                        ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM visitors), 2) as percentage
                 FROM visitors 
                 GROUP BY os 
                 ORDER BY count DESC''')
    os_stats = c.fetchall()
    
    conn.close()
    
    return {
        'full_visitor_table': full_visitor_table,
        'referrer_stats': referrer_stats,
        'daily_stats': daily_stats,
        'browser_stats': browser_stats,
        'os_stats': os_stats
    }
# @app.route('/visitor_dashboard')
# def visitor_dashboard():
#     conn = sqlite3.connect('visitor_tracking.db')
#     c = conn.cursor()
    
#     # Get full table of visitors with all details
#     c.execute('''SELECT * FROM visitors ORDER BY timestamp DESC''')
#     full_visitor_table = c.fetchall()
    
#     # Get column names
#     c.execute("PRAGMA table_info(visitors)")
#     columns = [column[1] for column in c.fetchall()]
    
#     conn.close()
    
#     return render_template('visitor_dashboard.html', 
#                            columns=columns, 
#                            visitors=full_visitor_table)

###login
# Set a secret key for sessions
app.secret_key = os.urandom(24)  # Generate a random secret key

# Configuration for admin access
ADMIN_USERNAME = 'adir'
ADMIN_PASSWORD = '659698'  # Consider using a more secure method like environment variables

def hash_password(password):
    """Hash the password for secure comparison"""
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    """Decorator to require login for specific routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if (username == ADMIN_USERNAME and 
            hash_password(password) == hash_password(ADMIN_PASSWORD)):
            session['logged_in'] = True
            return redirect(url_for('visitor_dashboard'))
        else:
            error = 'Invalid credentials'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/visitor_dashboard')
@login_required
def visitor_dashboard():
    conn = sqlite3.connect('visitor_tracking.db')
    c = conn.cursor()
    
    # Get full table of visitors with all details
    c.execute('''SELECT * FROM visitors ORDER BY timestamp DESC''')
    full_visitor_table = c.fetchall()
    
    # Get column names
    c.execute("PRAGMA table_info(visitors)")
    columns = [column[1] for column in c.fetchall()]
    
    conn.close()
    
    return render_template('visitor_dashboard.html', 
                           columns=columns, 
                           visitors=full_visitor_table)

###end login
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context=('assets\\fullchain.pem', 
                                                   'assets\\privkey.pem'))
