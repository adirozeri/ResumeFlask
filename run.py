
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from functools import wraps
import hashlib
import requests
import sqlite3
from datetime import datetime, timedelta
import os
import socket
from user_agents import parse
import logging
from logging.handlers import RotatingFileHandler
import json
from dataclasses import dataclass
from typing import Optional, Dict, List
import secrets
import argparse

# Add this near the top of your file
def parse_args():
    parser = argparse.ArgumentParser(description='Run Flask application')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    return parser.parse_args()



# Data classes for type safety and better organization
@dataclass
class VisitorInfo:
    timestamp: datetime
    ip_address: str
    user_agent: str
    referrer: str
    country: str
    city: str
    browser: str
    browser_version: str
    os: str
    device_type: str
    is_bot: bool
    bot_confidence: float
    bot_reason: str
    request_frequency: int
    visit_pattern: str
    headers: Dict
    host_name: Optional[str]
    response_time: float
    screen_resolution: Optional[str]
    time_zone: Optional[str]
    language: Optional[str]
    visit_count: int

class Config:
    def __init__(self):
        self.ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME')
        self.ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
        self.BOT_TOKEN = os.environ.get('BOT_TOKEN')
        self.CHAT_ID = os.environ.get('CHAT_ID')
        if not os.environ.get('SECRET_KEY', secrets.token_hex(24)):
            raise ValueError("SECRET_KEY environment variable must be set")
        self.SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(24))

        self.DB_PATH = 'visitor_tracking.db'
        self.LOG_FILE = 'visitor_tracking.log'
        self.WHITELISTED_IPS = {'127.0.0.1', '46.120.215.131'}  # Add your IP here
        
        self.RATE_LIMIT = 30  # requests per minute
        
        self.validate()
    
    def validate(self):
        required_vars = {
            'ADMIN_USERNAME': self.ADMIN_USERNAME,
            'ADMIN_PASSWORD': self.ADMIN_PASSWORD,
            'BOT_TOKEN': self.BOT_TOKEN,
            'CHAT_ID': self.CHAT_ID
        }
        
        missing = [k for k, v in required_vars.items() if not v]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()
    
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        with self.get_connection() as conn:
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
                         browser_version TEXT,
                         os TEXT,
                         device_type TEXT,
                         is_bot BOOLEAN,
                         bot_confidence REAL,
                         bot_reason TEXT,
                         request_frequency INTEGER,
                         visit_pattern TEXT,
                         headers TEXT,
                         host_name TEXT,
                         response_time REAL,
                         screen_resolution TEXT,
                         time_zone TEXT,
                         language TEXT,
                         visit_count INTEGER)''')
            
            # Add indices for common queries
            c.execute('CREATE INDEX IF NOT EXISTS idx_ip_timestamp ON visitors(ip_address, timestamp)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_is_bot ON visitors(is_bot)')

class VisitorTracker:
    def __init__(self, config: Config, db: Database, args):
        self.config = config
        self.db = db
        self.setup_logging(args)
    
    def setup_logging(self,args):
        # args = parse_args()
        if args.debug:
            # For debug mode: Log to terminal
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s [%(levelname)s] %(message)s'
            )
        else:
            # For production: Log to file
            logging.basicConfig(
                handlers=[RotatingFileHandler(
                    self.config.LOG_FILE, 
                    maxBytes=1024*1024, 
                    backupCount=5
                )],
                level=logging.DEBUG,
                format='%(asctime)s [%(levelname)s] %(message)s'
            )
        self.logger = logging.getLogger(__name__)
    

    def is_rate_limited(self, ip_address: str, path: str = None) -> bool:
        # Don't rate limit whitelisted IPs
        if ip_address in self.config.WHITELISTED_IPS:
            return False
                
        now = datetime.now()
        with self.db.get_connection() as conn:
            c = conn.cursor()
            c.execute('''SELECT COUNT(*) FROM visitors 
                        WHERE ip_address = ? 
                        AND timestamp > datetime('now', '-1 minute')''', 
                    (ip_address,))
            count = c.fetchone()[0]
            return count > self.config.RATE_LIMIT


    def detect_bot(self, visitor_info: VisitorInfo) -> tuple[float, str]:
        reasons = []
        confidence = 0.0
        
        # Check for known bot user agents
        bot_indicators = ['bot', 'crawler', 'spider', 'scan']
        if any(ind in visitor_info.user_agent.lower() for ind in bot_indicators):
            reasons.append("Bot-like user agent")
            confidence += 0.8
        
        # Check request frequency
        if visitor_info.request_frequency > 60:  # More than 1 request per second
            reasons.append(f"High request frequency: {visitor_info.request_frequency}/min")
            confidence += 0.6
        
        # Check for datacenter IPs
        try:
            host = socket.gethostbyaddr(visitor_info.ip_address)[0].lower()
            datacenter_patterns = ['amazon', 'google', 'microsoft', 'digital ocean']
            if any(dc in host for dc in datacenter_patterns):
                reasons.append(f"Datacenter IP: {host}")
                confidence += 0.7
        except:
            pass
        
        # Normalize confidence to [0, 1]
        confidence = min(confidence, 1.0)
        
        return confidence, '; '.join(reasons) if reasons else "No bot indicators"
    
    def get_geolocation(self, ip_address: str) -> tuple[str, str]:
        if ip_address in ['127.0.0.1', '::1']:
            return 'Local', 'Localhost'
        
        try:
            response = requests.get(
                f'https://ipapi.co/{ip_address}/json/',
                timeout=5
            ).json()
            
            return (
                response.get('country_name', 'Unknown'),
                response.get('city', 'Unknown')
            )
        except Exception as e:
            self.logger.error(f"Geolocation error for {ip_address}: {e}")
            return 'Unknown', 'Unknown'
    
    def log_visitor(self, request) -> VisitorInfo:
        # Get real IP from X-Forwarded-For or X-Real-IP header
        ip_address = request.headers.get('X-Forwarded-For', request.headers.get('X-Real-IP', request.remote_addr))
        if ',' in ip_address:  # X-Forwarded-For can contain multiple IPs
            ip_address = ip_address.split(',')[0].strip()
        # Skip tracking for whitelisted IPs
        if ip_address in self.config.WHITELISTED_IPS:
            return None
    
        start_time = datetime.now()
        
        visitor_info = VisitorInfo(
            timestamp=start_time,
            ip_address=ip_address,
            user_agent=request.user_agent.string,
            referrer=request.referrer or 'Direct',
            country='Unknown',
            city='Unknown',
            browser='Unknown',
            browser_version='Unknown',
            os='Unknown',
            device_type='Unknown',
            is_bot=False,
            bot_confidence=0.0,
            bot_reason='',
            request_frequency=0,
            visit_pattern='',
            headers=dict(request.headers),
            host_name=None,
            response_time=0.0,
            screen_resolution=request.args.get('screen_res'),
            time_zone=request.args.get('timezone'),
            language=request.accept_languages.best,
            visit_count=1
        )
        
        # Parse user agent
        ua = parse(visitor_info.user_agent)
        visitor_info.browser = ua.browser.family
        visitor_info.browser_version = ua.browser.version_string
        visitor_info.os = f"{ua.os.family} {ua.os.version_string}"
        visitor_info.device_type = ua.device.family
        
        # Get geolocation
        visitor_info.country, visitor_info.city = self.get_geolocation(visitor_info.ip_address)
        
        # Calculate response time
        visitor_info.response_time = (datetime.now() - start_time).total_seconds()
        
        # Bot detection
        visitor_info.bot_confidence, visitor_info.bot_reason = self.detect_bot(visitor_info)
        visitor_info.is_bot = visitor_info.bot_confidence > 0.5
        
        # Store in database
        with self.db.get_connection() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO visitors 
                        (timestamp, ip_address, user_agent, referrer, 
                         country, city, browser, browser_version, os, device_type,
                         is_bot, bot_confidence, bot_reason, request_frequency,
                         visit_pattern, headers, host_name, response_time,
                         screen_resolution, time_zone, language, visit_count)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (visitor_info.timestamp, visitor_info.ip_address, 
                      visitor_info.user_agent, visitor_info.referrer,
                      visitor_info.country, visitor_info.city, 
                      visitor_info.browser, visitor_info.browser_version,
                      visitor_info.os, visitor_info.device_type,
                      visitor_info.is_bot, visitor_info.bot_confidence,
                      visitor_info.bot_reason, visitor_info.request_frequency,
                      visitor_info.visit_pattern, json.dumps(visitor_info.headers),
                      visitor_info.host_name, visitor_info.response_time,
                      visitor_info.screen_resolution, visitor_info.time_zone,
                      visitor_info.language, visitor_info.visit_count))
        
        # Log visit
        self.logger.info(
            f"Visit from {visitor_info.ip_address} "
            f"({'Bot' if visitor_info.is_bot else 'Human'}) "
            f"from {visitor_info.country}, {visitor_info.city}"
        )
        
        return visitor_info

def create_app(args):
    config = Config()
    db = Database(config.DB_PATH)
    tracker = VisitorTracker(config, db,args)
    
    app = Flask(__name__)
    app.secret_key = config.SECRET_KEY
    
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'logged_in' not in session:
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    # If you're using a before_request handler:

    @app.before_request
    def check_rate_limit():
        ip_address = request.headers.get('X-Forwarded-For', request.headers.get('X-Real-IP', request.remote_addr))
        if ',' in ip_address:  # X-Forwarded-For can contain multiple IPs
            ip_address = ip_address.split(',')[0].strip()
        
        path = request.path
        if tracker.is_rate_limited(ip_address, path):
            return 'Rate limit exceeded', 429
    

    # @app.before_request
    # def before_request():
    #     if tracker.is_rate_limited(request.remote_addr):
    #         return 'Rate limit exceeded', 429
    
    @app.route('/')
    def index():
        visitor_info  = tracker.log_visitor(request)
        return render_template('index.html')
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
             
            if (username == config.ADMIN_USERNAME and 
                hashlib.sha256(password.encode()).hexdigest() == 
                hashlib.sha256(config.ADMIN_PASSWORD.encode()).hexdigest()):
                session['logged_in'] = True
                return redirect(url_for('dashboard'))
            
            return render_template('login.html', error='Invalid credentials')
        
        return render_template('login.html')
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        with db.get_connection() as conn:
            c = conn.cursor()
            
            # Get overall statistics
            c.execute('''
                SELECT 
                    COUNT(*) as total_visits,
                    COUNT(DISTINCT ip_address) as unique_visitors,
                    SUM(CASE WHEN is_bot THEN 1 ELSE 0 END) as bot_visits,
                    COUNT(DISTINCT CASE WHEN is_bot THEN ip_address END) as unique_bots,
                    COALESCE(AVG(response_time), 0) as avg_response_time  
                FROM visitors
            ''')
            stats = dict(c.fetchone())
            
            # Get recent visitors
            c.execute('''
                SELECT * FROM visitors 
                ORDER BY timestamp DESC 
                LIMIT 50
            ''')
            visitors = [dict(row) for row in c.fetchall()]
            
            return render_template(
                'dashboard.html',
                stats=stats,
                visitors=visitors
            )
    @app.route('/logout')
    def logout():
        session.clear()  # Clear all session data
        return redirect(url_for('login'))

    @app.route('/api/stats')
    @login_required
    def get_stats():
        with db.get_connection() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT 
                    strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                    COUNT(*) as visits,
                    SUM(CASE WHEN is_bot THEN 1 ELSE 0 END) as bot_visits
                FROM visitors
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY hour
                ORDER BY hour
            ''')
            hourly_stats = [dict(row) for row in c.fetchall()]
            return jsonify(hourly_stats)

    @app.route('/api/referrer-stats')
    @login_required
    def get_referrer_stats():
        with db.get_connection() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT 
                    CASE 
                        WHEN referrer = '' OR referrer IS NULL THEN 'Direct'
                        ELSE referrer 
                    END as referrer,
                    COUNT(*) as count
                FROM visitors
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY referrer
                ORDER BY count DESC
                LIMIT 5
            ''')
            results = c.fetchall()
            referrer_stats = [{'referrer': row[0], 'count': row[1]} for row in results]
            return jsonify(referrer_stats)
    
    @app.route('/logs')
    @login_required
    def view_logs():
        page = request.args.get('page', 1, type=int)
        lines_per_page = 100  # Adjust this number as needed
        
        try:
            with open('visitor_tracking.log', 'r') as f:
                all_lines = f.readlines()
                # Reverse lines to show newest first
                all_lines.reverse()
                
                # Calculate pagination
                total_lines = len(all_lines)
                total_pages = (total_lines + lines_per_page - 1) // lines_per_page
                
                # Get lines for current page
                start = (page - 1) * lines_per_page
                end = start + lines_per_page
                current_lines = all_lines[start:end]
                
                log_content = ''.join(current_lines)
                
                return render_template(
                    'logs.html',
                    log_content=log_content,
                    current_page=page,
                    total_pages=total_pages
                )
                
        except FileNotFoundError:
            return render_template('logs.html', 
                                log_content="Log file not found",
                                current_page=1,
                                total_pages=1)
        except Exception as e:
            return render_template('logs.html', 
                                log_content=f"Error reading log file: {str(e)}",
                                current_page=1,
                                total_pages=1)
    























    return app



def adapt_datetime(val: datetime) -> str:
    """Convert datetime to ISO format string for SQLite storage"""
    return val.isoformat()

def convert_datetime(val: bytes) -> datetime:
    """Convert ISO format string from SQLite back to datetime"""
    return datetime.fromisoformat(val.decode())

sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("datetime", convert_datetime)


import os

if __name__ == '__main__':
    args = parse_args()
    app = create_app(args)
    
    # Base configuration
    config = {
        'host': '0.0.0.0',
        'port': 8000,
        'debug': args.debug
    }
    
    # Add SSL context only if ENV is development
    if os.environ.get('FLASK_ENV') == 'development':
        config['ssl_context'] = (
            'static/assets/fullchain.pem',
            'static/assets/privkey.pem'
        )
    #
    app.run(**config)

# from flask import Flask

# app = Flask(__name__)

# @app.route('/')
# def hello():
#     return "Hello World!"

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=8000)