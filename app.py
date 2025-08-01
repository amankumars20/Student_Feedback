from flask import Flask, render_template, request, redirect, url_for, flash, session
import boto3
import botocore
import os
from datetime import datetime
import csv
import io
import logging
import hashlib
from functools import wraps
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask configuration from environment variables
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'fallback_secret_key_change_in_production')

# AWS configuration from environment variables
AWS_REGION = os.getenv('AWS_REGION')
S3_BUCKET = os.getenv('S3_BUCKET')
DYNAMODB_TABLE = os.getenv('DYNAMODB_TABLE')
ADMIN_TABLE = os.getenv('ADMIN_TABLE')

# AWS credentials from environment variables
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')

# Validate that all required environment variables are set
required_env_vars = {
    'AWS_ACCESS_KEY_ID': AWS_ACCESS_KEY_ID,
    'AWS_SECRET_ACCESS_KEY': AWS_SECRET_ACCESS_KEY,
    'AWS_REGION': AWS_REGION,
    'S3_BUCKET': S3_BUCKET,
    'DYNAMODB_TABLE': DYNAMODB_TABLE,
    'ADMIN_TABLE': ADMIN_TABLE
}

missing_vars = [var for var, value in required_env_vars.items() if not value]
if missing_vars:
    logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
    logger.error("Please check your .env file and ensure all required variables are set.")
    raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

logger.info("All required environment variables loaded successfully")

# Initialize boto3 clients with explicit credentials
s3_client = boto3.client(
    's3',
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

dynamodb = boto3.resource(
    'dynamodb',
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

def verify_dynamodb_table():
    """Verify that the DynamoDB table exists and is accessible"""
    try:
        table = dynamodb.Table(DYNAMODB_TABLE)
        # Try to get table status
        response = table.table_status
        logger.info(f"DynamoDB table '{DYNAMODB_TABLE}' status: {response}")
        return table
    except botocore.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            logger.error(f"DynamoDB table '{DYNAMODB_TABLE}' does not exist!")
            return create_dynamodb_table()
        else:
            logger.error(f"Error accessing DynamoDB table: {e}")
            return None
    except Exception as e:
        logger.error(f"Unexpected error with DynamoDB: {e}")
        return None

def create_dynamodb_table():
    """Create the DynamoDB table if it doesn't exist"""
    try:
        logger.info(f"Creating DynamoDB table '{DYNAMODB_TABLE}'...")
        table = dynamodb.create_table(
            TableName=DYNAMODB_TABLE,
            KeySchema=[
                {
                    'AttributeName': 'Id',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'Id',
                    'AttributeType': 'S'
                }
            ],
            BillingMode='PAY_PER_REQUEST'  # On-demand billing
        )
        
        # Wait for table to be created
        table.wait_until_exists()
        logger.info(f"DynamoDB table '{DYNAMODB_TABLE}' created successfully!")
        return table
    except botocore.exceptions.ClientError as e:
        logger.error(f"Error creating DynamoDB table: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error creating DynamoDB table: {e}")
        return None

# Initialize table on startup
table = verify_dynamodb_table()

def verify_admin_table():
    """Verify that the admin DynamoDB table exists and is accessible"""
    try:
        admin_table = dynamodb.Table(ADMIN_TABLE)
        # Try to get table status
        response = admin_table.table_status
        logger.info(f"Admin DynamoDB table '{ADMIN_TABLE}' status: {response}")
        return admin_table
    except botocore.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            logger.error(f"Admin DynamoDB table '{ADMIN_TABLE}' does not exist!")
            return create_admin_table()
        else:
            logger.error(f"Error accessing admin DynamoDB table: {e}")
            return None
    except Exception as e:
        logger.error(f"Unexpected error with admin DynamoDB: {e}")
        return None

def create_admin_table():
    """Create the admin DynamoDB table if it doesn't exist"""
    try:
        logger.info(f"Creating admin DynamoDB table '{ADMIN_TABLE}'...")
        admin_table = dynamodb.create_table(
            TableName=ADMIN_TABLE,
            KeySchema=[
                {
                    'AttributeName': 'email',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'email',
                    'AttributeType': 'S'
                }
            ],
            BillingMode='PAY_PER_REQUEST'  # On-demand billing
        )
        
        # Wait for table to be created
        admin_table.wait_until_exists()
        logger.info(f"Admin DynamoDB table '{ADMIN_TABLE}' created successfully!")
        return admin_table
    except botocore.exceptions.ClientError as e:
        logger.error(f"Error creating admin DynamoDB table: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error creating admin DynamoDB table: {e}")
        return None

# Initialize admin table on startup
admin_table = verify_admin_table()

def login_required(f):
    """Decorator to require admin login for certain routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash('Please log in to access the admin dashboard.')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def authenticate_admin(email, password):
    """Authenticate admin credentials against DynamoDB"""
    if admin_table is None:
        logger.error("Admin table is not available")
        return False
    
    try:
        # Try different possible key structures
        # First try with 'email' as key
        try:
            response = admin_table.get_item(Key={'email': email})
            if 'Item' in response:
                item = response['Item']
                # Check different possible password field names
                stored_password = item.get('password', item.get('Password', item.get('PASSWORD', '')))
                logger.info(f"Found admin item with email key: {item}")
                if stored_password == password:
                    return True
        except Exception as e1:
            logger.info(f"Email key lookup failed: {e1}")
        
        # Try with different key structures if email doesn't work
        # Scan the table to find the admin record
        try:
            response = admin_table.scan()
            items = response.get('Items', [])
            logger.info(f"Scanning admin table, found {len(items)} items")
            
            for item in items:
                logger.info(f"Checking item: {item}")
                # Check various email field names
                item_email = item.get('email', item.get('Email', item.get('EMAIL', '')))
                item_password = item.get('password', item.get('Password', item.get('PASSWORD', '')))
                
                if item_email == email and item_password == password:
                    logger.info(f"Authentication successful for {email}")
                    return True
                    
        except Exception as e2:
            logger.error(f"Table scan failed: {e2}")
        
        logger.info(f"Authentication failed for {email}")
        return False
        
    except Exception as e:
        logger.error(f"Error authenticating admin: {e}")
        return False

def generate_csv_content(name, email, feedback, timestamp):
    """Generate CSV content from feedback data"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Name', 'Email', 'Feedback', 'Timestamp'])
    
    # Write data
    writer.writerow([name, email, feedback, timestamp])
    
    return output.getvalue()

@app.route('/')
def home():
    print("home route accessed")
    return render_template('home.html')

@app.route('/form')
def feedback_form():
    return render_template('index.html')

@app.route('/admin')
def admin_login():
    """Admin login page"""
    if 'admin_logged_in' in session:
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_login.html')

@app.route('/admin/login', methods=['POST'])
def admin_login_post():
    """Handle admin login form submission"""
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    
    if not email or not password:
        flash('Please enter both email and password.')
        return redirect(url_for('admin_login'))
    
    if authenticate_admin(email, password):
        session['admin_logged_in'] = True
        session['admin_email'] = email
        flash('Login successful! Welcome to the admin dashboard.')
        return redirect(url_for('admin_dashboard'))
    else:
        flash('Invalid email or password. Please try again.')
        return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    """Protected admin dashboard"""
    return render_template('admin_dashboard.html', admin_email=session.get('admin_email'))

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.pop('admin_logged_in', None)
    session.pop('admin_email', None)
    flash('You have been logged out successfully.')
    return redirect(url_for('home'))

@app.route('/admin/reports')
@login_required
def admin_reports():
    """Protected reports page"""
    # Generate dummy report data
    dummy_reports = [
        {
            'id': 1,
            'title': 'Monthly Feedback Summary',
            'date': '2024-01-15',
            'total_feedback': 45,
            'avg_rating': 4.2,
            'status': 'Completed'
        },
        {
            'id': 2,
            'title': 'Weekly Analytics Report',
            'date': '2024-01-10',
            'total_feedback': 12,
            'avg_rating': 4.5,
            'status': 'Recent'
        },
        {
            'id': 3,
            'title': 'Department Wise Feedback',
            'date': '2024-01-08',
            'total_feedback': 28,
            'avg_rating': 3.9,
            'status': 'Archived'
        }
    ]
    
    return render_template('admin_reports.html', 
                         reports=dummy_reports, 
                         admin_email=session.get('admin_email'))

@app.route('/confirmation')
def confirmation():
    return render_template('confirmation.html')

@app.route('/submit', methods=['POST'])
def submit_feedback():
    name = request.form.get('name')
    email = request.form.get('email')
    feedback_text = request.form.get('feedback')

    # Validate required fields
    if not name or not email or not feedback_text:
        flash('All fields are required.')
        return redirect(url_for('feedback_form'))

    # Sanitize inputs
    name = name.strip()
    email = email.strip()
    feedback_text = feedback_text.strip()

    # Create timestamp
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    
    # Generate CSV filename
    csv_filename = f"feedback_{timestamp}.csv"

    try:
        # Generate CSV content
        csv_content = generate_csv_content(name, email, feedback_text, timestamp)
        
        # Convert string to bytes for S3 upload
        csv_bytes = csv_content.encode('utf-8')
        csv_file_obj = io.BytesIO(csv_bytes)

        # Upload CSV to S3
        logger.info(f"Uploading CSV file to S3: {csv_filename}")
        s3_client.upload_fileobj(
            csv_file_obj,
            S3_BUCKET,
            csv_filename,
            ExtraArgs={'ContentType': 'text/csv'}
        )
        logger.info(f"Successfully uploaded CSV to S3: {csv_filename}")

        # Store metadata in DynamoDB - now with proper error handling
        if table is not None:
            try:
                logger.info(f"Storing metadata in DynamoDB for file: {csv_filename}")
                response = table.put_item(
                    Item={
                        'Id': csv_filename,  # Using Id as the partition key
                        'filename': csv_filename,
                        'uploader_name': name,
                        'uploader_email': email,
                        'upload_timestamp': timestamp,
                        'feedback_text': feedback_text,
                        'created_at': datetime.utcnow().isoformat()
                    }
                )
                logger.info(f"Successfully stored metadata in DynamoDB: {response}")
            except botocore.exceptions.ClientError as dynamo_error:
                logger.error(f"DynamoDB ClientError: {dynamo_error}")
                error_code = dynamo_error.response['Error']['Code']
                error_message = dynamo_error.response['Error']['Message']
                flash(f'DynamoDB error ({error_code}): {error_message}')
                return redirect(url_for('feedback_form'))
            except Exception as dynamo_error:
                logger.error(f"Unexpected DynamoDB error: {dynamo_error}")
                flash(f'Unexpected DynamoDB error: {str(dynamo_error)}')
                return redirect(url_for('feedback_form'))
        else:
            logger.error("DynamoDB table is not available - cannot store metadata")
            flash('DynamoDB table is not available. Please check your AWS configuration.')
            return redirect(url_for('feedback_form'))

        # Redirect to confirmation page - feedback was successfully stored
        logger.info("Feedback submission completed successfully")
        return redirect(url_for('confirmation'))

    except botocore.exceptions.ClientError as e:
        logger.error(f"S3 ClientError: {e}")
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        flash(f'S3 error ({error_code}): {error_message}')
        return redirect(url_for('feedback_form'))
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        flash(f'An unexpected error occurred: {str(e)}')
        return redirect(url_for('feedback_form'))

@app.route('/admin/feedback-view')
@login_required
def feedback_view_page():
    return render_template('feedback_data.html')


@app.route('/admin/feedback-data')
@login_required
def feedback_data():
    try:
        feedback_table = dynamodb.Table('FeedbackSummaryTable')
        response = feedback_table.scan()
        items = response.get('Items', [])
        return {'data': items}
    except Exception as e:
        logger.error(f"Error fetching feedback data: {e}")
        return {'error': str(e)}, 500

@app.route('/admin/dashboard-stats')
@login_required
def dashboard_stats():
    """Get dashboard statistics for charts"""
    try:
        feedback_table = dynamodb.Table('FeedbackSummaryTable')
        response = feedback_table.scan()
        items = response.get('Items', [])
        
        # Process data for charts
        sentiment_counts = {'POSITIVE': 0, 'NEGATIVE': 0, 'NEUTRAL': 0, 'MIXED': 0}
        faculty_mentions = {}
        theme_tags = {}
        monthly_data = {}
        total_comments = 0
        
        for item in items:
            # Count total comments
            total_comments += int(item.get('TotalComments', 0))
            
            # Process sentiment data
            sentiment_data = item.get('SentimentCounts', {})
            for sentiment, count in sentiment_data.items():
                if sentiment.upper() in sentiment_counts:
                    sentiment_counts[sentiment.upper()] += int(count)
            
            # Process faculty mentions
            faculty_data = item.get('FacultyMentions', {})
            for faculty, count in faculty_data.items():
                faculty_mentions[faculty] = faculty_mentions.get(faculty, 0) + int(count)
            
            # Process theme tags
            theme_data = item.get('ThemeTags', {})
            for theme, count in theme_data.items():
                theme_tags[theme] = theme_tags.get(theme, 0) + int(count)
            
            # Process monthly data (extract from processed_at)
            processed_at = item.get('processed_at', '')
            if processed_at:
                try:
                    # Extract month from timestamp
                    month = processed_at[:7]  # YYYY-MM format
                    monthly_data[month] = monthly_data.get(month, 0) + int(item.get('TotalComments', 0))
                except:
                    pass
        
        return {
            'total_feedback': len(items),
            'total_comments': total_comments,
            'sentiment_distribution': sentiment_counts,
            'top_faculty': dict(sorted(faculty_mentions.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_themes': dict(sorted(theme_tags.items(), key=lambda x: x[1], reverse=True)[:10]),
            'monthly_trends': dict(sorted(monthly_data.items()))
        }
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {e}")
        return {'error': str(e)}, 500

@app.route('/admin/filtered-data')
@login_required
def filtered_data():
    """Get filtered feedback data based on query parameters"""
    try:
        # Get filter parameters
        sentiment_filter = request.args.get('sentiment', '').upper()
        faculty_filter = request.args.get('faculty', '')
        theme_filter = request.args.get('theme', '')
        start_date = request.args.get('start_date', '')
        end_date = request.args.get('end_date', '')
        
        feedback_table = dynamodb.Table('FeedbackSummaryTable')
        response = feedback_table.scan()
        items = response.get('Items', [])
        
        # Apply filters
        filtered_items = []
        for item in items:
            # Sentiment filter
            if sentiment_filter:
                sentiment_counts = item.get('SentimentCounts', {})
                if sentiment_filter not in [k.upper() for k in sentiment_counts.keys()]:
                    continue
            
            # Faculty filter
            if faculty_filter:
                faculty_mentions = item.get('FacultyMentions', {})
                if faculty_filter not in faculty_mentions:
                    continue
            
            # Theme filter
            if theme_filter:
                theme_tags = item.get('ThemeTags', {})
                if theme_filter not in theme_tags:
                    continue
            
            # Date filter
            if start_date or end_date:
                processed_at = item.get('processed_at', '')
                if processed_at:
                    try:
                        item_date = processed_at[:10]  # YYYY-MM-DD format
                        if start_date and item_date < start_date:
                            continue
                        if end_date and item_date > end_date:
                            continue
                    except:
                        continue
            
            filtered_items.append(item)
        
        return {'data': filtered_items, 'count': len(filtered_items)}
    except Exception as e:
        logger.error(f"Error fetching filtered data: {e}")
        return {'error': str(e)}, 500

@app.route('/admin/export-filtered-data')
@login_required
def export_filtered_data():
    """Export filtered data as CSV"""
    try:
        # Get the same filtered data
        filtered_response = filtered_data()
        if 'error' in filtered_response:
            return filtered_response
        
        items = filtered_response['data']
        
        # Generate CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        headers = [
            "File Name", "Processed At", "Total Comments", "Dominant Sentiment",
            "Faculty Mentions", "Theme Tags", "Top Key Phrases"
        ]
        writer.writerow(headers)
        
        # Write data rows
        for item in items:
            # Determine dominant sentiment
            sentiment_counts = item.get('SentimentCounts', {})
            dominant_sentiment = "UNKNOWN"
            if sentiment_counts:
                dominant_sentiment = max(sentiment_counts.items(), key=lambda x: int(x[1]))[0].upper()
            
            # Format complex fields
            faculty_mentions = '; '.join([f"{k}:{v}" for k, v in item.get('FacultyMentions', {}).items()])
            theme_tags = '; '.join([f"{k}:{v}" for k, v in item.get('ThemeTags', {}).items()])
            key_phrases = '; '.join(item.get('TopKeyPhrases', []))
            
            row = [
                item.get('file_name', ''),
                item.get('processed_at', ''),
                item.get('TotalComments', ''),
                dominant_sentiment,
                faculty_mentions,
                theme_tags,
                key_phrases
            ]
            writer.writerow(row)
        
        # Create response
        csv_content = output.getvalue()
        response = app.response_class(
            csv_content,
            mimetype='text/csv',
            headers={"Content-disposition": "attachment; filename=filtered_feedback_data.csv"}
        )
        return response
        
    except Exception as e:
        logger.error(f"Error exporting filtered data: {e}")
        return {'error': str(e)}, 500

@app.route('/admin/detailed-feedback-data')
@login_required
def detailed_feedback_data():
    """Get detailed feedback data for the admin dashboard table"""
    try:
        feedback_table = dynamodb.Table('FeedbackSummaryTable')
        response = feedback_table.scan()
        items = response.get('Items', [])
        
        detailed_data = []
        
        for item in items:
            # Extract date from processed_at
            processed_at = item.get('processed_at', '')
            date = processed_at[:10] if processed_at else 'N/A'  # Extract YYYY-MM-DD
            
            # Determine dominant sentiment
            sentiment_counts = item.get('SentimentCounts', {})
            dominant_sentiment = "UNKNOWN"
            if sentiment_counts:
                dominant_sentiment = max(sentiment_counts.items(), key=lambda x: int(x[1]))[0].upper()
            
            # Get faculty mentions (take the most mentioned faculty)
            faculty_mentions = item.get('FacultyMentions', {})
            top_faculty = ""
            if faculty_mentions:
                top_faculty = max(faculty_mentions.items(), key=lambda x: int(x[1]))[0]
            
            # Get total comments count
            total_comments = item.get('TotalComments', 0)
            
            # Get key phrases (join first few)
            key_phrases = item.get('TopKeyPhrases', [])
            key_phrases_str = ', '.join(key_phrases[:3]) if key_phrases else ''
            
            # Get themes (join first few)
            theme_tags = item.get('ThemeTags', {})
            themes_str = ', '.join(list(theme_tags.keys())[:3]) if theme_tags else ''
            
            detailed_data.append({
                'date': date,
                'sentiment': dominant_sentiment,
                'faculty': top_faculty,
                'comments': total_comments,
                'key_phrases': key_phrases_str,
                'themes': themes_str
            })
        
        # Sort by date (newest first)
        detailed_data.sort(key=lambda x: x['date'], reverse=True)
        
        return {'data': detailed_data}
        
    except Exception as e:
        logger.error(f"Error fetching detailed feedback data: {e}")
        return {'error': str(e)}, 500


if __name__ == "__main__":
    app.run(debug=True)
