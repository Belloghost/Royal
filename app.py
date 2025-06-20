# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import uuid
from werkzeug.utils import secure_filename
from functools import wraps
from flask import send_file
from PIL import Image
import io
import uuid
from werkzeug.utils import secure_filename
from functools import wraps
# Add this at the top with other imports
import logging
from io import BytesIO


# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = 'royal_chuckles_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///family.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['AUDIO_UPLOAD_FOLDER'] = 'static/audio'
app.config['VIDEO_UPLOAD_FOLDER'] = 'static/video'
app.config['AUDIO_FOLDER'] = 'static/audio'
app.config['VIDEO_FOLDER'] = 'static/video'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1024MB max upload
app.config['MAX_AUDIO_SIZE'] = 1024 * 1024 * 1024  # 1024MB max for audio
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['AUDIO_UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['VIDEO_UPLOAD_FOLDER'], exist_ok=True)


db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    family_code = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    password_plaintext = db.Column(db.String(100), nullable=True)  # Unhashed password
    profile = db.relationship('UserProfile', backref='user', uselist=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_head = db.Column(db.Boolean, default=False)
    profile_pic = db.Column(db.String(200), default='default.jpg')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    payments = db.relationship('Payment', backref='user', lazy=True)
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    messages_received = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)
    album_images = db.relationship('AlbumImage', backref='uploader', lazy=True)
   

class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    birth_date = db.Column(db.String(200))
    birth_place = db.Column(db.String(200))
    occupation = db.Column(db.String(200))
    education = db.Column(db.String(200))
    hobbies = db.Column(db.String(200))
    favorite_food = db.Column(db.String(200))
    grandfather_name = db.Column(db.String(100))
    grandfather_origin = db.Column(db.String(200))
    grandmother_name = db.Column(db.String(100))
    grandmother_origin = db.Column(db.String(200))
    father_name = db.Column(db.String(100))
    father_occupation = db.Column(db.String(200))
    mother_name = db.Column(db.String(100))
    mother_occupation = db.Column(db.String(200))
    spouse_name = db.Column(db.String(100))
    children_names = db.Column(db.Text)
    siblings_names = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user_rel = db.relationship('User')
class ProfileQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(500), nullable=False)
    field_name = db.Column(db.String(50), nullable=False, unique=True)
    is_required = db.Column(db.Boolean, default=False)
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    file_path = db.Column(db.String(200), nullable=True)
    file_type = db.Column(db.String(50), nullable=True)
    
    reply_to = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)
    replied_message = db.relationship('Message', remote_side=[id], backref='replies')

class Notice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    posted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_pinned = db.Column(db.Boolean, default=False)

class Family(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(50), unique=True, nullable=False)
    head_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    oriki = db.Column(db.Text, default="Our family is known for wisdom, strength, and unity...")
class GroupMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_path = db.Column(db.String(200), nullable=True)
    file_type = db.Column(db.String(50), nullable=True)
    family_id = db.Column(db.Integer, db.ForeignKey('family.id'), nullable=False)
# Database Models - Add AlbumImage model
class AlbumImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    thumbnail = db.Column(db.String(200), nullable=False)  # Store thumbnail filename
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    caption = db.Column(db.String(200))

# Initialize database
def init_db():
    db.create_all()
    
    # Create head user if none exists
    if User.query.count() == 0:
        hashed_password = generate_password_hash('admin123', method='pbkdf2:sha256')
        head_user = User(
            name='Bello Bilal',
            email='bb2010ng@gmail.com',
            family_code='000011',
            password=hashed_password,
            is_head=True,
            is_admin=True
        )
        db.session.add(head_user)
        db.session.commit()
        
        # Create family with head user
        family = Family(
            name="Royal Chuckles (Bello Family)",
            code="000011",
            head_id=head_user.id
        )
        db.session.add(family)
        db.session.commit()
    # Create profile questions if none exist
    if ProfileQuestion.query.count() == 0:
        questions = [
            {"question": "Date of Birth", "field_name": "birth_date", "is_required": True, "order": 1},
            {"question": "Place of Birth", "field_name": "birth_place", "is_required": True, "order": 2},
            {"question": "Occupation", "field_name": "occupation", "is_required": True, "order": 3},
            {"question": "Education", "field_name": "education", "is_required": False, "order": 4},
            {"question": "Hobbies", "field_name": "hobbies", "is_required": False, "order": 5},
            {"question": "Favorite Food", "field_name": "favorite_food", "is_required": False, "order": 6},
            {"question": "Grandfather's Name", "field_name": "grandfather_name", "is_required": True, "order": 7},
            {"question": "Grandfather's Origin", "field_name": "grandfather_origin", "is_required": True, "order": 8},
            {"question": "Grandmother's Name", "field_name": "grandmother_name", "is_required": True, "order": 9},
            {"question": "Grandmother's Origin", "field_name": "grandmother_origin", "is_required": True, "order": 10},
            {"question": "Father's Name", "field_name": "father_name", "is_required": True, "order": 11},
            {"question": "Father's Occupation", "field_name": "father_occupation", "is_required": False, "order": 12},
            {"question": "Mother's Name", "field_name": "mother_name", "is_required": True, "order": 13},
            {"question": "Mother's Occupation", "field_name": "mother_occupation", "is_required": False, "order": 14},
            {"question": "Spouse's Name", "field_name": "spouse_name", "is_required": False, "order": 15},
            {"question": "Children's Names", "field_name": "children_names", "is_required": False, "order": 16},
            {"question": "Siblings' Names", "field_name": "siblings_names", "is_required": False, "order": 17},
        ]
        
        for q in questions:
            question = ProfileQuestion(
                question=q["question"],
                field_name=q["field_name"],
                is_required=q["is_required"],
                order=q["order"]
            )
            db.session.add(question)
        
        db.session.commit()
    AlbumImage.__table__.create(db.engine, checkfirst=True)
    UserProfile.__table__.create(db.engine, checkfirst=True)
    User.__table__.create(db.engine, checkfirst=True)


# Call init_db when the app starts
with app.app_context():
    init_db()

# Helper Functions
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def head_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_head:
            flash('Only family head can perform this action', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def get_family():
    return Family.query.first()

def get_head_user():
    family = get_family()
    if family:
        return User.query.get(family.head_id)
    return None

def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

def save_file(file, folder, allowed_extensions):
    if file.filename == '':
        return None
        
    if not allowed_file(file.filename, allowed_extensions):
        return None
        
    # Generate unique filename
    ext = file.filename.rsplit('.', 1)[1].lower()
    unique_filename = f"{uuid.uuid4().hex}.{ext}"
    file_path = os.path.join(folder, unique_filename)
    file.save(file_path)
    
    return unique_filename

# Update user last seen time
def update_last_seen():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            user.last_seen = datetime.utcnow()
            db.session.commit()

# Check if user is online (active in last 2 minutes)
def is_online(user):
    if not user.last_seen:
        return False
    return (datetime.utcnow() - user.last_seen).total_seconds() < 120

# Routes
@app.route('/')
def home():
    return render_template('index.html', family=get_family())

@app.route('/register', methods=['GET', 'POST'])
def register():
    family = get_family()
    head_user = get_head_user()
    
    if not family or not head_user:
        flash('Family not set up yet. Please contact the head of the family.', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        family_code = request.form['family_code']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if family_code != family.code:
            flash('Invalid family code', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
            
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_user = User(
            name=name,
            email=email,
            family_code=family.code,
            password_plaintext=password,
            password=hashed_password
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', family_code=family.code)
# Create thumbnail function
@app.route('/admin/passwords')
@head_required
def manage_passwords():
    user = User.query.get(session['user_id'])
    family = get_family()
    users = User.query.filter_by(family_code=family.code).all()
    return render_template('passwords.html', user=user, family=family, users=users)

@app.route('/admin/update_password', methods=['POST'])
@head_required
def update_password():
    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not new_password or not confirm_password:
        flash('Password fields cannot be empty', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if new_password != confirm_password:
        flash('Passwords do not match', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Update both password fields
    user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
    user.password_plaintext = new_password
    db.session.commit()
    
    flash(f"Password for {user.name} updated successfully", 'success')
    return redirect(url_for('admin_dashboard'))
def create_thumbnail(image_path, size=(400, 400)):
    img = Image.open(image_path)
    img.thumbnail(size)
    
    # Generate unique filename for thumbnail
    ext = os.path.splitext(image_path)[1]
    thumb_filename = f"thumb_{uuid.uuid4().hex}{ext}"
    thumb_path = os.path.join(app.config['UPLOAD_FOLDER'], thumb_filename)
    
    # Save thumbnail
    img.save(thumb_path)
    
    return thumb_filename

@app.route('/album')
def album():
    if 'user_id' not in session:
        flash('Please login to view the family album', 'info')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    family = get_family()
    
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 20  # Images per page
    
    # Get images with uploader information
    images = AlbumImage.query.options(db.joinedload(AlbumImage.uploader))\
        .order_by(AlbumImage.timestamp.desc())\
        .paginate(page=page, per_page=per_page)
    
    # Get family statistics
    total_images = AlbumImage.query.count()
    family_members = User.query.filter_by(family_code=family.code).count()
    current_year = datetime.now().year
    
    return render_template('album.html', 
                           user=user, 
                           family=family, 
                           images=images,
                           total_images=total_images,
                           family_members=family_members,
                           current_year=current_year)

@app.route('/upload_image', methods=['POST'])
def upload_image():
    if 'user_id' not in session:
        flash('Please login to upload images', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    family = get_family()
    
    app.logger.debug(f"Files in request: {request.files}")
    
    # Check if the post request has the file part
    if 'image' not in request.files:
        flash('No file part in request', 'danger')
        return redirect(url_for('album'))
    
    file = request.files['image']
    
    # If user does not select file, browser submits empty file without filename
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('album'))
    
    # Validate image
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'tfif'}
    if not allowed_file(file.filename, allowed_extensions):
        flash('Invalid file type. Allowed: PNG, JPG, JPEG, GIF, WEBP, TFIF', 'danger')
        return redirect(url_for('album'))
    
    try:
        # Generate unique filename
        ext = file.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"album_{uuid.uuid4().hex}.{ext}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # Save original file
        file.save(file_path)
        
        # Create thumbnail
        thumb_filename = f"thumb_{unique_filename}"
        thumb_path = os.path.join(app.config['UPLOAD_FOLDER'], thumb_filename)
        
        # Create thumbnail (300x300)
        img = Image.open(file_path)
        img.thumbnail((300, 300))
        img.save(thumb_path)
        
        # Get caption
        caption = request.form.get('caption', '')
        
        # Save to database
        new_image = AlbumImage(
            filename=unique_filename,
            thumbnail=thumb_filename,
            uploaded_by=user.id,
            caption=caption
        )
        db.session.add(new_image)
        db.session.commit()
        
        flash('Image uploaded successfully!', 'success')
        return redirect(url_for('album'))
    
    except Exception as e:
        app.logger.error(f"Error uploading image: {str(e)}")
        flash(f'Error uploading image: {str(e)}', 'danger')
        return redirect(url_for('album'))

@app.route('/delete_image/<int:image_id>', methods=['POST'])
@admin_required
def delete_image(image_id):
    image = AlbumImage.query.get(image_id)
    if not image:
        flash('Image not found', 'danger')
        return redirect(url_for('album'))
    
    # Delete files
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image.filename))
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image.thumbnail))
    except OSError:
        pass  # If files don't exist
    
    # Delete from database
    db.session.delete(image)
    db.session.commit()
    
    flash('Image deleted successfully', 'success')
    return redirect(url_for('album'))

@app.route('/download_image/<filename>')
def download_image(filename):
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        filename,
        as_attachment=True,
        download_name=filename
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    family = get_family()
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        family_code = request.form.get('family_code', '')  
        
        user = User.query.filter_by(name=name).first()
        
        if not user or not check_password_hash(user.password, password):
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))
        elif not family_code == family.code:
            flash('Invalid Family Code', 'danger')
            return redirect(url_for('login'))

        
        session['user_id'] = user.id
        user.last_seen = datetime.utcnow()
        db.session.commit()
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            user.last_seen = datetime.utcnow()
            db.session.commit()
    session.pop('user_id', None)
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    family = get_family()
    
    if not user or not family:
        flash('Family not set up', 'danger')
        return redirect(url_for('home'))
    
    # Update last seen
    user.last_seen = datetime.utcnow()
    db.session.commit()
    
    # Calculate payment information
    total_paid = sum(payment.amount for payment in user.payments)
    
    # Calculate debts
    months_remaining = (datetime(datetime.now().year + 1, 1, 1) - datetime.now()).days // 30
    monthly_target = 500  # Example monthly target
    debt_this_month = max(0, monthly_target - sum(
        p.amount for p in user.payments 
        if p.date.month == datetime.now().month
    ))
    total_debt = max(0, (monthly_target * months_remaining) - (total_paid - (monthly_target * (datetime.now().month - 1))))
    
    # Get unread messages
    unread_messages = Message.query.filter_by(receiver_id=user.id, is_read=False).count()
    
    # Get latest notices
    notices = Notice.query.order_by(Notice.timestamp.desc()).limit(5).all()
    
    # Get family members for ranking
    family_members = User.query.filter_by(family_code=family.code).all()
    members_ranking = []
    for member in family_members:
        total = sum(p.amount for p in member.payments)
        members_ranking.append({
            'id': member.id,
            'name': member.name,
            'profile_pic': member.profile_pic,
            'total_paid': total,
            'is_admin': member.is_admin,
            'is_online': is_online(member)
        })
    
    # Sort by total paid
    members_ranking.sort(key=lambda x: x['total_paid'], reverse=True)
    
    head_user = get_head_user()
    
    return render_template(
        'dashboard.html',
        user=user,
        family=family,
        head_user=head_user,
        total_paid=total_paid,
        debt_this_month=debt_this_month,
        total_debt=total_debt,
        unread_messages=unread_messages,
        notices=notices,
        members_ranking=members_ranking
    )

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    family = get_family()
    head_user = get_head_user()
    
    if not user or not family:
        flash('Family not set up', 'danger')
        return redirect(url_for('home'))
    
    # Update last seen
    user.last_seen = datetime.utcnow()
    db.session.commit()
    
    if request.method == 'POST':
        # Handle profile updates
        user.name = request.form.get('name', user.name)
        new_email = request.form.get('email', user.email)
        
        # Validate email
        if new_email != user.email:
            existing_user = User.query.filter_by(email=new_email).first()
            if existing_user and existing_user.id != user.id:
                flash('Email already registered by another user', 'danger')
                return redirect(url_for('profile'))
            user.email = new_email
        
        # Handle password change
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password:
            if new_password != confirm_password:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('profile'))
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            user.password_plaintext = new_password
            flash('Password changed successfully', 'success')
        
        # Handle profile picture upload
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file.filename != '':
                # Save file
                filename = save_file(
                    file, 
                    app.config['UPLOAD_FOLDER'], 
                    {'png', 'jpg', 'jpeg', 'gif', 'tfif', 'pdf', 'webp'}
                )
                
                if filename:
                    # Update user profile
                    if user.profile_pic != 'default.jpg' and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], user.profile_pic)):
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user.profile_pic))
                    
                    user.profile_pic = filename
                    flash('Profile picture updated', 'success')
        
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user, family=family, head_user=head_user)

@app.route('/profile/questions', methods=['GET', 'POST'])
def profile_questions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('home'))
    
    # Get or create profile
    profile = user.profile
    if not profile:
        profile = UserProfile(user_id=user.id)
        db.session.add(profile)
        db.session.commit()
    
    # Get questions
    questions = ProfileQuestion.query.order_by(ProfileQuestion.order).all()
    
    if request.method == 'POST':
        for question in questions:
            field_name = question.field_name
            value = request.form.get(field_name, '')
            
            if question.is_required and not value:
                flash(f"{question.question} is required", 'danger')
                return redirect(url_for('profile_questions'))
            
            setattr(profile, field_name, value)
        
        db.session.commit()
        flash('Profile information saved successfully', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile_questions.html', 
                           user=user, 
                           profile=profile, 
                           questions=questions)
@app.route('/family_directory')
def family_directory():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    family = get_family()
    if not user or not family:
        flash('Family not set up', 'danger')
        return redirect(url_for('home'))
    
    # Get all family members with their profiles
    family_members = User.query.filter_by(family_code=family.code).all()
    
    return render_template('family_directory.html', 
                           user=user, 
                           family=family, 
                           family_members=family_members)
@app.route('/get_user_profile/<int:user_id>')
def get_user_profile(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    profile = user.profile
    questions = ProfileQuestion.query.order_by(ProfileQuestion.order).all()
    
    profile_data = {
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'profile_pic': user.profile_pic,
        'created_at': user.created_at.strftime('%Y-%m-%d'),
    }
    
    # Add profile answers
    for question in questions:
        field_name = question.field_name
        value = getattr(profile, field_name, '') if profile else ''
        profile_data[field_name] = {
            'question': question.question,
            'value': value if value else 'Not provided',
            'is_answered': bool(value)
        }
    
    return jsonify(profile_data)
@app.route('/messages')
def messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    family = get_family()
    if not user or not family:
        flash('Family not set up', 'danger')
        return redirect(url_for('home'))
    
    # Update last seen
    user.last_seen = datetime.utcnow()
    db.session.commit()
    
    # Get all family members for messaging
    family_members = User.query.filter(User.family_code == family.code).all()
    
    # Get messages
    messages = Message.query.filter(
        (Message.sender_id == user.id) | 
        (Message.receiver_id == user.id)
    ).order_by(Message.timestamp.desc()).all()
    
    # Mark received messages as read
    for msg in messages:
        if msg.receiver_id == user.id and not msg.is_read:
            msg.is_read = True
    db.session.commit()
    
    return render_template('messages.html', user=user, family=family, family_members=family_members, messages=messages)

@app.route('/get_messages/<int:receiver_id>')
def get_messages(receiver_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    # Get last message ID from query parameter
    last_message_id = request.args.get('last_id', 0, type=int)
    
    # Filter messages
    query = Message.query.filter(
        ((Message.sender_id == user_id) & (Message.receiver_id == receiver_id)) |
        ((Message.sender_id == receiver_id) & (Message.receiver_id == user_id))
    )
    
    if last_message_id:
        query = query.filter(Message.id > last_message_id)
    
    messages = query.order_by(Message.timestamp.asc()).all()
    
    # Mark received messages as read
    for msg in messages:
        if msg.receiver_id == user_id and not msg.is_read:
            msg.is_read = True
    db.session.commit()
    
    # Format messages for JSON response
    formatted_messages = []
    for msg in messages:
        sender = User.query.get(msg.sender_id)
        
        # Get replied message if exists
        replied_message = None
        if msg.reply_to:
            original_msg = Message.query.get(msg.reply_to)
            if original_msg:
                replied_sender = User.query.get(original_msg.sender_id)
                replied_message = {
                    'id': original_msg.id,
                    'content': original_msg.content,
                    'sender_name': replied_sender.name,
                    'file_type': original_msg.file_type
                }
        
        message_data = {
            'id': msg.id,
            'content': msg.content,
            'timestamp': msg.timestamp.strftime('%I:%M %p'),
            'is_sender': msg.sender_id == user_id,
            'sender_name': sender.name,
            'sender_initial': sender.name[0],
            'file_path': msg.file_path,
            'file_type': msg.file_type,
            'replied_message': replied_message
        }
        formatted_messages.append(message_data)
    
    # Get receiver info
    receiver = User.query.get(receiver_id)
    receiver_info = {
        'id': receiver.id,
        'name': receiver.name,
        'initial': receiver.name[0],
        'is_admin': receiver.is_admin,
        'is_online': is_online(receiver)
    }
    
    return jsonify({
        'messages': formatted_messages,
        'receiver': receiver_info
    })

@app.route('/upload_media', methods=['POST'])
def upload_media():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    # Determine file type
    if file.content_type.startswith('image/'):
        folder = app.config['UPLOAD_FOLDER']
        url_prefix = 'uploads'
    elif file.content_type.startswith('audio/'):
        folder = app.config['AUDIO_FOLDER']
        url_prefix = 'audio'
    elif file.content_type.startswith('video/'):
        folder = app.config['VIDEO_FOLDER']
        url_prefix = 'video'
    else:
        return jsonify({'error': 'Unsupported file type'}), 400
    
    # Save file
    ext = file.filename.rsplit('.', 1)[1].lower()
    type_prefix = file.content_type.split('/')[0]
    filename = f"{type_prefix}_{uuid.uuid4().hex}.{ext}"  # e.g. "video_abc123.mp4"
    file_path = os.path.join(folder, filename)
    
    try:
        file.save(file_path)
        return jsonify({
            'success': True,
            'filename': filename,
            'url': f"/{url_prefix}/{filename}",
            'type': file.content_type.split('/')[0]
        })
    except Exception as e:
        logger.error(f"Error saving media file: {str(e)}")
        return jsonify({'error': 'Error saving file'}), 500

@app.route('/upload_audio', methods=['POST'])
def upload_audio():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if 'audio' not in request.files:
        return jsonify({'error': 'No audio file'}), 400
    
    audio_file = request.files['audio']
    if audio_file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    # Generate unique filename
    ext = audio_file.filename.rsplit('.', 1)[1].lower() if '.' in audio_file.filename else 'webm'
    unique_filename = f"audio_{uuid.uuid4().hex}.{ext}"
    file_path = os.path.join(app.config['AUDIO_UPLOAD_FOLDER'], unique_filename)
    
    try:
        audio_file.save(file_path)
        return jsonify({
            'success': True,
            'filename': unique_filename,
            'url': f"/audio/{unique_filename}",
            'type': 'audio'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/get_message/<int:message_id>')
def get_message(message_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    message = Message.query.get(message_id)
    if not message:
        return jsonify({'error': 'Message not found'}), 404
    
    # Format message for JSON response
    message_data = {
        'id': message.id,
        'content': message.content,
        'timestamp': message.timestamp.strftime('%I:%M %p'),
        'is_sender': message.sender_id == session['user_id'],
        'file_path': message.file_path,
        'file_type': message.file_type
    }
    
    return jsonify(message_data)
# Updated message sending endpoint
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    sender_id = session['user_id']
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('content', '')
    reply_to = request.form.get('reply_to')
    media_files = request.form.getlist('media_files[]')
    media_types = request.form.getlist('media_types[]')
    
    # Validate receiver
    if not receiver_id or not receiver_id.isdigit():
        return jsonify({'error': 'Invalid receiver'}), 400
    
    # Create the message
    new_message = Message(
        sender_id=sender_id,
        receiver_id=int(receiver_id),
        content=content,
        reply_to=reply_to
    )
    
    # Handle media files
    if media_files and media_types:
        filename = media_files[0]
        filetype = media_types[0]
        new_message.file_path = filename
        new_message.file_type = filetype
    
    db.session.add(new_message)
    db.session.commit()
    
    # Format response
    message_data = {
        'id': new_message.id,
        'content': content,
        'timestamp': new_message.timestamp.strftime('%I:%M %p'),
        'file_path': new_message.file_path,
        'file_type': new_message.file_type,
        'sender_id': sender_id,
        'receiver_id': receiver_id
    }
    
    return jsonify({
        'success': True,
        'message': message_data
    })
@app.route('/delete_message/<int:message_id>', methods=['DELETE'])
def delete_message(message_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    message = Message.query.get(message_id)
    if not message:
        return jsonify({'error': 'Message not found'}), 404
    
    # Only allow sender to delete message
    if message.sender_id != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Delete associated file if exists
    if message.file_path:
        if message.file_type == 'image':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], message.file_path)
        elif message.file_type == 'video':
            file_path = os.path.join(app.config['VIDEO_UPLOAD_FOLDER'], message.file_path)
        else:
            file_path = os.path.join(app.config['AUDIO_UPLOAD_FOLDER'], message.file_path)
        
        if os.path.exists(file_path):
            os.remove(file_path)
    
    db.session.delete(message)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/audio/<filename>')
def audio_file(filename):
    return send_from_directory(app.config['AUDIO_FOLDER'], filename)

@app.route('/video/<filename>')
def video_file(filename):
    return send_from_directory(app.config['VIDEO_FOLDER'], filename)

@app.route('/check_online/<int:user_id>')
def check_online(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'is_online': is_online(user),
        'last_seen': user.last_seen.strftime('%Y-%m-%d %H:%M:%S') if user.last_seen else None
    })

@app.route('/notices')
def notices():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    family = get_family()
    
    if not user or not family:
        flash('Family not set up', 'danger')
        return redirect(url_for('home'))
    
    # Update last seen
    user.last_seen = datetime.utcnow()
    db.session.commit()
    
    notices = Notice.query.order_by(Notice.is_pinned.desc(), Notice.timestamp.desc()).all()
    return render_template('notices.html', user=user, family=family, notices=notices)

# Admin Routes
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    user = User.query.get(session['user_id'])
    family = get_family()
    
    if not user or not family:
        flash('Family not set up', 'danger')
        return redirect(url_for('home'))
    
    # Update last seen
    user.last_seen = datetime.utcnow()
    db.session.commit()
    
    users = User.query.filter_by(family_code=family.code).all()
    total_contributions = db.session.query(db.func.sum(Payment.amount)).scalar() or 0
    notices_count = Notice.query.count()
    upcoming_events = 3  # Placeholder
    
    return render_template(
        'admin_dashboard.html',
        user=user,
        family=family,
        users=users,
        total_contributions=total_contributions,
        notices_count=notices_count,
        upcoming_events=upcoming_events,
        is_head=user.is_head
    )

@app.route('/admin/record_payment', methods=['POST'])
@admin_required
def record_payment():
    user_id = request.form['user_id']
    amount = float(request.form['amount'])
    date_str = request.form.get('date', '')
    
    try:
        date = datetime.strptime(date_str, '%Y-%m-%d') if date_str else datetime.utcnow()
    except ValueError:
        date = datetime.utcnow()
    
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    new_payment = Payment(user_id=user_id, amount=amount, date=date)
    db.session.add(new_payment)
    db.session.commit()
    
    flash('Payment recorded successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/post_notice', methods=['POST'])
@admin_required
def post_notice():
    title = request.form['title']
    content = request.form['content']
    is_pinned = 'is_pinned' in request.form
    
    if not title.strip() or not content.strip():
        flash('Title and content cannot be empty', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    new_notice = Notice(
        title=title,
        content=content,
        posted_by=session['user_id'],
        is_pinned=is_pinned
    )
    
    db.session.add(new_notice)
    db.session.commit()
    
    flash('Notice posted successfully', 'success')
    return redirect(url_for('notices'))

@app.route('/admin/make_admin', methods=['POST'])
@head_required
def make_admin():
    user_id = request.form['user_id']
    user = User.query.get(user_id)
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    user.is_admin = True
    db.session.commit()
    
    flash(f'{user.name} is now an admin', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/remove_admin', methods=['POST'])
@head_required
def remove_admin():
    user_id = request.form['user_id']
    user = User.query.get(user_id)
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if user.is_head:
        flash('Cannot remove admin status from family head', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    user.is_admin = False
    db.session.commit()
    
    flash(f'{user.name} is no longer an admin', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update_family', methods=['POST'])
@head_required
def update_family():
    family = get_family()
    
    if not family:
        flash('Family not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    family.name = request.form['family_name']
    family.oriki = request.form['oriki']
    family.code = request.form['family_code']
    
    db.session.commit()
    flash('Family information updated successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_notice/<int:notice_id>', methods=['POST'])
@admin_required
def delete_notice(notice_id):
    notice = Notice.query.get(notice_id)
    if not notice:
        flash('Notice not found', 'danger')
        return redirect(url_for('notices'))
    
    db.session.delete(notice)
    db.session.commit()
    flash('Notice deleted successfully', 'success')
    return redirect(url_for('notices'))

@app.route('/admin/toggle_pin_notice/<int:notice_id>', methods=['POST'])
@admin_required
def toggle_pin_notice(notice_id):
    notice = Notice.query.get(notice_id)
    if not notice:
        flash('Notice not found', 'danger')
        return redirect(url_for('notices'))
    
    notice.is_pinned = not notice.is_pinned
    db.session.commit()
    
    action = "pinned" if notice.is_pinned else "unpinned"
    flash(f'Notice {action} successfully', 'success')
    return redirect(url_for('notices'))

@app.route('/family_oriki')
def family_oriki():
    family = get_family()
    if not family:
        return jsonify({
            'title': "Family Oriki",
            'content': "Our family is known for wisdom, strength, and unity..."
        })
    
    return jsonify({
        'title': f"Oriki of the {family.name}",
        'content': family.oriki
    })

@app.route('/update_online_status')
def update_online_status():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            user.last_seen = datetime.utcnow()
            db.session.commit()
            return jsonify({'success': True})
    return jsonify({'success': False})

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)