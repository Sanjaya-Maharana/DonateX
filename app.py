from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from flask_jwt_extended import, jwt_required
import jwt
import razorpay
import random
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///donation.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'GHf0WQugty9hBxrA9iqZgi8GU1AjqcOhbO_PfbeanGc'
app.config['OTP_DIGITS'] = 6  # Number of OTP digits
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

razorpay_client = razorpay.Client(auth=("YOUR_API_KEY", "YOUR_API_SECRET"))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    otp = db.Column(db.String(6))


class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    order_id = db.Column(db.String(50))


# Initialize the database
with app.app_context():
    db.create_all()


def generate_token(user_id):
    token = jwt.encode({'user_id': user_id}, app.config['SECRET_KEY'], algorithm='HS256')
    return token


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            token_payload = jwt.decode(token.split(' ')[1], app.config['SECRET_KEY'], algorithms=['HS256'])
        except ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(token_payload['user_id'], *args, **kwargs)

    return decorated


def generate_and_send_otp():
    otp = ''.join([str(random.randint(0, 9)) for _ in range(app.config['OTP_DIGITS'])])
    return otp


@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        name = data['name']
        phone_number = data['phone_number']
        email = data['email']

        existing_user = User.query.filter_by(phone_number=phone_number).first()
        if existing_user:
            otp = generate_and_send_otp(phone_number)
            existing_user.otp = otp
            db.session.commit()
            return jsonify({'message': 'OTP regenerated and sent for existing user', 'otp': otp}), 200
        else:
            otp = generate_and_send_otp(phone_number)
            user = User(name=name, phone_number=phone_number, email=email, otp=otp)
            db.session.add(user)
            db.session.commit()
            return jsonify({'message': 'Registration successful. OTP sent for verification', 'otp': otp}), 200

    except Exception as e:
        return jsonify({'error': 'User registration failed', 'details': str(e)}), 400


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        phone_number = data.get('phone_number')
        user_id = data.get('user_id')
        otp = data['otp']

        user = User.query.filter_by(phone_number=phone_number, otp=otp).first()

        if user:
            user.otp = ''
            db.session.commit()

            access_token = generate_token(user.id)
            return jsonify({'access_token': access_token}), 200
        else:
            return jsonify({'error': 'Invalid OTP or user not found'}), 400

    except Exception as e:
        return jsonify({'error': 'User login failed', 'details': str(e)}), 400


@app.route('/donate', methods=['POST'])
@token_required
def donate(user_id):
    try:
        data = request.get_json()
        amount = data['amount']
        # Create a Razorpay order
        order_amount = int(amount * 100)
        order_currency = 'INR'
        order_receipt = 'order_rcptid_' + str(user_id)
        order = razorpay_client.order.create({
            'amount': order_amount,
            'currency': order_currency,
            'receipt': order_receipt,
        })

        donation = Donation(amount=amount, user_id=user_id, order_id=order['id'])
        db.session.add(donation)
        db.session.commit()

        return jsonify({'order_id': order['id'], 'order_amount': order_amount}), 200
    except Exception as e:
        return jsonify({'error': 'Donation failed', 'details': str(e)}), 400


@app.route('/capture', methods=['POST'], endpoint='capture_donation')
@jwt_required
def capture_donation():
    try:

        data = request.get_json()
        order_id = data['order_id']
        order_amount = data['order_amount']
        donation = Donation.query.filter_by(order_id=order_id).first()

        if donation:
            payment = razorpay_client.payment.fetch(payment_id)
            if payment['order_id'] == order_id and payment['status'] == 'captured':
                # Update the donation record in the database
                donation.amount = order_amount
                db.session.commit()
                return jsonify({'message': 'Donation successful'}), 200
            else:
                return jsonify({'error': 'Payment verification failed'}), 400
        else:
            return jsonify({'error': 'Donation not found or already processed'}), 400
    except Exception as e:
        return jsonify({'error': 'Donation capture failed', 'details': str(e)}), 400


# Donation History
@app.route('/history', methods=['GET'], endpoint='donation_history')
@jwt_required
def donation_history(user_id):
    try:
        donations = [{'amount': donation.amount, 'timestamp': donation.timestamp} for donation in
                     User.query.get(user_id).donations]
        return jsonify({'donation_history': donations}), 200
    except Exception as e:
        return jsonify({'error': 'Retrieving donation history failed', 'details': str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True)
