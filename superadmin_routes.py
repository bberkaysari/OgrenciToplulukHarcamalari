from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, SuperAdmin, User, Community
import jwt
import datetime
from functools import wraps

superadmin_bp = Blueprint('superadmin_bp', __name__)
SUPERADMIN_USERNAME = 'superadmin'
SUPERADMIN_PASSWORD = 'supersecret'
SUPERADMIN_SECRET = 'superadmin-secret-key'

def superadmin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token or not token.startswith("Bearer "):
            return jsonify({"message": "Token gerekli"}), 401

        try:
            token = token.replace("Bearer ", "")
            decoded = jwt.decode(token, SUPERADMIN_SECRET, algorithms=["HS256"])
            if not decoded.get("superadmin"):
                return jsonify({"message": "Erişim reddedildi"}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token süresi dolmuş"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Geçersiz token"}), 401

        return f(*args, **kwargs)
    return decorated

@superadmin_bp.route('/superadmin/login', methods=['POST'])
def superadmin_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username != SUPERADMIN_USERNAME or password != SUPERADMIN_PASSWORD:
        return jsonify({'message': 'Geçersiz kimlik bilgileri'}), 401

    sa = SuperAdmin.query.filter_by(username=username).first()
    if not sa:
        return jsonify({'message': 'Superadmin veritabanında yok'}), 404

    token = jwt.encode({
        'superadmin': True,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=12)
    }, SUPERADMIN_SECRET, algorithm='HS256')

    return jsonify({'token': token})

@superadmin_bp.route('/superadmin/add_admin', methods=['POST'])
@superadmin_required
def add_admin():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    community_id = data.get('community_id')

    if not username or not password or not community_id:
        return jsonify({'message': 'Tüm alanlar zorunludur'}), 400

    # Aynı topluluğa ait admin var mı?
    existing_admin = User.query.filter_by(community_id=community_id, role='admin').first()
    if existing_admin:
        return jsonify({'message': 'Bu topluluk için zaten bir admin var'}), 400

    # Aynı kullanıcı adıyla daha önce biri eklenmiş mi?
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Bu kullanıcı adı zaten mevcut'}), 400

    new_admin = User(
        username=username,
        password=generate_password_hash(password),
        community_id=community_id,
        role='admin'
    )
    db.session.add(new_admin)
    db.session.commit()

    return jsonify({'message': 'Admin başarıyla eklendi'})

@superadmin_bp.route('/superadmin/delete_admin/<int:user_id>', methods=['DELETE'])
@superadmin_required
def delete_admin(user_id):
    user = User.query.get(user_id)
    if not user or user.role != 'admin':
        return jsonify({"message": "Admin bulunamadı"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "Admin silindi"}), 200


@superadmin_bp.route('/add_community', methods=['POST'])
@superadmin_required
def add_community():
    data = request.get_json()
    name = data.get("name")
    if not name:
        return jsonify({"message": "Topluluk adı gerekli"}), 400

    if Community.query.filter_by(name=name).first():
        return jsonify({"message": "Bu topluluk zaten var"}), 409

    new_community = Community(name=name)
    db.session.add(new_community)
    db.session.commit()
    return jsonify({"message": "Topluluk eklendi"}), 201

@superadmin_bp.route('/superadmin/delete_community/<int:community_id>', methods=['DELETE'])
@superadmin_required
def delete_community(community_id):
    from models import Community, Spending, User

    community = Community.query.get(community_id)
    if not community:
        return jsonify({"message": "Topluluk bulunamadı"}), 404

    # Spending'leri user üzerinden topluluğa göre filtrele
    has_spending = db.session.query(Spending).join(User).filter(User.community_id == community_id).first()
    if has_spending:
        return jsonify({"message": "Bu topluluğa ait harcama var, silinemez"}), 400

    db.session.delete(community)
    db.session.commit()
    return jsonify({"message": "Topluluk silindi"}), 200

@superadmin_bp.route('/superadmin/admins', methods=['GET'])
@superadmin_required
def list_admins():
    admins = User.query.filter_by(role='admin').all()
    result = [{
        "id": admin.id,
        "username": admin.username,
        "community": admin.community.name
    } for admin in admins]

    return jsonify(result)
