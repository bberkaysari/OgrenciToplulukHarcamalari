from flask import Flask, request, jsonify
from flask_login import login_required
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Spending, Community
from blockchain.blockchain import Blockchain
from datetime import datetime, timedelta
from flask_cors import CORS
import jwt
from functools import wraps
from smart_contract import SmartContract
import hashlib
from sqlalchemy import text
from models import AdminLimit

app = Flask(__name__)
app.config.from_object('config.Config')

CORS(app, supports_credentials=True, origins=["http://localhost:3000"])
db.init_app(app)
with app.app_context():
    db.create_all()

blockchain = Blockchain()
blockchain.load_chain_from_file()
JWT_SECRET = "jwt-secret-key"
JWT_EXPIRATION_MINUTES = 60

def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token or not token.startswith("Bearer "):
            return jsonify({"message": "Token gerekli"}), 401
        try:
            token = token.replace("Bearer ", "")
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            user = User.query.get(decoded["user_id"])
            if not user:
                return jsonify({"message": "Kullanıcı bulunamadı"}), 401
            request.user = user
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token süresi dolmuş"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Geçersiz token"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    community_id = data.get("community_id")

    if not username or not password or not community_id:
        return jsonify({"message": "Kullanıcı adı, şifre ve topluluk gerekli"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Kullanıcı adı zaten kayıtlı"}), 400

    user = User(
        username=username,
        password=generate_password_hash(password),
        community_id=community_id
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Kayıt başarılı"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(username=data["username"]).first()
    if user and check_password_hash(user.password, data["password"]):
        payload = {
            "user_id": user.id,
            "username": user.username,
            "community": user.community.name,
            "role": user.role,
            "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION_MINUTES)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        return jsonify({"token": token})
    return jsonify({"message": "Hatalı kullanıcı adı veya şifre"}), 401

@app.route("/spending", methods=["POST"])
@jwt_required
def add_spending():
    data = request.json

    contract = SmartContract(request.user)
    valid, message = contract.can_add_transaction(data)
    if not valid:
        return jsonify({"message": message}), 400

    user_id = request.user.id
    amount = data["amount"]
    category = data.get("category", "")
    description = data.get("description", "")
    timestamp = datetime.utcnow()

    last_spending = (
        Spending.query
        .join(User)
        .filter(User.community_id == request.user.community_id)
        .order_by(Spending.id.desc())
        .first()
    )
    previous_hash = last_spending.hash if last_spending and last_spending.hash else "0"

    hash_input = f"{user_id}{amount}{category}{description}{timestamp}{previous_hash}"
    new_hash = hashlib.sha256(hash_input.encode()).hexdigest()

    spending = Spending(
        user_id=user_id,
        amount=amount,
        category=category,
        description=description,
        timestamp=timestamp,
        hash=new_hash,
        previous_hash=previous_hash
    )
    db.session.add(spending)
    db.session.commit()

    blockchain.add_transaction({
        "user_id": user_id,
        "username": request.user.username,
        "community": request.user.community.name,
        "amount": amount,
        "category": category,
        "description": description,
        "timestamp": str(timestamp)
    })
    blockchain.mine_block()
    blockchain.save_chain_to_file()

    fetch_chain = view_chain()
    return jsonify({
        "message": "Harcama eklendi",
        "hash": new_hash,
        "previous_hash": previous_hash
    }), 201

@app.route("/chain", methods=["GET"])
@jwt_required
def view_chain():
    user_chain = []
    for block in blockchain.chain:
        include_block = False
        filtered_transactions = []
        for tx in block.transactions:
            if tx.get("community") == request.user.community.name or not tx.get("community"):
                filtered_transactions.append(tx)
                include_block = True
        if include_block:
            user_chain.append({
                "index": block.index,
                "timestamp": block.timestamp,
                "transactions": filtered_transactions,
                "hash": block.hash,
                "previous_hash": block.previous_hash
            })
    return jsonify({"chain": user_chain})

@app.route("/validate", methods=["GET"])
def validate_chain():
    return jsonify({"valid": blockchain.is_chain_valid()})

@app.route("/communities", methods=["GET"])
def get_communities():
    communities = Community.query.all()
    return jsonify([{"id": c.id, "name": c.name} for c in communities])

@app.route("/delete_spending/<int:spending_id>", methods=["DELETE"])
@jwt_required
def delete_spending(spending_id):
    spending = Spending.query.get(spending_id)
    if not spending:
        return jsonify({"message": "Harcama bulunamadı"}), 404

    if spending.user_id != request.user.id:
        return jsonify({"message": "Bu harcamayı silme yetkiniz yok"}), 403

    # Silinmeden önce hash'i al
    deleted_hash = spending.hash

    # Harcamayı sil
    db.session.delete(spending)
    db.session.commit()

    # Güncellenmesi gereken harcamaları al (bu hash'i previous_hash olarak kullananlar)
    to_update = Spending.query.filter_by(previous_hash=deleted_hash).order_by(Spending.id).all()

    for i, s in enumerate(to_update):
        # Yeni previous_hash: silinen harcamanın previous_hash'ini devral
        if i == 0:
            s.previous_hash = spending.previous_hash
        else:
            s.previous_hash = to_update[i - 1].hash

        # Yeni hash'i hesapla
        hash_input = f"{s.user_id}{s.amount}{s.category}{s.description}{s.timestamp}{s.previous_hash}"
        s.hash = hashlib.sha256(hash_input.encode()).hexdigest()

    db.session.commit()
    return jsonify({"message": "Harcama silindi ve zincir güncellendi"}), 200
@app.route("/update_spending/<int:spending_id>", methods=["PUT"])
@jwt_required
def update_spending(spending_id):
    data = request.json
    spending = Spending.query.get(spending_id)

    if not spending:
        return jsonify({"message": "Harcama bulunamadı"}), 404

    if spending.user_id != request.user.id:
        return jsonify({"message": "Bu harcamayı güncelleyemezsiniz"}), 403

    original_hash = spending.hash  # zincirde takip edeceğimiz hash

    # Harcamayı güncelle
    spending.amount = data.get("amount", spending.amount)
    spending.category = data.get("category", spending.category)
    spending.description = data.get("description", spending.description)
    spending.timestamp = datetime.utcnow()

    # Hash’i yeniden hesapla
    spending.hash = hashlib.sha256(
        f"{spending.user_id}{spending.amount}{spending.category}{spending.description}{spending.timestamp}{spending.previous_hash}".encode()
    ).hexdigest()

    db.session.commit()

    # Zincirin devamını güncelle
    current_hash = spending.hash
    current_id = spending.id
    prev_hash = original_hash

    while True:
        next_spending = Spending.query.filter_by(previous_hash=prev_hash).filter(Spending.id > current_id).order_by(Spending.id.asc()).first()
        if not next_spending:
            break

        next_spending.previous_hash = current_hash
        next_spending.hash = hashlib.sha256(
            f"{next_spending.user_id}{next_spending.amount}{next_spending.category}{next_spending.description}{next_spending.timestamp}{next_spending.previous_hash}".encode()
        ).hexdigest()

        db.session.commit()

        prev_hash = next_spending.hash
        current_hash = next_spending.hash
        current_id = next_spending.id

    return jsonify({"message": "Harcama ve zincir güncellendi"}), 200
@app.route('/api/spendings', methods=['GET'])
@jwt_required
def get_spendings():
    spendings = Spending.query.join(User).filter(User.community_id == request.user.community_id).order_by(Spending.id.asc()).all()
    results = []
    for s in spendings:
        results.append({
            'id': s.id,
            'amount': s.amount,
            'category': s.category,
            'description': s.description,
            'timestamp': s.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'username': s.user.username
        })
    return jsonify(results)

@app.route("/user", methods=["GET"])
@jwt_required
def get_user():
    return jsonify({"username": request.user.username})

@app.route("/test_sql", methods=["GET"])
def test_sql():
    q = request.args.get("q", "")
    sql = text(f"SELECT * FROM spending WHERE category LIKE '%{q}%'")
    results = db.session.execute(sql)
    return jsonify([dict(r) for r in results])

from superadmin_routes import superadmin_bp
app.register_blueprint(superadmin_bp)



@app.route("/admin/set_limit", methods=["PUT"])
@jwt_required
def set_monthly_limit():
    if request.user.role != "admin":
        return jsonify({"message": "Yetkisiz erişim"}), 403

    data = request.json
    new_limit = data.get("limit")
    if new_limit is None:
        return jsonify({"message": "Limit değeri gerekli"}), 400

    # Topluluğun bu ayki ilk gününü al
    from datetime import datetime
    now = datetime.utcnow()
    first_day_of_month = datetime(now.year, now.month, 1)

    # Var olan kaydı kontrol et
    from models import AdminLimit
    existing = AdminLimit.query.filter_by(community_id=request.user.community_id, month=first_day_of_month).first()

    if existing:
        existing.limit = new_limit
    else:
        new_record = AdminLimit(
            community_id=request.user.community_id,
            month=first_day_of_month,
            limit=new_limit
        )
        db.session.add(new_record)

    db.session.commit()
    return jsonify({"message": "Aylık limit ayarlandı"}), 200

@app.route("/admin/monthly_status", methods=["GET"])
@jwt_required
def get_monthly_status():
    if request.user.role != "admin" and request.user.role != "user":
        return jsonify({"message": "Yetkisiz erişim"}), 403

    from datetime import datetime
    now = datetime.utcnow()
    first_day = datetime(now.year, now.month, 1)

    # Limiti al
    from models import AdminLimit, Spending
    limit_record = AdminLimit.query.filter_by(
        community_id=request.user.community_id, month=first_day
    ).first()

    limit = limit_record.limit if limit_record else 0

    # Harcanan toplamı hesapla
    from sqlalchemy import func
    user_ids = [u.id for u in User.query.filter_by(community_id=request.user.community_id).all()]
    total_spent = db.session.query(func.sum(Spending.amount)).filter(
        Spending.user_id.in_(user_ids),
        Spending.timestamp >= first_day
    ).scalar() or 0

    remaining = limit - total_spent

    return jsonify({
        "monthly_limit": limit,
        "total_spent": total_spent,
        "remaining_limit": remaining
    })

if __name__ == "__main__":
    app.run(debug=True)
