
class SmartContract:
    def __init__(self, user):
        self.user = user

    def can_add_transaction(self, transaction_data):
        # Temel kontrol: gerekli alanlar var mı
        required_fields = ["amount", "category", "description"]
        for field in required_fields:
            if not transaction_data.get(field):
                return False, "Eksik alan var"

        # Harcama tutarı pozitif olmalı
        if float(transaction_data["amount"]) <= 0:
            return False, "Tutar pozitif olmalı"

        return True, "İşlem onaylandı"

    def can_update_block(self, block, username):
        # Sadece kullanıcıya ait blok güncellenebilir
        for tx in block.transactions:
            if tx.get("username") != username:
                return False, "Bu bloğu güncelleyemezsiniz"
        return True, "Güncelleme onaylandı"

    def can_delete_block(self, block, username):
        # Aynı şekilde sadece kendi eklediği blok silinebilir
        for tx in block.transactions:
            if tx.get("username") != username:
                return False, "Bu bloğu silemezsiniz"
        return True, "Silme onaylandı"