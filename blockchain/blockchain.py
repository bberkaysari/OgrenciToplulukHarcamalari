import json
import hashlib
import time
import os

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0, hash=None):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = hash or self.calculate_hash()

    def calculate_hash(self):
        block_data = {
            "index": self.index,
            "transactions": self.transactions,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }
        block_string = json.dumps(block_data, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self, filename="blockchain.json"):
        self.filename = filename
        self.chain = []
        self.pending_transactions = []
        self.load_chain_from_file()

    def create_genesis_block(self):
        genesis = Block(0, [], time.time(), "0")
        print(f"[GENESIS BLOK OLUŞTURULDU] Hash: {genesis.hash}")
        return genesis

    def get_latest_block(self):
        return self.chain[-1]

    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def mine_block(self):
        new_block = Block(
            index=len(self.chain),
            transactions=self.pending_transactions,
            timestamp=time.time(),
            previous_hash=self.get_latest_block().hash
        )
        self.chain.append(new_block)
        self.pending_transactions = []
        self.save_chain_to_file()

    def save_chain_to_file(self):
        with open(self.filename, "w") as f:
            chain_data = [block.__dict__ for block in self.chain]
            json.dump(chain_data, f)

    def load_chain_from_file(self):
        if os.path.exists(self.filename):
            with open(self.filename, "r") as f:
                chain_data = json.load(f)
                self.chain = [Block(**block) for block in chain_data]
        else:
            self.chain = [self.create_genesis_block()]
            self.save_chain_to_file()

    def get_user_chain(self, user_id):
        user_chain = []
        for block in self.chain:
            user_transactions = [tx for tx in block.transactions if tx.get("user_id") == user_id]
            if user_transactions:
                user_chain.append({
                    "index": block.index,
                    "timestamp": block.timestamp,
                    "transactions": user_transactions,
                    "hash": block.hash,
                    "previous_hash": block.previous_hash
                })
        return user_chain

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.hash != current.calculate_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
        return True