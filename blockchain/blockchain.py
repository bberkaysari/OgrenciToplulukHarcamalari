import json
import hashlib
import time
import os

DIFFICULTY = 4
TARGET_TIME = 10  # target block time in seconds
INTERVAL = 5      # adjust difficulty every 5 blocks

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0, hash=None):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = hash or self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "transactions": self.transactions,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self, filename="blockchain.json"):
        self.filename = filename
        self.chain = []
        self.pending_transactions = []
        self.difficulty = DIFFICULTY
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
        previous_hash = self.get_latest_block().hash
        index = len(self.chain)
        timestamp = time.time()
        transactions = self.pending_transactions

        nonce = 0
        prefix_str = '0' * self.difficulty
        while True:
            candidate_block = Block(index, transactions, timestamp, previous_hash, nonce)
            candidate_hash = candidate_block.calculate_hash()
            if candidate_hash.startswith(prefix_str):
                candidate_block.hash = candidate_hash
                break
            nonce += 1

        self.chain.append(candidate_block)
        self.save_chain_to_file()
        self.pending_transactions = []

        self.adjust_difficulty()  # Call this after mining

        return {
            "index": candidate_block.index,
            "hash": candidate_block.hash,
            "previous_hash": candidate_block.previous_hash,
            "nonce": candidate_block.nonce
        }

    def add_block(self, block):
        self.chain.append(block)
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

    def adjust_difficulty(self):
        if len(self.chain) < INTERVAL + 1:
            return

        latest_block = self.chain[-1]
        prev_adjustment_block = self.chain[-INTERVAL - 1]
        actual_time = latest_block.timestamp - prev_adjustment_block.timestamp
        expected_time = INTERVAL * TARGET_TIME

        if actual_time < expected_time / 2:
            self.difficulty += 1
            print(f"[ZORLUK ARTTI] Yeni zorluk: {self.difficulty}")
        elif actual_time > expected_time * 2:
            self.difficulty = max(1, self.difficulty - 1)
            print(f"[ZORLUK AZALDI] Yeni zorluk: {self.difficulty}")