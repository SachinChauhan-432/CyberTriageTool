from flask import Flask, request, jsonify
from flask_cors import CORS
from blockchain import Blockchain, Block
import json
import os

app = Flask(__name__)
CORS(app)

CHAIN_FILE = "ledger.json"
blockchain = Blockchain()

def save_chain():
    with open(CHAIN_FILE, 'w') as f:
        json.dump(blockchain.get_chain_data(), f, indent=4)

def load_chain():
    global blockchain
    if os.path.exists(CHAIN_FILE):
        with open(CHAIN_FILE, 'r') as f:
            try:
                data = json.load(f)
                if data and len(data) > 0:
                    blockchain.chain = []
                    for b in data:
                        block = Block(b['index'], b['timestamp'], b['data'], b['previous_hash'])
                        block.hash = b['hash']
                        blockchain.chain.append(block)
            except:
                pass
                
load_chain()

@app.route('/log', methods=['POST'])
def log_event():
    """
    Receives alerts, incidents, or system actions and securely hashes them into the ledger.
    """
    data = request.json
    if not data:
        return jsonify({"error": "No data to log"}), 400
        
    new_block = blockchain.add_block(data)
    save_chain()
    
    return jsonify({
        "status": "success",
        "message": "Data securely hashed and logged to blockchain.",
        "block_index": new_block.index,
        "hash": new_block.hash
    }), 201

@app.route('/ledger', methods=['GET'])
def get_ledger():
    """
    Returns the entire immutable ledger.
    """
    is_valid = blockchain.is_chain_valid()
    return jsonify({
        "chain": blockchain.get_chain_data(),
        "length": len(blockchain.chain),
        "is_valid": is_valid
    })

@app.route('/verify', methods=['GET'])
def verify_ledger():
    """
    Verifies the cryptographic integrity of the entire chain.
    """
    is_valid = blockchain.is_chain_valid()
    return jsonify({"is_valid": is_valid})

if __name__ == '__main__':
    print("[*] Starting Blockchain Immutable Ledger Service on port 5002...")
    app.run(port=5002)
