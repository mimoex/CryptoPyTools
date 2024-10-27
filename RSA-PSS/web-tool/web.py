from flask import Flask, request, render_template, jsonify
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import binascii

app = Flask(__name__)

## キーペアの生成
def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return private_key, public_key

## 署名の生成
def sign_message(message, private_key):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    print(h)
    signature = pss.new(key).sign(h)
    return binascii.hexlify(signature).decode()

## 署名の検証
def verify_signature(message, signature, public_key):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    
    print(h.hexdigest())
    verifier = pss.new(key)
    try:
        verifier.verify(h, binascii.unhexlify(signature))
        return True
    except (ValueError, TypeError):
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    private_key, public_key = generate_key_pair()
    return jsonify({'private_key': private_key, 'public_key': public_key})

@app.route('/sign', methods=['POST'])
def sign():
    message = request.json['message']
    private_key = request.json['private_key']
    signature = sign_message(message, private_key)
    return jsonify({'signature': signature})

@app.route('/verify', methods=['POST'])
def verify():
    message = request.json['message']
    signature = request.json['signature']
    public_key = request.json['public_key']
    is_valid = verify_signature(message, signature, public_key)
    return jsonify({'is_valid': is_valid})

if __name__ == '__main__':
    app.run(debug=True)
