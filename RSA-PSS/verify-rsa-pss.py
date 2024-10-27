from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.backends import default_backend
import binascii

def verify_rsa_pss_signature(modulus_hex, message, signature_hex):
    # モジュラスを16進数から整数に変換
    modulus = int(modulus_hex, 16)
    
    # 公開指数（通常は65537）
    public_exponent = 65537
    
    # 公開鍵オブジェクトを作成
    public_numbers = rsa.RSAPublicNumbers(public_exponent, modulus)
    public_key = public_numbers.public_key(default_backend())
    
    # 署名を16進数からバイト列に変換
    signature = binascii.unhexlify(signature_hex)
    
    try:
        # 署名を検証
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("署名は有効です。")
    except:
        print("署名は無効です。")

# ユーザー入力
modulus_hex = input("公開鍵のモジュラス（16進数）を入力してください: ")
message = input("メッセージを入力してください: ")
signature_hex = input("署名（16進数）を入力してください: ")

# 署名検証を実行
verify_rsa_pss_signature(modulus_hex, message, signature_hex)
