from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import binascii

## キーペアの生成
def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

## 署名の生成
def sign_message(message, private_key):
    key = RSA.import_key(private_key)
    h = SHA256.new(message)
    signature = pss.new(key).sign(h)
    return signature

## 署名の検証
def verify_signature(message, signature, public_key):
    key = RSA.import_key(public_key)
    h = SHA256.new(message)
    verifier = pss.new(key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

## 抽出
def extract_public_key_components(public_key):
    key = RSA.import_key(public_key)
    return key.n, key.e

## メイン処理
if __name__ == "__main__":
    # キーペアの生成
    private_key, public_key = generate_key_pair()

    print("公開鍵 (PEM):")
    print(public_key.decode('utf-8'))

    # 公開鍵のコンポーネント（モジュラスと指数）を抽出
    modulus, exponent = extract_public_key_components(public_key)

    print("公開鍵のモジュラス (HEX):")
    print(binascii.hexlify(modulus.to_bytes((modulus.bit_length() + 7) // 8, byteorder='big')).decode())

    print("\n公開鍵の指数 (HEX):")
    print(binascii.hexlify(exponent.to_bytes((exponent.bit_length() + 7) // 8, byteorder='big')).decode())


    # メッセージの設定
    message = b"This is a test message for RSA-PSS signature."
    print("\nメッセージ:", message.decode())

    # 署名の生成
    signature = sign_message(message, private_key)
    print("\n署名 (HEX):")
    decoded_signature = binascii.hexlify(signature).decode()
    if decoded_signature is not None:
        print(decoded_signature)
    else:
        print("署名地値のデコードに失敗しました")

    # 署名の検証
    is_valid = verify_signature(message, signature, public_key)
    print("\n署名検証結果:", "有効" if is_valid else "無効")

    # 改ざんされたメッセージでの検証
    tampered_message = b"This is a tampered message for RSA-PSS signature."
    is_valid_tampered = verify_signature(tampered_message, signature, public_key)
    print("改ざんメッセージの署名検証結果:", "有効" if is_valid_tampered else "無効")
