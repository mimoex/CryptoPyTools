from flask import Flask, render_template, request

app = Flask(__name__)

def format_hex_with_0x(hex_string, bytes_count):
    # 空白とカンマを取り除き、小文字に変換
    hex_string = hex_string.replace(' ', '').replace(',', '').lower()
    
    # 指定されたバイト数に合わせてゼロ埋め
    hex_string = hex_string.zfill(bytes_count * 2)
    
    # バイト数に応じて分割し、0xを付ける
    formatted = [f'0x{hex_string[i:i+bytes_count*2]}' for i in range(0, len(hex_string), bytes_count*2)]
    
    # カンマと空白で結合
    return ', '.join(formatted)

@app.route('/', methods=['GET', 'POST'])
def hex_converter():
    result = ''
    if request.method == 'POST':
        hex_input = request.form['hex_input']
        bytes_count = int(request.form['bytes_count'])
        try:
            result = format_hex_with_0x(hex_input, bytes_count)
        except ValueError:
            result = '無効な16進数入力です'

    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
