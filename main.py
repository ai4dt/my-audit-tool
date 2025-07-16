from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import json
import requests
from datetime import datetime
import PyPDF2
import docx
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# 确保上传文件夹存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('templates', exist_ok=True)

# 允许的文件扩展名
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    """初始化数据库"""
    conn = sqlite3.connect('audit_system.db')
    cursor = conn.cursor()
    
    # 创建用户表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 创建提示词表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS prompts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            content TEXT NOT NULL,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')
    
    # 创建合同表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contracts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_type TEXT NOT NULL,
            uploaded_by INTEGER,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users(id)
        )
    ''')
    
    # 创建提取结果表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS extractions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contract_id INTEGER,
            prompt_id INTEGER,
            result TEXT,
            model_used TEXT,
            extracted_by INTEGER,
            extracted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (contract_id) REFERENCES contracts(id),
            FOREIGN KEY (prompt_id) REFERENCES prompts(id),
            FOREIGN KEY (extracted_by) REFERENCES users(id)
        )
    ''')
    
    # 创建默认管理员用户
    cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        admin_hash = generate_password_hash('admin123')
        cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                      ('admin', admin_hash, 'admin'))
    
    conn.commit()
    conn.close()

def extract_text_from_pdf(file_path):
    """从PDF文件提取文本"""
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text() + "\n"
            return text
    except Exception as e:
        logger.error(f"PDF提取错误: {e}")
        return None

def extract_text_from_docx(file_path):
    """从DOCX文件提取文本"""
    try:
        doc = docx.Document(file_path)
        text = ""
        for paragraph in doc.paragraphs:
            text += paragraph.text + "\n"
        return text
    except Exception as e:
        logger.error(f"DOCX提取错误: {e}")
        return None

def extract_text_from_file(file_path, file_type):
    """根据文件类型提取文本"""
    if file_type == 'pdf':
        return extract_text_from_pdf(file_path)
    elif file_type in ['docx', 'doc']:
        return extract_text_from_docx(file_path)
    elif file_type == 'txt':
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.read()
        except:
            with open(file_path, 'r', encoding='gbk') as file:
                return file.read()
    return None

def call_ollama_api(prompt, model='deepseek-r1:8b'):
    """调用Ollama API"""
    try:
        url = "http://localhost:11434/api/generate"
        data = {
            "model": model,
            "prompt": prompt,
            "stream": False
        }
        response = requests.post(url, json=data, timeout=60)
        if response.status_code == 200:
            return response.json().get('response', '')
        else:
            return f"API调用失败: {response.status_code}"
    except Exception as e:
        logger.error(f"Ollama API调用错误: {e}")
        return f"API调用错误: {str(e)}"

@app.route('/')
def index():
    """首页重定向到登录页面"""
    return redirect(url_for('login'))

@app.route('/login')
def login():
    """登录页面"""
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    """处理登录请求"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    conn = sqlite3.connect('audit_system.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, password_hash, role FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and check_password_hash(user[1], password):
        session['user_id'] = user[0]
        session['username'] = username
        session['role'] = user[2]
        flash('登录成功！', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('用户名或密码错误！', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """退出登录"""
    session.clear()
    flash('已退出登录！', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    """仪表板页面"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/contracts')
def contracts():
    """合同管理页面"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('contracts.html')

@app.route('/upload_contract', methods=['POST'])
def upload_contract():
    """上传合同文件"""
    if 'user_id' not in session:
        return jsonify({'error': '未登录'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': '没有选择文件'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
        filename = timestamp + filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        file_type = filename.rsplit('.', 1)[1].lower()
        
        # 保存到数据库
        conn = sqlite3.connect('audit_system.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO contracts (filename, original_filename, file_path, file_type, uploaded_by)
            VALUES (?, ?, ?, ?, ?)
        ''', (filename, file.filename, file_path, file_type, session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'message': '文件上传成功', 'filename': filename})
    
    return jsonify({'error': '不支持的文件类型'}), 400

@app.route('/prompts')
def prompts():
    """提示词管理页面"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('prompts.html')

@app.route('/api/prompts', methods=['GET'])
def get_prompts():
    """获取提示词列表"""
    if 'user_id' not in session:
        return jsonify({'error': '未登录'}), 401
    
    conn = sqlite3.connect('audit_system.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT p.id, p.name, p.content, p.created_at, u.username
        FROM prompts p
        LEFT JOIN users u ON p.created_by = u.id
        ORDER BY p.created_at DESC
    ''')
    prompts = cursor.fetchall()
    conn.close()
    
    return jsonify([{
        'id': p[0],
        'name': p[1],
        'content': p[2],
        'created_at': p[3],
        'created_by': p[4]
    } for p in prompts])

@app.route('/api/prompts', methods=['POST'])
def create_prompt():
    """创建新提示词"""
    if 'user_id' not in session:
        return jsonify({'error': '未登录'}), 401
    
    data = request.json
    name = data.get('name')
    content = data.get('content')
    
    if not name or not content:
        return jsonify({'error': '名称和内容不能为空'}), 400
    
    conn = sqlite3.connect('audit_system.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO prompts (name, content, created_by)
        VALUES (?, ?, ?)
    ''', (name, content, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'message': '提示词创建成功'})

@app.route('/extract')
def extract():
    """信息提取页面"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('extract.html')

@app.route('/api/contracts', methods=['GET'])
def get_contracts():
    """获取合同列表"""
    if 'user_id' not in session:
        return jsonify({'error': '未登录'}), 401
    
    conn = sqlite3.connect('audit_system.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT c.id, c.original_filename, c.file_type, c.uploaded_at, u.username
        FROM contracts c
        LEFT JOIN users u ON c.uploaded_by = u.id
        ORDER BY c.uploaded_at DESC
    ''')
    contracts = cursor.fetchall()
    conn.close()
    
    return jsonify([{
        'id': c[0],
        'filename': c[1],
        'file_type': c[2],
        'uploaded_at': c[3],
        'uploaded_by': c[4]
    } for c in contracts])

@app.route('/api/extract', methods=['POST'])
def extract_contract_info():
    """提取合同信息"""
    if 'user_id' not in session:
        return jsonify({'error': '未登录'}), 401
    
    data = request.json
    contract_id = data.get('contract_id')
    prompt_id = data.get('prompt_id')
    model = data.get('model', 'deepseek-r1:8b')
    
    if not contract_id or not prompt_id:
        return jsonify({'error': '合同ID和提示词ID不能为空'}), 400
    
    conn = sqlite3.connect('audit_system.db')
    cursor = conn.cursor()
    
    # 获取合同信息
    cursor.execute('SELECT file_path, file_type FROM contracts WHERE id = ?', (contract_id,))
    contract = cursor.fetchone()
    if not contract:
        return jsonify({'error': '合同不存在'}), 404
    
    # 获取提示词
    cursor.execute('SELECT content FROM prompts WHERE id = ?', (prompt_id,))
    prompt = cursor.fetchone()
    if not prompt:
        return jsonify({'error': '提示词不存在'}), 404
    
    # 提取文本
    text = extract_text_from_file(contract[0], contract[1])
    if not text:
        return jsonify({'error': '无法提取文件内容'}), 400
    
    # 构建完整提示词
    full_prompt = f"{prompt[0]}\n\n合同内容:\n{text}"
    
    # 调用AI模型
    result = call_ollama_api(full_prompt, model)
    
    # 保存提取结果
    cursor.execute('''
        INSERT INTO extractions (contract_id, prompt_id, result, model_used, extracted_by)
        VALUES (?, ?, ?, ?, ?)
    ''', (contract_id, prompt_id, result, model, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'result': result})

@app.route('/settings')
def settings():
    """设置页面"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('settings.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
