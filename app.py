from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from models import db, Empresa, Resposta, Usuario, OKR, KR, MacroAcao, Sprint, TarefaSemanal, PostsInstagram, Reuniao, SprintPendente, TarefasFinalizadas, Squad, FormsObjetivos, ObjetivoGeradoChatAprovacao, KrGeradoChatAprovacao, MacroAcaoGeradoChatAprovacao, TarefasMetasSemanais, TarefasAndamento, AnaliseInstagram
import requests
import json
from collections import defaultdict
from flask_migrate import Migrate
from flask import jsonify
from sqlalchemy import desc
from dotenv import load_dotenv
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import time
import re
from flask_login import current_user
from sqlalchemy.exc import IntegrityError
from json import dumps, loads
import openpyxl
import uuid
import logging
from sqlalchemy.orm import joinedload
from sqlalchemy import distinct
import traceback



load_dotenv()  # Carrega as variáveis de ambiente do arquivo .env

url = os.getenv("DATABASE_URL")  # obtém a URL do banco de dados do ambiente
if url.startswith("postgres://"):
    url = url.replace("postgres://", "postgresql://", 1)  # substitui o primeiro 'postgres://' por 'postgresql://'

app = Flask(__name__)
app.secret_key = 'Omega801'
app.config['SQLALCHEMY_DATABASE_URI'] = url or 'sqlite:///C:\\Users\\USER\\PycharmProjects\\bizarte\\test.db'
migrate = Migrate(app, db)
db.init_app(app)
app.jinja_env.globals.update(zip=zip)
app.jinja_env.globals.update(len=len)

# As credenciais que você obteve do Google Cloud Console
CLIENT_ID = '1027763865144-rmpcned2tf61h4ci22gkt561aefu6qkr.apps.googleusercontent.com'
CLIENT_SECRET = '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'

# As permissões que seu aplicativo precisa
SCOPES = ['https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.readonly']

"""
# Carrega as credenciais do arquivo
creds = None
if os.path.exists('token.json'):
    creds = Credentials.from_authorized_user_file('token.json')
if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file(
            'credentials.json', SCOPES)
        creds = flow.run_local_server(port=5000, host='127.0.0.1')
    # Salve as credenciais para a próxima execução
    with open('token.json', 'w') as token:
        token.write(creds.to_json())

# Constrói o serviço de e-mail
service = build('gmail', 'v1', credentials=creds)
"""


# Configuração do gerenciador de login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def gerar_email(usuario):
    empresa = usuario.empresa
    tarefas = "\n".join([sprint.tarefa for sprint in usuario.sprints])
    objetivos = empresa.objetivos_principais
    krs = "\n".join([f"{kr.texto} (OKR: {kr.okr.objetivo})" for okr in empresa.okrs for kr in okr.krs])

    titulo = f'Sprint da Semana {empresa.nome_contato}'
    corpo = f'Seguindo os nossos objetivos que são:\n\n{objetivos}\n\nMedidos pelos Seguintes KR\'s:\n\n{krs}\n\nEssas são as suas tarefas para essa semana:\n\n{tarefas}'

    return titulo, corpo

@app.route('/get_email_content/<int:usuario_id>', methods=['GET'])
def get_email_content(usuario_id):
    usuario = Usuario.query.get(usuario_id)
    titulo, corpo = gerar_email(usuario)
    return jsonify({'titulo': titulo, 'corpo': corpo})

@app.route('/enviar_email/<int:usuario_id>', methods=['GET', 'POST'])
def enviar_email(usuario_id):
    usuario = Usuario.query.get(usuario_id)
    titulo, corpo = gerar_email(usuario)

    msg = MIMEMultipart()
    msg['From'] = 'ai@bizarte.com.br'
    msg['To'] = usuario.email
    msg['Subject'] = titulo
    msg.attach(MIMEText(corpo, 'plain'))

    raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    message = service.users().messages().send(userId='me', body={'raw': raw_message}).execute()

    return redirect(url_for('listar_email_tarefas'))


def gerar_email_tarefa(tarefa):
    empresa_id = tarefa.empresa_id
    usuario = tarefa.usuario.nome
    tarefa_semana = tarefa.tarefa_semana
    passos_datas = "\n\n".join([f"* {passo} - {data}" for passo, data in zip(tarefa.to_do_decoded['passos'], tarefa.to_do_decoded['datas'])])

    titulo = f'Novo Sprint Semanal: Tarefa {tarefa.id}'

    corpo = f"""
    Olá {usuario},

    Estamos iniciando um novo sprint semanal e temos algumas tarefas e sugestões de to-do's para você. 

    **Tarefa da Semana:** {tarefa_semana}

    Aqui estão os passos e datas sugeridos para esta semana:

    {passos_datas}

    Lembre-se, você pode responder a este e-mail a qualquer momento com comentários ou perguntas sobre a tarefa. Suas interações são valiosas e nos ajudarão a planejar melhor o próximo sprint.

    Agradecemos sua colaboração e desejamos uma semana produtiva!

    Atenciosamente,
    Bizarte
    """

    return titulo, corpo




@app.route('/enviar_email_tarefa/<int:tarefa_id>', methods=['GET', 'POST'])
def enviar_email_tarefa(tarefa_id):
    tarefa = TarefaSemanal.query.get(tarefa_id)
    titulo, corpo = gerar_email_tarefa(tarefa)

    msg = MIMEMultipart()
    msg['From'] = 'ai@bizarte.com.br'
    msg['To'] = tarefa.usuario.email
    msg['Subject'] = titulo
    msg.attach(MIMEText(corpo, 'plain'))

    raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    message = service.users().messages().send(userId='me', body={'raw': raw_message}).execute()

    return redirect(url_for('listar_tarefas_semanais_usuario'))


def get_body(msg):
    if 'parts' in msg['payload']:
        part_data = ''.join(part['body']['data'] for part in msg['payload']['parts'])
    else:
        part_data = msg['payload']['body']['data']

    # Os dados do e-mail estão em base64, então precisamos decodificar
    part_data = part_data.replace("-", "+").replace("_", "/")  # Correção para URL-Safe base64
    decoded_bytes = base64.urlsafe_b64decode(part_data)
    decoded_str = str(decoded_bytes, 'utf-8')

    # Dividir o corpo do e-mail na primeira ocorrência de uma linha que começa com '>'
    reply, _, _ = decoded_str.partition("\n>")

    # Remover qualquer HTML restante
    reply = re.sub('<[^<]+?>', '', reply)

    return reply.strip()


"""

def ler_emails_respondidos():
    def format_body(body):
        # Remover caracteres de controle
        body = re.sub(r'\r\n', ' ', body)

        # Extrair a data da resposta
        match = re.search(r'Em seg\., (\d+ de \w+ de \d+)', body)
        if match:
            date = match.group(1)
            body = body.replace(f'Em seg., {date} escreveu:', f'. Em seg., {date}')

        return body

    with app.app_context():
        try:
            # Limpar a coluna 'observacoes' de todas as tarefas
            for tarefa in TarefaSemanal.query.all():
                tarefa.observacoes = "{}"  # Limpar com string JSON vazia
            db.session.commit()

            # Listar os e-mails na caixa de entrada
            results = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
            messages = results.get('messages', [])


            for message in messages:
                msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()

                # Obter o campo 'subject' da mensagem
                subject = ''
                for header in msg['payload']['headers']:
                    if header['name'] == 'Subject':
                        subject = header['value']

                # Verificar se o e-mail é uma resposta a uma tarefa
                if 'Novo Sprint Semanal: Tarefa' in subject:


                    # Extrair o ID da tarefa do assunto do e-mail
                    tarefa_id = int(subject.split(' ')[-1])

                    # Encontrar a tarefa correspondente no banco de dados
                    tarefa = TarefaSemanal.query.get(tarefa_id)

                    if tarefa:

                        body = get_body(msg)
                        body = format_body(body)  # Format the body of the email
                        # Load 'observacoes' if it exists, otherwise create a new dictionary
                        observacoes = json.loads(tarefa.observacoes) if tarefa.observacoes else {}

                        # Add new observation to the dictionary
                        unique_key = f"{datetime.utcnow().isoformat()}_{message['id']}"  # Usar datetime + message_id como chave única
                        observacoes[unique_key] = json.dumps(body)  # Certificar-se de que o body é uma string JSON

                        tarefa.observacoes = json.dumps(observacoes)
                        db.session.commit()


                    else:
                        print(f'Não foi encontrada tarefa com ID: {tarefa_id}')

        except HttpError as error:
            print(f'Um erro ocorreu: {error}')



def job():
    ler_emails_respondidos()

schedule.every(5).minutes.do(job)

def run_schedule():
    while True:
        schedule.run_pending()
        time.sleep(1)

# Cria e inicia uma nova thread que executará a função run_schedule
thread = threading.Thread(target=run_schedule)
thread.start()

"""

@app.cli.command("create-db")
def create_db():
    with app.app_context():
        db.create_all()

@app.cli.command("create-empresa")
def create_empresa():
    empresa = Empresa(
        nome_contato='Nome do Contato',
        email_contato='email@contato.com',
        telefone_contato='123456789',
        endereco_empresa='Endereço da Empresa',
        setor_atuacao='Setor de Atuação',
        tamanho_empresa='Tamanho da Empresa',
        descricao_empresa='Descrição da Empresa',
        objetivos_principais='Objetivos Principais',
        historico_interacoes='Histórico de Interações'
    )
    db.session.add(empresa)
    db.session.commit()
    print("Empresa criada com sucesso.")


@app.cli.command("create-admin")
def create_admin():
    with app.app_context():
        db.create_all()
        nome = input('Enter name: ')
        sobrenome = input('Enter last name: ')
        email = input('Enter email: ')
        celular = input('Enter phone number: ')
        id_empresa = int(input('Enter company id: '))
        cargo = input('Enter position: ')
        status = input('Enter status: ')
        password = input('Enter password: ')

        new_user = Usuario(
            nome=nome,
            sobrenome=sobrenome,
            email=email,
            celular=celular,
            id_empresa=id_empresa,
            cargo=cargo,
            status=status,
            password=password,
            is_admin=True
        )

        db.session.add(new_user)
        db.session.commit()
        print(f'User created: {new_user.email}')  # Add this line




def verify_password(self, password):
    if self.password_hash is None:
        return False
    return check_password_hash(self.password_hash, password)


class User(UserMixin):
    pass

@login_manager.user_loader
def user_loader(email):
    user = Usuario.query.filter_by(email=email).first()
    if user is None:
        return

    user = User()
    user.id = email
    return user



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    email = request.form['email']
    user = Usuario.query.filter_by(email=email).first()
    if user is None:
        return abort(401)

    if user.verify_password(request.form['password']):
        user_auth = User()
        user_auth.id = user.id  # use user id instead of email
        login_user(user_auth)
        return redirect(url_for('home'))

    return abort(401)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@login_manager.user_loader
def user_loader(user_id):
    return Usuario.query.get(int(user_id))

@login_manager.request_loader
def request_loader(request):
    user_id = request.form.get('user_id')
    if user_id is None:
        return
    return Usuario.query.get(int(user_id))

def json_loads(value):
    return json.loads(value)

app.jinja_env.globals.update(json=json)




@app.route('/')
@login_required
def home():
    return render_template('home.html')

@app.route('/empresas', methods=['GET'])
@login_required
def listar_empresas():
    if current_user.is_admin:
        empresas = Empresa.query.all()
    else:
        empresas = Empresa.query.filter_by(id=current_user.id_empresa).all()
    return render_template('listar_empresas.html', empresas=empresas)

@app.route('/cadastrar/empresa', methods=['GET', 'POST'])
@login_required
def cadastrar_empresa():
    if not current_user.is_admin:
        abort(403)  # Forbidden
    if request.method == 'POST':
        empresa = Empresa(
            nome_contato=request.form.get('nome_contato'),
            email_contato=request.form.get('email_contato'),
            telefone_contato=request.form.get('telefone_contato'),
            endereco_empresa=request.form.get('endereco_empresa'),
            setor_atuacao=request.form.get('setor_atuacao'),
            tamanho_empresa=request.form.get('tamanho_empresa'),
            descricao_empresa=request.form.get('descricao_empresa'),
            objetivos_principais=request.form.get('objetivos_principais'),
            historico_interacoes=request.form.get('historico_interacoes')
        )
        db.session.add(empresa)
        db.session.commit()
        return redirect(url_for('listar_empresas'))
    return render_template('cadastrar_empresa.html')

@app.route('/atualizar/empresa/<int:id>', methods=['GET', 'POST'])
@login_required
def atualizar_empresa(id):
    empresa = Empresa.query.get(id)
    if empresa.id != current_user.id_empresa and not current_user.is_admin:
        abort(403)  # Forbidden
    if request.method == 'POST':
        empresa.nome_contato = request.form['nome_contato']
        empresa.email_contato = request.form['email_contato']
        empresa.telefone_contato = request.form['telefone_contato']
        empresa.endereco_empresa = request.form['endereco_empresa']
        empresa.setor_atuacao = request.form['setor_atuacao']
        empresa.tamanho_empresa = request.form['tamanho_empresa']
        empresa.descricao_empresa = request.form['descricao_empresa']
        empresa.objetivos_principais = request.form['objetivos_principais']
        empresa.historico_interacoes = request.form['historico_interacoes']
        db.session.commit()
        return redirect(url_for('listar_empresas'))
    return render_template('atualizar_empresa.html', empresa=empresa)

@app.route('/deletar_empresa/<int:id>', methods=['POST'])
@login_required
def deletar_empresa(id):
    if not current_user.is_admin:
        abort(403)  # Forbidden
    empresa = Empresa.query.get_or_404(id)
    db.session.delete(empresa)
    db.session.commit()
    return redirect(url_for('listar_empresas'))


@app.route('/cadastrar/usuario', methods=['GET', 'POST'])
@login_required
def cadastrar_usuario():
    if request.method == 'POST':
        hashed_password = generate_password_hash(request.form.get('password'), method='sha256')
        usuario = Usuario(
            nome=request.form.get('nome'),
            sobrenome=request.form.get('sobrenome'),
            email=request.form.get('email'),
            celular=request.form.get('celular'),
            id_empresa=request.form.get('id_empresa'),
            cargo=request.form.get('cargo'),
            status=request.form.get('status'),
            password=request.form.get('password'),
        )
        db.session.add(usuario)
        db.session.commit()
        return redirect(url_for('listar_usuarios'))
    if current_user.is_admin:
        empresas = Empresa.query.all()
    else:
        empresas = Empresa.query.filter_by(id=current_user.id_empresa).all()
    return render_template('cadastrar_usuario.html', empresas=empresas)


@app.route('/usuarios', methods=['GET'])
@login_required
def listar_usuarios():
    if current_user.is_admin:
        usuarios = Usuario.query.all()
    else:
        usuarios = Usuario.query.filter_by(id_empresa=current_user.id_empresa).all()
    return render_template('listar_usuarios.html', usuarios=usuarios)



@app.route('/atualizar/usuario/<int:id>', methods=['GET', 'POST'])
@login_required
def atualizar_usuario(id):
    usuario = Usuario.query.get(id)
    if usuario.id_empresa != current_user.id_empresa and not current_user.is_admin:
        abort(403)  # Forbidden
    if request.method == 'POST':
        usuario.nome = request.form['nome']
        usuario.sobrenome = request.form['sobrenome']
        usuario.email = request.form['email']
        usuario.celular = request.form['celular']
        usuario.id_empresa = request.form['id_empresa']  # Alterado aqui
        usuario.cargo = request.form['cargo']
        usuario.status = request.form['status']
        if request.form['password']:
            usuario.password = request.form['password']
        db.session.commit()
        return redirect(url_for('listar_usuarios'))
    if current_user.is_admin:
        empresas = Empresa.query.all()
    else:
        empresas = Empresa.query.filter_by(id=current_user.id_empresa).all()
    return render_template('atualizar_usuario.html', usuario=usuario, empresas=empresas)






@app.route('/deletar_usuario/<int:id>', methods=['POST'])
@login_required
def deletar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    db.session.delete(usuario)
    db.session.commit()
    return redirect(url_for('listar_usuarios'))





@app.route('/planejamento_redes', methods=['GET', 'POST'])
@login_required
def planejamento_redes():
    empresas = Empresa.query.all()
    if request.method == 'POST':
        empresa_id = request.form.get('empresa')  # Obtenha o ID da empresa a partir do formulário
        empresa = Empresa.query.get(empresa_id)
        empresa.descricao_empresa = request.form.get('descricao_empresa')
        db.session.commit()
        # Armazenar o ID da empresa na sessão
        session['empresa_id'] = empresa_id
        # Inicializar a lista de perguntas
        session['perguntas'] = [
            f"Agora você é um especialista de redes sociais dessa empresa: {empresa.descricao_empresa}",
            "Monte uma persona para esse negocio {empresa.descricao_empresa} com a dores, objetivos e interesses?",
            "Passe um entendimento de como esse perfil se comportam nas redes sociais e como eles consomem conteudo?",
            "Crie o publico alvo para as redes sociais desse negocio?",
            "Defina quais são os objetivos desse negocio para as redes sociais?",
            "Quais redes sociais e as estrategias a devem ser usadas para essa empresa?",
            "Crie KPI de acompanhamento para essa rede para os proximos 3 meses para essas redes com os seus objetivos a serem alcançados ?"
        ]
        # Inicializar a lista de respostas
        session['respostas'] = []
        # Inicializar a lista de mensagens
        session['messages'] = [{"role": "system", "content": "You are a helpful assistant."}]
        # Redirecionar para a primeira pergunta
        return redirect(url_for('responder_pergunta', id=0))
    return render_template('planejamento_redes.html', empresas=empresas)




@app.route('/responder_pergunta/<int:id>', methods=['GET', 'POST'])
@login_required
def responder_pergunta(id):
    # Obter o ID da empresa da sessão
    empresa_id = session.get('empresa_id')
    if not empresa_id:
        # Se o ID da empresa não estiver na sessão, redirecionar para a página de planejamento
        return redirect(url_for('planejamento_redes'))

    if id >= len(session['perguntas']):
        # Todas as perguntas foram respondidas
        return redirect(url_for('visualizar_planejamento_atual', id_empresa=empresa_id))

    pergunta = session['perguntas'][id]

    # Inicializa as mensagens com a mensagem do sistema se for a primeira pergunta
    if id == 0:
        messages = [{"role": "system", "content": "You are a helpful assistant."}]
    else:
        # Caso contrário, obter as mensagens da sessão
        messages = session.get('messages')

    if request.method == 'POST':
        if 'aprovado' in request.form:
            # Se o método for POST e o usuário aprovou a resposta
            # Verificar se a lista de respostas está vazia antes de tentar acessar o último elemento
            if session['respostas']:
                resposta = session['respostas'][-1]  # A última resposta é a aprovada
            else:
                resposta = None

            # Mapeamento de classificações
            classificacoes = {
                0: "Apresentação",
                1: "Persona",
                2: "Comportamento da persona das Redes",
                3: "Público-Alvo",
                4: "Objetivos das Redes",
                5: "Redes Socais",
                6: "KPI's de acompanhamento",
            }

            resposta_db = Resposta(id_empresa=empresa_id, pergunta=pergunta, resposta=resposta, classificacao=classificacoes[id])
            db.session.add(resposta_db)
            db.session.commit()

            # Redirecionar para a próxima pergunta
            return redirect(url_for('responder_pergunta', id=id+1))
        elif 'feedback_submit' in request.form:
            # Se o método for POST e o usuário enviou feedback
            feedback = request.form['feedback']
            # Adiciona o feedback à lista de mensagens
            messages.append({"role": "user", "content": feedback})

    resposta, messages = perguntar_gpt(pergunta, id, messages)

    # Salvar a resposta e as mensagens na variável de sessão
    session['respostas'].append(resposta)
    session['messages'] = messages

    return render_template('responder_pergunta.html', pergunta=pergunta, resposta=resposta, id=id)



def perguntar_gpt(pergunta, pergunta_id, messages):
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + os.getenv("OPENAI_API_KEY")
    }

    # Adiciona a pergunta atual
    messages.append({"role": "user", "content": pergunta})

    data = {
        "model": "gpt-4",
        "messages": messages
    }

    backoff_time = 1  # Começamos com um tempo de espera de 1 segundo
    while True:
        try:
            response = requests.post(url, headers=headers, data=json.dumps(data))
            response.raise_for_status()

            # Adiciona a resposta do modelo à lista de mensagens
            messages.append({"role": "assistant", "content": response.json()['choices'][0]['message']['content']})

            return response.json()['choices'][0]['message']['content'], messages
        except requests.exceptions.HTTPError as e:
            if e.response.status_code in (429, 520, 502, 503):  # Limite de requisições atingido ou erro de servidor
                print(f"Erro {e.response.status_code} atingido. Aguardando antes de tentar novamente...")
                time.sleep(backoff_time)  # Aguarda antes de tentar novamente
                backoff_time *= 2  # Aumenta o tempo de espera
            else:
                raise



@app.route('/visualizar_planejamento_atual/<int:id_empresa>', methods=['GET'])
@login_required
def visualizar_planejamento_atual(id_empresa):
    # Mapeamento de classificações
    classificacoes = [
        "Apresentação",
        "Persona",
        "Comportamento da persona das Redes",
        "Público-Alvo",
        "Objetivos das Redes",
        "Redes Socais",
        "KPI's de acompanhamento",
    ]

    respostas = []
    for classificacao in classificacoes:
        # Buscar a última resposta de cada classificação
        resposta = Resposta.query.filter_by(id_empresa=id_empresa, classificacao=classificacao).order_by(Resposta.data_criacao.desc()).first()
        if resposta:
            respostas.append(resposta)

    return render_template('visualizar_planejamento.html', respostas=respostas)


def convert_string_to_datetime(date_string):
    return datetime.strptime(date_string, '%Y-%m-%d')

@app.route('/cadastrar/okr', methods=['GET', 'POST'])
@login_required
def cadastrar_okr():
    if request.method == 'POST':
        try:
            # Obter o squad_id do formulário
            squad_id = request.form.get('squad')
            if not squad_id:
                # Se o squad_id não for fornecido, mostrar uma mensagem de erro.
                flash('Por favor, selecione um squad.', 'error')
                return redirect(url_for('cadastrar_okr'))

            okr = OKR(
                id_empresa=request.form.get('empresa'),
                squad_id=squad_id,  # Aqui estamos incluindo o squad_id
                objetivo=request.form.get('objetivo'),
                data_inicio=convert_string_to_datetime(request.form.get('data_inicio')),
                data_fim=convert_string_to_datetime(request.form.get('data_fim')),
            )
            db.session.add(okr)
            db.session.commit()
            return redirect(url_for('listar_okrs'))  # Redireciona para a página de listagem de OKRs
        except ValueError:
            flash('A data fornecida é inválida. Use o formato YYYY-MM-DD.', 'error')

    if current_user.is_admin:
        empresas = Empresa.query.all()
    else:
        empresas = Empresa.query.filter_by(id=current_user.id_empresa).all()

    # Supondo que você deseja carregar todos os squads caso seja admin, ou apenas os squads associados à empresa do usuário
    if current_user.is_admin:
        squads = Squad.query.all()
    else:
        squads = Squad.query.filter_by(empresa_id=current_user.id_empresa).all()

    return render_template('cadastrar_okr.html', empresas=empresas, squads=squads)  # Enviando squads para o template também


@app.route('/listar/okrs', methods=['GET'])
@login_required
def listar_okrs():
    if current_user.is_admin:
        okrs = OKR.query.all()  # Substitua OKR pela classe do seu modelo de OKR
    else:
        okrs = OKR.query.filter_by(id_empresa=current_user.id_empresa).all()
    return render_template('listar_okrs.html', okrs=okrs)

@app.route('/atualizar/okr/<int:id>', methods=['GET', 'POST'])
@login_required
def atualizar_okr(id):
    okr = OKR.query.get(id)
    if okr.id_empresa != current_user.id_empresa and not current_user.is_admin:
        abort(403)  # Forbidden

    if request.method == 'POST':
        okr.id_empresa = request.form['empresa']
        okr.squad_id = request.form['squad']  # Adiciona essa linha para atualizar o squad
        okr.objetivo = request.form['objetivo']
        okr.data_inicio = datetime.strptime(request.form['data_inicio'], "%Y-%m-%d")
        okr.data_fim = datetime.strptime(request.form['data_fim'], "%Y-%m-%d")
        db.session.commit()
        return redirect(url_for('listar_okrs'))

    if current_user.is_admin:
        empresas = Empresa.query.all()
        squads = Squad.query.all()  # Se for admin, buscar todos os squads
    else:
        empresas = Empresa.query.filter_by(id=current_user.id_empresa).all()
        squads = Squad.query.filter_by(empresa_id=current_user.id_empresa).all()

    return render_template('atualizar_okr.html', okr=okr, empresas=empresas, squads=squads)  # Enviando squads para o template também


@app.route('/deletar/okr/<int:id>', methods=['POST'])
@login_required
def deletar_okr(id):
    okr = OKR.query.get(id)
    if okr.id_empresa != current_user.id_empresa and not current_user.is_admin:
        abort(403)  # Forbidden
    for kr in okr.krs:
        db.session.delete(kr)
    db.session.delete(okr)
    db.session.commit()
    return redirect(url_for('listar_okrs'))



@app.route('/listar/krs', methods=['GET'])
@login_required
def listar_krs():
    if current_user.is_admin:
        krs = KR.query.all()
    else:
        krs = KR.query.filter_by(id_empresa=current_user.id_empresa).all()
    return render_template('listar_krs.html', krs=krs)


@app.route('/cadastrar/kr', methods=['GET', 'POST'])
@login_required
def cadastrar_kr():
    if request.method == 'POST':
        id_empresa = int(request.form.get('empresa', '0'))
        id_okr = int(request.form.get('objetivo', '0'))
        texto = request.form['texto']
        meta = request.form['meta']  # Pega o valor do campo "meta" do formulário
        squad_id = int(request.form.get('squad', '0'))

        # Verificações opcionais para o campo "meta" (ajuste conforme necessário)
        if not meta or len(meta) > 255:
            return "Meta inválida", 400

        # Verifique se o OKR e o Squad existem
        okr = OKR.query.get(id_okr)
        squad = Squad.query.get(squad_id)

        if okr is None:
            return "OKR não encontrado", 404
        if squad is None:
            return "Squad não encontrado", 404

        kr = KR(id_empresa=id_empresa, id_okr=id_okr, squad_id=squad_id, texto=texto, meta=meta, data_inclusao=datetime.utcnow())
        db.session.add(kr)
        db.session.commit()
        return redirect(url_for('listar_krs'))

    if current_user.is_admin:
        empresas = Empresa.query.all()
    else:
        empresas = Empresa.query.filter_by(id=current_user.id_empresa).all()

    return render_template('cadastrar_kr.html', empresas=empresas)


@app.route('/atualizar/kr/<int:id>', methods=['GET', 'POST'])
@login_required
def atualizar_kr(id):
    kr = KR.query.get(id)
    if kr.id_empresa != current_user.id_empresa and not current_user.is_admin:
        abort(403)  # Forbidden
    if request.method == 'POST':
        texto = request.form['texto']
        meta = request.form['meta']  # Novo campo

        kr.texto = texto
        kr.meta = meta   # Atualize a meta
        db.session.commit()
        return redirect(url_for('listar_krs'))

    if current_user.is_admin:
        empresas = Empresa.query.all()
    else:
        empresas = Empresa.query.filter_by(id=current_user.id_empresa).all()
    okrs = OKR.query.filter_by(id_empresa=kr.id_empresa).all()

    return render_template('atualizar_kr.html', empresas=empresas, kr=kr, okrs=okrs)






@app.route('/update_kr/<int:krId>', methods=['POST'])
@login_required
def update_kr(krId):
    okrId = request.form['objetivo']  # assumindo que isso retorna um id de OKR
    kr = KR.query.get(krId)

    if kr.id_empresa != current_user.id_empresa and not current_user.is_admin:
        abort(403)  # Forbidden

    # Obtenha a instância OKR e atribua-a ao KR.
    okr = OKR.query.get(okrId)
    if okr is None:
        return "OKR não encontrado", 404
    kr.okr = okr

    db.session.commit()
    return 'OK', 200

@app.route('/get_okrs/<int:empresa_id>', methods=['GET'])
@login_required
def get_okrs(empresa_id):
    if empresa_id != current_user.id_empresa and not current_user.is_admin:
        abort(403)  # Forbidden

    empresa = Empresa.query.get(empresa_id)
    if not empresa:
        abort(404)  # Retorna um erro 404 se a empresa não for encontrada
    okrs = OKR.query.filter_by(id_empresa=empresa.id).all()

    # Converte a lista de OKRs em uma lista de dicionários para poder ser serializada em JSON
    okrs_dict = []
    for okr in okrs:
        okrs_dict.append({'id': okr.id, 'objetivo': okr.objetivo})

    return jsonify(okrs_dict)

@app.route('/get_okrs_by_squad/<int:squad_id>', methods=['GET'])
@login_required
def get_okrs_by_squad(squad_id):
    squad = Squad.query.get(squad_id)
    if not squad:
        abort(404)  # Retorna um erro 404 se o Squad não for encontrado

    # Verificação adicional de permissão: se o usuário não é da empresa do Squad e não é admin, nega acesso
    if squad.empresa_id != current_user.id_empresa and not current_user.is_admin:
        abort(403)  # Forbidden

    okrs = OKR.query.filter_by(squad_id=squad.id).all()

    # Converte a lista de OKRs em uma lista de dicionários para poder ser serializada em JSON
    okrs_dict = [{'id': okr.id, 'objetivo': okr.objetivo} for okr in okrs]

    return jsonify(okrs_dict)



@app.route('/deletar/kr/<int:id>', methods=['POST'])
@login_required
def deletar_kr(id):
    kr = KR.query.get(id)

    if kr.id_empresa != current_user.id_empresa and not current_user.is_admin:
        abort(403)  # Forbidden

    db.session.delete(kr)
    db.session.commit()
    return redirect(url_for('listar_krs'))

@app.route('/get_objectives/<int:empresa_id>', methods=['GET'])
@login_required
def get_objectives(empresa_id):
    if empresa_id != current_user.id_empresa and not current_user.is_admin:
        abort(403)  # Forbidden

    okrs = OKR.query.filter_by(id_empresa=empresa_id).all()
    objectives = [{'id': okr.id, 'objetivo': okr.objetivo} for okr in okrs]
    return jsonify(objectives)


@app.route('/get_objectives_by_squad/<int:squad_id>', methods=['GET'])
@login_required
def get_objectives_by_squad(squad_id):
    if not current_user.is_admin:
        squad = Squad.query.get(squad_id)
        if squad.empresa_id != current_user.id_empresa:
            abort(403)  # Forbidden

    okrs = OKR.query.filter_by(squad_id=squad_id).all()
    objectives = [{'id': okr.id, 'objetivo': okr.objetivo} for okr in okrs]
    return jsonify(objectives)


@app.route('/listar_macro_acao')
@login_required
def listar_macro_acao():
    if current_user.is_admin:
        krs = KR.query.all()  # Busca todos os KR do banco de dados se for admin
    else:
        krs = KR.query.filter_by(id_empresa=current_user.id_empresa).all()  # Busca apenas os KR da empresa do usuário
    return render_template('listar_macro_acao.html', krs=krs)


@app.route('/gerar_macro_acao/<int:id>', methods=['GET', 'POST'])
@login_required
def gerar_macro_acao(id):
    time_now = datetime.utcnow()  # Salve o horário atual
    kr = KR.query.get(id)  # Busca o KR específico pelo id
    if kr is None:
        flash('KR não encontrado', 'error')
        return redirect(url_for('listar_macro_acao'))

    if request.method == 'POST':
        # Gera a pergunta para o GPT-4
        pergunta = f"Considerando o Key Result {kr.texto} definidos para o objetivo: {kr.okr.objetivo} para a empresa {kr.okr.empresa.descricao_empresa} para os próximos 90 dias, eu gostaria que você gerasse uma lista de macro ações estratégicas necessárias para alcançar esses KRs. Depois de gerar essa lista, por favor, organize as ações em ordem de prioridade, levando em consideração a eficiência e a eficácia na realização dos KRs. Provide them in JSON format with the following keys: prioridade, acao."
        messages = [{"role": "system", "content": "You are a helpful assistant."}]
        resposta, messages = perguntar_gpt(pergunta, id, messages)

        # Carrega a resposta JSON
        resposta_dict = json.loads(resposta)
        # Verifica se a resposta é uma lista ou um dicionário com a chave 'acoes'
        if isinstance(resposta_dict, list):
            macro_acoes = resposta_dict
        elif 'acoes' in resposta_dict:
            macro_acoes = resposta_dict['acoes']
        else:
            raise ValueError("Resposta inesperada: não é uma lista nem contém a chave 'acoes'")

        # Adiciona um ID a cada ação
        for i, acao in enumerate(macro_acoes, start=1):
            acao['id'] = i

        # Armazena a resposta, as macro ações e o id do KR na sessão
        session['resposta'] = resposta
        session['macro_acoes'] = macro_acoes
        session['kr_id'] = id

        # Redireciona para a página de revisão
        return redirect(url_for('revisar_macro_acoes'))

    return render_template('gerar_macro_acao.html', kr=kr)



@app.route('/revisar_macro_acoes', methods=['GET', 'POST'])
@login_required
def revisar_macro_acoes():
    if request.method == 'POST':
        macro_acoes = session.get('macro_acoes')
        kr_id = session.get('kr_id')
        kr = KR.query.get(kr_id)

        for acao in macro_acoes:
            # Cria uma nova entrada em MacroAcao para cada ação na resposta
            macro_acao = MacroAcao(
                texto=acao['acao'],
                aprovada=False,  # Inicialmente, a ação não é aprovada
                kr_id=kr_id,
                objetivo=kr.okr.objetivo,
                objetivo_id=kr.okr.id,
                empresa=kr.okr.empresa.nome_contato,
                empresa_id=kr.okr.empresa.id
            )

            # Salva a nova entrada no banco de dados
            db.session.add(macro_acao)
        db.session.commit()

        # Redireciona para a página de resultados
        return redirect(url_for('mostrar_resultados', kr_id=kr_id))

    else:
        macro_acoes = session.get('macro_acoes')
        return render_template('revisar_macro_acoes.html', macro_acoes=macro_acoes)

@app.route('/refazer_macro_acao/<int:id>', methods=['POST'])
@login_required
def refazer_macro_acao(id):
    feedback = request.form.get('feedback')  # Obtenha o feedback do formulário
    resposta_anterior = session.get('resposta')  # Obtenha a resposta anterior da sessão
    kr = KR.query.get(id)  # Busca o KR específico pelo id

    # Gera a pergunta para o GPT-4
    pergunta = f"Considerando essa resposta {resposta_anterior}, e esse feedback {feedback}, Considerando o Key Result {kr.texto} definidos para o objetivo: {kr.okr.objetivo} para a empresa {kr.okr.empresa.descricao_empresa} para os próximos 90 dias, eu gostaria que você gerasse uma lista de macro ações estratégicas necessárias para alcançar esses KRs. Depois de gerar essa lista, por favor, organize as ações em ordem de prioridade, levando em consideração a eficiência e a eficácia na realização dos KRs. Provide them in JSON format with the following keys: prioridade, acao."
    messages = [{"role": "system", "content": "You are a helpful assistant."}]
    resposta, messages = perguntar_gpt(pergunta, id, messages)

    print(f'Resposta: {resposta}')  # Imprime a resposta

    # Carrega a resposta JSON
    resposta_dict = json.loads(resposta)
    # Verifica se a resposta é uma lista ou um dicionário com a chave 'acoes'
    if isinstance(resposta_dict, list):
        macro_acoes = resposta_dict
    elif 'acoes' in resposta_dict:
        macro_acoes = resposta_dict['acoes']
    else:
        raise ValueError("Resposta inesperada: não é uma lista nem contém a chave 'acoes'")

    # Adiciona um ID a cada ação
    for i, acao in enumerate(macro_acoes, start=1):
        acao['id'] = i

    # Armazena a nova resposta e as novas macro ações na sessão
    session['resposta'] = resposta
    session['macro_acoes'] = macro_acoes

    # Redireciona para a página de revisão
    return redirect(url_for('revisar_macro_acoes'))



@app.route('/mostrar_resultados/<int:kr_id>')
@login_required
def mostrar_resultados(kr_id):
    kr = KR.query.get(kr_id)  # Busca o KR novamente do banco de dados

    # Busca as macro ações no banco de dados e as ordena por data_inclusao (descendente)
    macro_acoes = MacroAcao.query.filter_by(kr_id=kr_id, aprovada=False)\
                      .order_by(MacroAcao.data_inclusao.desc())\
                      .all()  # Remova `.all()` e adicione `.first()` para obter apenas a mais recente ou `.limit(n)` para as `n` mais recentes

    return render_template('mostrar_resultados.html', macro_acoes=macro_acoes, kr=kr)





@app.route('/atualizar_macro_acao/<int:id>', methods=['GET', 'POST'])
@login_required
def atualizar_macro_acao(id):
    macro_acao = MacroAcao.query.get(id)

    if macro_acao.kr.id_empresa != current_user.id_empresa and not current_user.is_admin:
        abort(403)  # Forbidden

    if request.method == 'POST':
        macro_acao.texto = request.form['texto']
        macro_acao.aprovada = True if request.form['aprovada'] == 'sim' else False
        db.session.commit()
        return redirect(url_for('listar_macro_acoes_aprovadas'))
    return render_template('atualizar_macro_acao.html', acao=macro_acao)



@app.route('/deletar_macro_acao/<int:id>', methods=['GET'])
@login_required
def deletar_macro_acao(id):
    macro_acao = MacroAcao.query.get(id)

    if macro_acao.kr.id_empresa != current_user.id_empresa and not current_user.is_admin:
        abort(403)  # Forbidden

    db.session.delete(macro_acao)
    db.session.commit()
    return redirect(url_for('listar_macro_acoes_aprovadas'))


@app.route('/listar_macro_acoes_aprovadas', methods=['GET'])
@login_required
def listar_macro_acoes_aprovadas():
    if current_user.is_admin:
        macro_acoes = MacroAcao.query.options(joinedload(MacroAcao.squad)).all()  # Carrega Squad junto com MacroAcao
    else:
        macro_acoes = MacroAcao.query.join(KR).filter(KR.id_empresa == current_user.id_empresa).options(joinedload(MacroAcao.squad)).all()  # Carrega Squad junto com MacroAcao
    return render_template('listar_macro_acoes_aprovadas.html', macro_acoes=macro_acoes)


@app.route('/montagem_sprint_semana')
@login_required
def montagem_sprint_semana():
    empresas = Empresa.query.all()
    return render_template('montagem_sprint_semana.html', empresas=empresas)

@app.route('/get_objetivos/<int:empresa_id>')
@login_required
def get_objetivos(empresa_id):
    objetivos = OKR.query.filter_by(id_empresa=empresa_id).all()
    return jsonify([{'id': objetivo.id, 'objetivo': objetivo.objetivo} for objetivo in objetivos])


@app.route('/get_krs/<int:empresa_id>/<int:squad_id>/<int:objetivo_id>')
@login_required
def get_krs(empresa_id, squad_id, objetivo_id):
    krs = KR.query.filter_by(id_empresa=empresa_id, squad_id=squad_id, id_okr=objetivo_id).all()
    krs_list = [{'id': kr.id, 'texto': kr.texto} for kr in krs]
    return jsonify(krs_list)



@app.route('/get_empresa_info/<int:empresa_id>', methods=['GET'])
@login_required
def get_empresa_info(empresa_id):
    empresa = Empresa.query.get(empresa_id)
    okrs = OKR.query.filter_by(id_empresa=empresa_id).all()
    krs = KR.query.filter_by(id_empresa=empresa_id).all()
    macro_acoes = MacroAcao.query.filter_by(empresa_id=empresa_id).all()
    usuarios = Usuario.query.filter_by(id_empresa=empresa_id).all()

    empresa_info = {
        'descricao_empresa': empresa.descricao_empresa,
        'objetivos': [okr.objetivo for okr in okrs],
        'krs': [kr.texto for kr in krs],
        'macro_acoes': [acao.texto for acao in macro_acoes],
        'usuarios': [f"{usuario.nome} {usuario.sobrenome}, {usuario.cargo}" for usuario in usuarios]
    }

    return jsonify(empresa_info)


@app.route('/get_descricao_sprint/<int:empresa_id>')
@login_required
def get_descricao_sprint(empresa_id):
    empresa = Empresa.query.get(empresa_id)
    return jsonify(descricao=empresa.descricao_empresa)

@app.route('/get_cargos_sprint/<int:empresa_id>')
@login_required
def get_cargos_sprint(empresa_id):
    usuarios = Usuario.query.filter_by(id_empresa=empresa_id)
    return jsonify([usuario.cargo for usuario in usuarios])

@app.route('/get_okrs_sprint/<int:empresa_id>')
@login_required
def get_okrs_sprint(empresa_id):
    okrs = OKR.query.filter_by(id_empresa=empresa_id)
    return jsonify([okr.objetivo for okr in okrs])

@app.route('/get_krs_sprint/<int:empresa_id>')
@login_required
def get_krs_sprint(empresa_id):
    krs = KR.query.filter_by(id_empresa=empresa_id)
    return jsonify([kr.texto for kr in krs])

@app.route('/get_macro_acoes_sprint/<int:empresa_id>')
@login_required
def get_macro_acoes_sprint(empresa_id):
    macro_acoes = MacroAcao.query.filter_by(id_empresa=empresa_id)
    return jsonify([macro_acao.texto for macro_acao in macro_acoes])


@app.route('/criar_sprint_semana', methods=['GET', 'POST'])
@login_required
def criar_sprint_semana():
    if request.method == 'POST':
        # Coletar informações da empresa
        empresa_id = request.form.get('empresa')
        empresa = db.session.get(Empresa, empresa_id)  # Obter a empresa pelo ID
        if empresa is None:
            return redirect(url_for('montagem_sprint_semana'))  # Se a empresa não existir, redirecionar

        # Obter as macro ações associadas à empresa
        macro_acoes = MacroAcao.query.filter_by(empresa_id=empresa.id).all()

        # Obter os OKRs e usuários associados à empresa
        okrs = OKR.query.filter_by(id_empresa=empresa.id).all()
        usuarios = Usuario.query.filter_by(id_empresa=empresa.id).all()

        # Formatar as listas como strings
        macro_acoes_str = ', '.join([acao.texto for acao in macro_acoes])
        okrs_str = ', '.join([okr.objetivo for okr in okrs])
        usuarios_str = ', '.join([f'{usuario.nome} ({usuario.cargo})' for usuario in usuarios])

        # Construir a pergunta para o GPT-4
        pergunta = f"Inteligência Artificial GPT, considerando a lista de macro ações estratégicas geradas a partir dos OKRs {okrs_str} da empresa para os próximos 90 dias, as habilidades específicas dos colaboradores da equipe {usuarios_str}, peço que você desenvolva um plano de sprint para a próxima semana. Para ajudar a moldar esse plano, aqui estão as informações que você precisa considerar: Lista de macro ações: {macro_acoes_str}, Habilidades dos colaboradores: {usuarios_str}, Resumo sobre a empresa: {empresa.descricao_empresa}. Com base nessas informações, por favor, crie um plano de sprint que defina as tareas específicas a serem realizadas na próxima semana, priorizando as ações mais críticas e detalhando como essas tarefas suportam os OKRs definidos. Além disso, coloque o responsável por cada tarefa específica de acordo com a tarefa e o cargo dos colaboradores. Provide them in JSON format with the following keys: prioridade, tarefa, responsável."
        print(pergunta)
        messages = [{"role": "system", "content": "You are a helpful assistant."}]
        resposta, messages = perguntar_gpt(pergunta, empresa_id, messages)

        # Encontra o início e o final do objeto JSON na resposta
        inicio_json = resposta.find('[')
        final_json = resposta.rfind(']')

        # Se não encontramos um objeto JSON, lançamos um erro
        if inicio_json == -1 or final_json == -1:
            print(f"Erro ao decodificar JSON: não foi possível encontrar um objeto JSON na resposta")
            print(f"Resposta: {resposta}")
            return redirect(url_for('montagem_sprint_semana'))  # Se a decodificação falhar, redirecionar

        json_str = resposta[inicio_json:final_json+1]

        # Carrega a resposta JSON
        try:
            sprints = json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f"Erro ao decodificar JSON: {str(e)}")
            print(f"Resposta:{resposta}")

            return redirect(url_for('montagem_sprint_semana'))  # Se a decodificação falhar, redirecionar

        # Armazena a resposta, os sprints e o id da empresa na sessão
        session['resposta'] = resposta
        session['sprints'] = sprints
        session['empresa_id'] = empresa_id

        # Redireciona para a página de revisão
        return redirect(url_for('revisar_sprint'))

    # Renderiza o template de criação de sprint
    return render_template('montagem_sprint_semana.html')




@app.route('/criar_sprint_semana_revisao', methods=['GET', 'POST'])
@login_required
def criar_sprint_semana_revisao():
    if request.method == 'POST':
        empresa_id = request.form.get('empresa')
        empresa = db.session.get(Empresa, empresa_id)
        if empresa is None:
            return redirect(url_for('montagem_sprint_semana'))

        SprintPendente.query.filter_by(empresa_id=empresa.id).delete()

        macro_acoes = MacroAcao.query.filter_by(empresa_id=empresa.id).all()
        okrs = OKR.query.filter_by(id_empresa=empresa.id).all()
        krs = KR.query.filter_by(id_empresa=empresa.id).all()
        sprints = Sprint.query.filter_by(empresa_id=empresa.id).all()
        usuarios = Usuario.query.filter_by(id_empresa=empresa.id).all()

        usuarios_competencias_str = ', '.join([f'{usuario.nome} ({usuario.cargo}, id: {usuario.id})' for usuario in usuarios])
        macro_acoes_str = ', '.join([acao.texto for acao in macro_acoes])
        okrs_str = ', '.join([okr.objetivo for okr in okrs])
        krs_str = ', '.join([kr.texto for kr in krs])
        sprints_str = ', '.join([
            f'Sprint {sprint.id}: Tarefa - {sprint.tarefa}, Responsável - {sprint.usuario.nome}, Status - {sprint.dado_1_sprint.get("status", "N/A")}, Observação - {sprint.dado_1_sprint.get("observacoes", "N/A")}'
            for sprint in sprints])
        usuarios_str = ', '.join([f'{usuario.nome} ({usuario.cargo})' for usuario in usuarios])

        pergunta = f"""Olá GPT,

                        Para planejar nosso próximo sprint de uma semana, preciso que você leve em conta os OKRs da empresa {okrs_str} para os próximos 90 dias, os KR's ligados a cada objetivo {krs_str}, o sprint atual {sprints_str}, o estado atual das tarefas e os perfis de competências dos colaboradores da equipe {usuarios_competencias_str}.
                        
                        Ao criar este plano, por favor, considere as seguintes informações:
                        
                        Os OKRs da empresa para os próximos 90 dias: {okrs_str}
                        Os KR's ligados a cada objetivo: {krs_str}
                        A lista de macro ações estratégicas geradas a partir dos OKRs e KR's: {macro_acoes_str}
                        As habilidades e competências específicas dos colaboradores da equipe: {usuarios_competencias_str}
                        A descrição da empresa: {empresa.descricao_empresa}
                        O sprint atual da equipe e o estado atual das tarefas: {sprints_str}
                        Com essas informações em mente, por favor, desenvolva um plano de sprint para a próxima semana. Este plano deve definir tarefas específicas que resultem em entregas concretas, como relatórios ou apresentações, e não apenas atividades como "pensar" ou "analisar". Cada tarefa deve ser priorizada com base em sua importância para alcançar nossos OKRs e KR's.
                        
                        Além disso, identifique o responsável por cada tarefa de acordo com as habilidades e competências dos membros da equipe.
                        
                        Responda em formato JSON, usando as seguintes chaves: prioridade (como um número, onde 1 é a maior prioridade e os números aumentam conforme a prioridade diminui), tarefa, responsável (utilize o ID do usuário e seja sempre um int), status (em progresso, pendente, concluída).
                        
                        Lembre-se de que este plano é estratégico: não precisa fazer nenhum tipo de comentário, apenas responda com o JSON necessário.

                        Aguardo seu plano de sprint.
                        """
        print(pergunta)
        messages = [{"role": "system", "content": "You are a helpful assistant."}]
        resposta, messages = perguntar_gpt(pergunta, empresa_id, messages)

        print("Resposta do GPT-4:")
        print(resposta)

        inicio_json = resposta.find('[')
        final_json = resposta.rfind(']')

        if inicio_json == -1 or final_json == -1:
            print(f"Erro ao decodificar JSON: não foi possível encontrar um objeto JSON na resposta")
            print(f"Resposta: {resposta}")
            return redirect(url_for('montagem_sprint_semana'))

        json_str = resposta[inicio_json:final_json + 1]

        try:
            sprints = json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f"Erro ao decodificar JSON: {str(e)}")
            print(f"Resposta:{resposta}")
            return redirect(url_for('montagem_sprint_semana'))

        SprintPendente.query.filter_by(empresa_id=empresa.id).delete()

        for sprint in sprints:
            print(f"Processing sprint: {sprint}")

            if 'tarefa' not in sprint or 'responsavel' not in sprint:
                print(f"Erro: o sprint não contém as chaves 'tarefa' ou 'responsavel'. Sprint: {sprint}")
                continue

            responsavel_id = sprint.get('responsavel')
            if not responsavel_id:
                print(f"Responsável ID não especificado ou inválido para o sprint {sprint['tarefa']}.")
                continue

            # Busque o usuário pelo ID no banco de dados.
            usuario = Usuario.query.get(responsavel_id)

            if usuario is None or usuario.id_empresa != empresa.id:
                print(
                    f"Usuário com ID {responsavel_id} não encontrado na base de dados para a empresa {empresa.nome_contato}. Sprint: {sprint}")
                continue

            novo_sprint = SprintPendente(
                empresa_id=empresa.id,
                nome_empresa=empresa.nome_contato,
                prioridade=sprint['prioridade'],
                tarefa=sprint['tarefa'],
                usuario_id=usuario.id,
                usuario=usuario,  # Adicione esta linha
                dado_1_sprint={"status": "pendente", "data_conclusao": None, "observacoes": ""}
            )
            db.session.add(novo_sprint)

        db.session.commit()

        return redirect(url_for('montagem_sprint_semana'))
@app.route('/listar_sprint_aguardando_aprovacao', methods=['GET'])
@login_required
def listar_sprint_aguardando_aprovacao():
    if current_user.is_admin:
        sprints = SprintPendente.query.all()
    else:
        sprints = SprintPendente.query.filter_by(usuario_id=current_user.id).all()
    return render_template('listar_sprint_aguardando_aprovacao.html', sprints=sprints)



@app.route('/aceitar_sprint_sugerido/<int:sprint_id>', methods=['POST'])
@login_required
def aceitar_sprint_sugerido(sprint_id):
    sprint_pendente = SprintPendente.query.get(sprint_id)
    if sprint_pendente is None:
        flash('Sprint não encontrado.', 'error')
        return redirect(url_for('listar_sprint_aguardando_aprovacao'))

    novo_sprint = Sprint(
        empresa_id=sprint_pendente.empresa_id,
        nome_empresa=sprint_pendente.nome_empresa,
        prioridade=sprint_pendente.prioridade,
        tarefa=sprint_pendente.tarefa,
        usuario_id=sprint_pendente.usuario_id,
        usuario_grupo=sprint_pendente.usuario_grupo,
        dado_1_sprint=sprint_pendente.dado_1_sprint
    )
    db.session.add(novo_sprint)
    db.session.delete(sprint_pendente)
    db.session.commit()

    flash('Sprint aceito com sucesso.', 'success')
    return redirect(url_for('listar_sprint_aguardando_aprovacao'))


@app.route('/recusar_sprint_sugerido/<int:sprint_id>', methods=['POST'])
@login_required
def recusar_sprint_sugerido(sprint_id):
    sprint_pendente = SprintPendente.query.get(sprint_id)
    if sprint_pendente is None:
        flash('Sprint não encontrado.', 'error')
        return redirect(url_for('listar_sprint_aguardando_aprovacao'))

    db.session.delete(sprint_pendente)
    db.session.commit()

    flash('Sprint recusado com sucesso.', 'success')
    return redirect(url_for('listar_sprint_aguardando_aprovacao'))

@app.route('/revisar_sprint', methods=['GET', 'POST'])
@login_required
def revisar_sprint():
    if request.method == 'POST':
        # Aqui, vamos adicionar os sprints ao banco de dados
        sprints = session.get('sprints', [])
        empresa_id = session.get('empresa_id')
        empresa = db.session.get(Empresa, empresa_id)
        for sprint in sprints:
            if isinstance(sprint, dict):
                nome_usuario_responsavel = sprint.get('responsável', '')
                usuario_responsavel = Usuario.query.filter_by(nome=nome_usuario_responsavel).first()
                sprint_db = Sprint(
                    empresa_id=empresa_id,
                    nome_empresa=empresa.nome_contato,
                    prioridade=sprint.get('prioridade', ''),
                    tarefa=sprint.get('tarefa', ''),
                    usuario=usuario_responsavel
                )
                db.session.add(sprint_db)
        db.session.commit()

        # Limpa os dados da sessão
        session.pop('resposta', None)
        session.pop('sprints', None)
        session.pop('empresa_id', None)

        # Redireciona para a página de resultados
        return redirect(url_for('resultado_sprint'))

    # Renderiza o template de revisão de sprint
    return render_template('revisar_sprint.html')


@app.route('/aprovar_sprints', methods=['POST'])
@login_required
def aprovar_sprints():
    # Aqui, você pode adicionar o código para aprovar os sprints
    # Por exemplo, você pode adicionar os sprints ao banco de dados
    sprints = session.get('sprints', [])
    empresa_id = session.get('empresa_id')
    empresa = db.session.get(Empresa, empresa_id)
    for sprint in sprints:
        if isinstance(sprint, dict):
            nome_usuario_responsavel = sprint.get('responsável', '')
            usuario_responsavel = Usuario.query.filter_by(nome=nome_usuario_responsavel).first()
            sprint_db = Sprint(
                empresa_id=empresa_id,
                nome_empresa=empresa.nome_contato,
                prioridade=sprint.get('prioridade', ''),
                tarefa=sprint.get('tarefa', ''),
                usuario=usuario_responsavel
            )
            db.session.add(sprint_db)
    db.session.commit()

    # Limpa os dados da sessão
    session.pop('resposta', None)
    session.pop('sprints', None)
    session.pop('empresa_id', None)

    # Redireciona para a página de resultados
    return redirect(url_for('resultado_sprint'))



@app.route('/refazer_sprint', methods=['POST'])
@login_required
def refazer_sprint():
    # Obter o feedback do usuário
    feedback = request.form.get('feedback')

    # Obter as informações da empresa
    empresa_id = session.get('empresa_id')
    empresa = db.session.get(Empresa, empresa_id)  # Obter a empresa pelo ID
    if empresa is None:
        return redirect(url_for('montagem_sprint_semana'))  # Se a empresa não existir, redirecionar

    # Obter as macro ações associadas à empresa
    macro_acoes = MacroAcao.query.filter_by(empresa_id=empresa.id).all()

    # Obter os OKRs e usuários associados à empresa
    okrs = OKR.query.filter_by(id_empresa=empresa.id).all()
    usuarios = Usuario.query.filter_by(id_empresa=empresa.id).all()

    # Formatar as listas como strings
    macro_acoes_str = ', '.join([acao.texto for acao in macro_acoes])
    okrs_str = ', '.join([okr.objetivo for okr in okrs])
    usuarios_str = ', '.join([f'{usuario.nome} ({usuario.cargo})' for usuario in usuarios])

    # Obter a resposta anterior
    resposta_anterior = session.get('resposta')

    # Construir a pergunta para o GPT-3
    pergunta = f"Considerando essa resposta {resposta_anterior}, e esse feedback {feedback}, considerando a lista de macro ações estratégicas geradas a partir dos OKRs {okrs_str} da empresa para os próximos 90 dias, as habilidades específicas dos colaboradores da equipe {usuarios_str}, peço que você desenvolva um plano de sprint para a próxima semana. Para ajudar a moldar esse plano, aqui estão as informações que você precisa considerar: Lista de macro ações: {macro_acoes_str}, Habilidades dos colaboradores: {usuarios_str}, Resumo sobre a empresa: {empresa.descricao_empresa}. Com base nessas informações, por favor, crie um plano de sprint que defina as tareas específicas a serem realizadas na próxima semana, priorizando as ações mais críticas e detalhando como essas tarefas suportam os OKRs definidos. Além disso, coloque o responsável por cada tarefa específica de acordo com a tarefa e o cargo dos colaboradores. Provide them in JSON format with the following keys: prioridade, tarefa, responsável."
    print(pergunta)
    messages = [{"role": "system", "content": "You are a helpful assistant."}]
    resposta, messages = perguntar_gpt(pergunta, empresa_id, messages)

    # Encontra o início e o final do objeto JSON na resposta
    inicio_json = resposta.find('[')
    final_json = resposta.rfind(']')

    # Se não encontramos um objeto JSON, lançamos um erro
    if inicio_json == -1 or final_json == -1:
        print(f"Erro ao decodificar JSON: não foi possível encontrar")
        return redirect(url_for('montagem_sprint_semana'))

    # Extrair o objeto JSON da resposta
    json_str = resposta[inicio_json:final_json+1]

    # Decodificar o objeto JSON
    sprints = json.loads(json_str)

    # Salvar os sprints na sessão
    session['sprints'] = sprints

    # Redirecionar para a página de revisão de sprints
    return redirect(url_for('revisar_sprint'))






@app.route('/resultado_sprint')
@login_required
def resultado_sprint():
    if 'empresa_id' not in session:
        return redirect(url_for('montagem_sprint_semana'))  # Se não há empresa, redirecionar

    # Pegar o id da empresa da sessão
    empresa_id = session['empresa_id']

    # Remover o id da empresa da sessão
    session.pop('empresa_id', None)

    # Buscar os sprints do banco de dados
    sprints = Sprint.query.filter_by(empresa_id=empresa_id).all()

    return render_template('resultado_sprint.html', sprints=sprints, empresa_id=empresa_id)



@app.route('/listar_sprints_semana', methods=['GET'])
@login_required
def listar_sprints_semana():
    if current_user.is_admin:
        sprints = Sprint.query.all()  # Busca todos os sprints se for admin
    else:
        sprints = Sprint.query.filter_by(empresa_id=current_user.id_empresa).all()  # Busca apenas os sprints da empresa do usuário
    return render_template('listar_sprints_semana.html', sprints=sprints)



@app.route('/atualizar_sprint/<int:id>', methods=['GET', 'POST'])
@login_required
def atualizar_sprint(id):
    sprint = Sprint.query.get(id)
    if request.method == 'POST':
        tarefa = request.form.get('tarefa')
        sprint.tarefa = tarefa
        db.session.commit()
        return redirect(url_for('listar_sprints_semana'))
    return render_template('atualizar_sprint.html', sprint=sprint)

@app.route('/deletar_sprint/<int:id>', methods=['GET', 'POST'])
@app.route('/deletar_sprint/<int:id>/<string:redirect_page>', methods=['GET', 'POST'])
@login_required
def deletar_sprint(id, redirect_page=None):
    sprint = Sprint.query.get(id)
    empresa_id = sprint.empresa_id  # Armazena o empresa_id antes de excluir o sprint
    db.session.delete(sprint)
    db.session.commit()

    if redirect_page == 'revisao':
        return redirect(url_for('listar_revisao_sprint_semana', empresa_id=empresa_id))
    else:
        return redirect(url_for('listar_sprints_semana'))

@app.route('/montagem_lista_usuario_sprint', methods=['GET', 'POST'])
@login_required
def montagem_lista_usuario_sprint():
    if request.method == 'POST':
        empresa_id = request.form.get('empresa')
        usuarios = Usuario.query.filter_by(id_empresa=empresa_id).all()
        return render_template('lista_usuario_sprint.html', usuarios=usuarios)
    empresas = Empresa.query.all()
    return render_template('montagem_lista_usuario_sprint.html', empresas=empresas)

@app.route('/lista_usuario_sprint', methods=['GET', 'POST'])
@login_required
def lista_usuario_sprint():
    if request.method == 'POST':
        empresa_id = request.form.get('empresa')
        usuarios = Usuario.query.filter_by(empresa_id=empresa_id).all()
        return render_template('lista_usuario_sprint.html', usuarios=usuarios)
    empresas = Empresa.query.all()
    return render_template('selecionar_empresa.html', empresas=empresas)

@app.route('/montar_tarefas_semana/<int:usuario_id>', methods=['GET', 'POST'])
@login_required
def montar_tarefas_semana(usuario_id):
    usuario = Usuario.query.get(usuario_id)
    empresa = Empresa.query.get(usuario.id_empresa)
    okrs = OKR.query.filter_by(id_empresa=usuario.id_empresa).all()
    krs = KR.query.filter_by(id_empresa=usuario.id_empresa).all()  # Adicionado aqui
    macro_acoes = MacroAcao.query.filter_by(empresa_id=usuario.id_empresa).all()
    sprints = Sprint.query.filter_by(usuario_id=usuario.id).all()

    # Adicionado código de depuração
    print(f"Usuario: {usuario.nome}")
    print(f"Empresa: {empresa.nome_contato}")
    print(f"OKRs: {[okr.objetivo for okr in okrs]}")
    print(f"KRs: {[kr.texto for kr in krs]}")
    print(f"Macro Ações: {[acao.texto for acao in macro_acoes]}")
    print(f"Sprints: {[sprint.tarefa for sprint in sprints]}")

    if request.method == 'POST':
        # Aqui você pode iniciar o processo que mencionou
        pass

    return render_template('montar_tarefas_semana.html', empresa=empresa, usuario=usuario, okrs=okrs, krs=krs, macro_acoes=macro_acoes, sprints=sprints)


@app.route('/iniciar_processo/<int:usuario_id>', methods=['POST'])
@login_required
def iniciar_processo(usuario_id):
    print(f"Usuario ID: {usuario_id}")  # Adicione esta linha
    # Obter o usuário pelo ID
    usuario = db.session.get(Usuario, usuario_id)
    if usuario is None:
        return redirect(url_for('montar_tarefas_semana', usuario_id=usuario_id))  # Se o usuário não existir, redirecionar

    # Obter a empresa associada ao usuário
    empresa = db.session.get(Empresa, usuario.id_empresa)

    # Obter as macro ações associadas à empresa
    macro_acoes = MacroAcao.query.filter_by(empresa_id=empresa.id).all()

    # Obter os OKRs associados à empresa
    okrs = OKR.query.filter_by(id_empresa=empresa.id).all()

    # Obter os KRs associados à empresa
    krs = KR.query.filter_by(id_empresa=empresa.id).all()

    # Obter os sprints associados ao usuário
    sprints = Sprint.query.filter_by(usuario_id=usuario.id).all()

    # Formatar as listas como strings
    macro_acoes_str = ', '.join([acao.texto for acao in macro_acoes])
    okrs_str = ', '.join([okr.objetivo for okr in okrs])
    krs_str = ', '.join([kr.texto for kr in krs])
    sprints_str = ', '.join([f'{sprint.tarefa} ({sprint.data_criacao})' for sprint in sprints])

    # Construir a pergunta para o GPT-4
    pergunta = f"Inteligência Artificial GPT, considerando a lista de macro ações estratégicas geradas a partir dos OKRs {okrs_str} e dos KRs {krs_str}, Resumo sobre a empresa: {empresa.descricao_empresa} e a Lista de macro ações: {macro_acoes_str}, as tarefas da semana {sprints_str} para o colaborador {usuario.nome} {usuario.cargo}  crie to-do para cada tarefa. Provide them in JSON format with the following keys: tarefa, usuario, data_para_conclusão, passo1, data1, passo2, data2, passo3, data3, passo4, data4, passo5, data5, passo6, data6."
    print(pergunta)
    messages = [{"role": "system", "content": "You are a helpful assistant."}]
    resposta, messages = perguntar_gpt(pergunta, empresa.id, messages)
    # Imprimir a resposta do GPT
    print(f"Resposta do GPT: {resposta}")
    # Encontra o início e o final do objeto JSON na resposta
    inicio_json = resposta.find('[')
    final_json = resposta.rfind(']')

    # Se não encontramos um objeto JSON, lançamos um erro
    if inicio_json == -1 or final_json == -1:
        print(f"Erro ao decodificar JSON: não foi possível encontrar um objeto JSON na resposta")
        print(f"Resposta: {resposta}")
        return redirect(url_for('montar_tarefas_semana', usuario_id=usuario_id))


    json_str = resposta[inicio_json:final_json+1]

    # Carrega a resposta JSON
    try:
        tarefas_semana = json.loads(json_str)

    except json.JSONDecodeError as e:
        print(f"Erro ao decodificar JSON: {str(e)}")
        print(f"Resposta:{resposta}")

        return redirect(url_for('montar_tarefas_semana', usuario_id=usuario_id))  # Se a decodificação falhar, redirecionar

    # Armazena a resposta, as tarefas da semana e o id do usuário na sessão
    session['resposta'] = resposta
    session['tarefas_semana'] = tarefas_semana
    session['usuario_id'] = usuario_id

    # Redireciona para a página de revisão
    return redirect(url_for('revisar_tarefas'))


@app.route('/refazer_tarefa/<int:usuario_id>', methods=['POST'])
@login_required
def refazer_tarefa(usuario_id):
    # Obter o feedback do usuário
    feedback = request.form.get('feedback')

    # Obter a resposta anterior do GPT
    resposta_anterior = session.get('resposta')

    # Obter o usuário pelo ID
    usuario = db.session.get(Usuario, usuario_id)
    if usuario is None:
        return redirect(url_for('montar_tarefa_semana'))  # Se o usuário não existir, redirecionar

    # Obter a empresa associada ao usuário
    empresa = db.session.get(Empresa, usuario.id_empresa)

    # Obter as macro ações associadas à empresa
    macro_acoes = MacroAcao.query.filter_by(empresa_id=empresa.id).all()

    # Obter os OKRs associados à empresa
    okrs = OKR.query.filter_by(id_empresa=empresa.id).all()

    # Obter os KRs associados à empresa
    krs = KR.query.filter_by(id_empresa=empresa.id).all()

    # Obter os sprints associados ao usuário
    sprints = Sprint.query.filter_by(usuario_id=usuario.id).all()

    # Formatar as listas como strings
    macro_acoes_str = ', '.join([acao.texto for acao in macro_acoes])
    okrs_str = ', '.join([okr.objetivo for okr in okrs])
    krs_str = ', '.join([kr.texto for kr in krs])
    sprints_str = ', '.join([f'{sprint.tarefa} ({sprint.data_criacao})' for sprint in sprints])

    # Construir a pergunta para o GPT-4
    pergunta = f"Inteligência Artificial GPT, considerando esse feedback {feedback} pra essa resposta {resposta_anterior}, considerando a lista de macro ações estratégicas geradas a partir dos OKRs {okrs_str} e dos KRs {krs_str}, Resumo sobre a empresa: {empresa.descricao_empresa} e a Lista de macro ações: {macro_acoes_str}, as tarefas da semana {sprints_str} para o colaborador {usuario.nome} {usuario.cargo}  crie to-do para cada tarefa. Provide them in JSON format with the following keys: tarefa, usuario, data_para_conclusão, passo1, data1, passo2, data2, passo3, data3, passo4, data4, passo5, data5, passo6, data6."
    print(pergunta)
    messages = [{"role": "system", "content": "You are a helpful assistant."}]
    resposta, messages = perguntar_gpt(pergunta, empresa.id, messages)
    # Imprimir a resposta do GPT
    print(f"Resposta do GPT: {resposta}")
    # Encontra o início e o final do objeto JSON na resposta
    inicio_json = resposta.find('[')
    final_json = resposta.rfind(']')

    # Se não encontramos um objeto JSON, lançamos um erro
    if inicio_json == -1 or final_json == -1:
        print(f"Erro ao decodificar JSON: não foi possível encontrar um objeto JSON na resposta")
        print(f"Resposta: {resposta}")
        return redirect(url_for('montar_tarefa_semana'))

    json_str = resposta[inicio_json:final_json+1]

    # Carrega a resposta JSON
    try:
        tarefas_semana = json.loads(json_str)

    except json.JSONDecodeError as e:
        print(f"Erro ao decodificar JSON: {str(e)}")
        print(f"Resposta:{resposta}")

        return redirect(url_for('montar_tarefa_semana'))  # Se a decodificação falhar, redirecionar

    # Armazena a resposta, as tarefas da semana e o id do usuário na sessão
    session['resposta'] = resposta
    session['tarefas_semana'] = tarefas_semana
    session['usuario_id'] = usuario_id

    # Redireciona para a página de revisão
    return redirect(url_for('revisar_tarefas'))




@app.route('/revisar_tarefas', methods=['GET'])
@login_required
def revisar_tarefas():
    # Obter o ID do usuário da sessão
    usuario_id = session.get('usuario_id')
    if usuario_id is None:
        print("Erro: usuario_id não encontrado na sessão")
        return redirect(url_for('montar_tarefa_semana'))

    # Obter o usuário pelo ID
    usuario = db.session.get(Usuario, usuario_id)
    if usuario is None:
        print(f"Erro: Não foi possível encontrar o usuário com o ID {usuario_id}")
        return redirect(url_for('montar_tarefa_semana'))  # Se o usuário não existir, redirecionar

    # Obter as tarefas da semana da sessão
    tarefas_semana = session.get('tarefas_semana', [])
    if not tarefas_semana:
        print("Erro: tarefas_semana não encontradas na sessão")

    # Renderizar o template 'revisar_tarefas.html'
    return render_template('revisar_tarefas.html', usuario=usuario, tarefas_semana=tarefas_semana)




@app.route('/aprovar_tarefas', methods=['POST'])
@login_required
def aprovar_tarefas():
    usuario_id = session.get('usuario_id')
    tarefas_semana = session.get('tarefas_semana', [])

    usuario = db.session.get(Usuario, usuario_id)
    if usuario is None:
        return redirect(url_for('montar_tarefa_semana'))

    for tarefa in tarefas_semana:
        passos = []
        datas = []
        for i in range(1, 7):
            passo_key = 'passo' + str(i)
            data_key = 'data' + str(i)
            passo = tarefa.get(passo_key, '')
            data_str = tarefa.get(data_key, '')

            if data_str:
                data = datetime.strptime(data_str, '%Y-%m-%d')
            else:
                data = None

            passos.append(passo)
            if data:
                datas.append(data.strftime('%Y-%m-%d'))
            else:
                datas.append(None)

        to_do = json.dumps({"passos": passos, "datas": datas})

        data_para_conclusao_str = tarefa.get('data_para_conclusão')
        data_para_conclusao = None

        # Tenta vários formatos de data
        for fmt in ('%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f'):
            try:
                data_para_conclusao = datetime.strptime(data_para_conclusao_str, fmt)
                break  # Se a conversão for bem sucedida, saia do loop
            except ValueError:
                pass  # Se a conversão falhar, continue para o próximo formato

        tarefa_semanal = TarefaSemanal(
            empresa_id=usuario.id_empresa,
            usuario_id=usuario_id,
            tarefa_semana=tarefa.get('tarefa', ''),
            to_do=to_do,
            data_para_conclusao=data_para_conclusao,
        )
        db.session.add(tarefa_semanal)
    db.session.commit()

    session.pop('usuario_id', None)
    session.pop('tarefas_semana', None)

    return redirect(url_for('listar_tarefas_semanais_usuario'))





@app.route('/listar_tarefas_semanais_usuario', methods=['GET'])
@login_required
def listar_tarefas_semanais_usuario():
    if current_user.is_admin:
        tarefas_semanais = TarefaSemanal.query.all()  # Busca todas as tarefas se for admin
    else:
        tarefas_semanais = TarefaSemanal.query.filter_by(empresa_id=current_user.id_empresa, usuario_id=current_user.id).all()  # Busca apenas as tarefas da empresa do usuário e atribuídas a ele
    tarefas_decodificadas = []
    for tarefa in tarefas_semanais:
        tarefa_dict = tarefa.__dict__
        tarefa_dict['to_do_decoded'] = tarefa.to_do_decoded
        if tarefa.observacoes is not None:
            tarefa_dict['observacoes_decoded'] = json.loads(tarefa.observacoes)  # Adicionado aqui
        else:
            tarefa_dict['observacoes_decoded'] = None  # ou algum valor padrão
        tarefa_dict['usuario'] = tarefa.usuario.nome
        tarefas_decodificadas.append(tarefa_dict)
    return render_template('listar_tarefas_semanais_usuario.html', tarefas_semanais=tarefas_decodificadas)


@app.route('/atualizar_tarefa_semanal/<int:id>', methods=['GET', 'POST'])
@login_required
def atualizar_tarefa_semanal(id):
    tarefa = TarefaSemanal.query.get_or_404(id)

    # Verifique se o usuário tem permissão para atualizar esta tarefa
    if not current_user.is_admin and (tarefa.empresa_id != current_user.id_empresa or tarefa.usuario_id != current_user.id):
        abort(403)  # Forbidden

    db.session.refresh(tarefa)

    if request.method == 'POST':
        tarefa.tarefa_semana = request.form['tarefa_semana']
        tarefa.data_para_conclusao = datetime.strptime(request.form['data_para_conclusao'], '%Y-%m-%d')

        to_do = {
            'passos': [],
            'datas': [],
            'status': []
        }

        for key in request.form.keys():
            if key.startswith('passo'):
                to_do['passos'].append(request.form[key])
            elif key.startswith('data'):
                to_do['datas'].append(request.form[key])
            elif key.startswith('status') and not key == 'status_tarefa':
                to_do['status'].append(request.form[key])

        tarefa.to_do = json.dumps(to_do)
        tarefa.data_atualizacao = datetime.utcnow()

        observacoes = tarefa.observacoes_decoded() if tarefa.observacoes else {}

        observacoes['status_tarefa'] = request.form['status_tarefa']
        if 'observacao_tarefa' in request.form:
            observacoes['observacao_tarefa'] = request.form['observacao_tarefa']

        tarefa.observacoes = json.dumps(observacoes)

        db.session.commit()

        return redirect(url_for('listar_tarefas_semanais_usuario'))

    tarefa_dict = tarefa.__dict__.copy()
    tarefa_dict['to_do_decoded'] = tarefa.to_do_decoded
    tarefa_dict['observacoes_decoded'] = tarefa.observacoes_decoded()

    if 'status' not in tarefa_dict['to_do_decoded']:
        new_to_do = tarefa_dict['to_do_decoded'].copy()
        new_to_do['status'] = ['criado' for _ in range(len(tarefa_dict['to_do_decoded']['passos']))]
        tarefa.to_do = json.dumps(new_to_do)
        db.session.commit()

    observacoes = tarefa_dict['observacoes_decoded'] if tarefa.observacoes else {}

    if not ('status_tarefa' in observacoes and 'observacao_tarefa' in observacoes):
        observacoes['status_tarefa'] = 'pendente'
        observacoes['observacao_tarefa'] = ''
        tarefa.observacoes = json.dumps(observacoes)
        db.session.commit()

    return render_template('atualizar_tarefa_semanal.html', tarefa=tarefa_dict, observacoes=observacoes)






@app.route('/deletar_todo/<int:id>/<int:todo_index>', methods=['POST'])
@login_required
def deletar_todo(id, todo_index):
    tarefa = TarefaSemanal.query.get_or_404(id)
    to_do_decoded = tarefa.to_do_decoded

    # Check if the todo_index is valid
    if todo_index < 0 or todo_index >= len(to_do_decoded['passos']):
        return "Invalid todo index", 400

    # Remove the corresponding step, date and status
    del to_do_decoded['passos'][todo_index]
    del to_do_decoded['datas'][todo_index]
    del to_do_decoded['status'][todo_index]


    # Save the updated to_do to the task
    tarefa.to_do = json.dumps(to_do_decoded)

    db.session.commit()

    return redirect(url_for('atualizar_tarefa_semanal', id=id))




@app.route('/deletar_tarefa_semanal/<int:id>', methods=['POST'])
@login_required
def deletar_tarefa_semanal(id):
    tarefa = TarefaSemanal.query.get_or_404(id)
    db.session.delete(tarefa)
    db.session.commit()
    return redirect(url_for('listar_tarefas_semanais_usuario'))

@app.route('/cadastrar/macro_acao', methods=['GET', 'POST'])
@login_required
def cadastrar_macro_acao():
    if request.method == 'POST':
        id_empresa = int(request.form.get('empresa', '0'))
        id_squad = int(request.form.get('squad', '0'))
        id_objetivo = int(request.form.get('objetivo', '0'))
        id_kr = int(request.form.get('kr', '0'))
        texto = request.form['texto']

        empresa = Empresa.query.get(id_empresa)
        squad = Squad.query.get(id_squad)
        objetivo = OKR.query.get(id_objetivo)
        kr = KR.query.get(id_kr)

        if not all([empresa, squad, objetivo, kr]):
            return "Empresa, Squad, Objetivo ou KR não encontrado", 404

        macro_acao = MacroAcao(
            texto=texto,
            kr_id=kr.id,
            objetivo=objetivo.objetivo,
            objetivo_id=objetivo.id,
            empresa=empresa.nome_contato,
            empresa_id=empresa.id,
            squad_id=squad.id
        )

        db.session.add(macro_acao)
        db.session.commit()
        return redirect(url_for('listar_macro_acoes_aprovadas'))

    if current_user.is_admin:
        empresas = Empresa.query.all()
        squads = Squad.query.all()
        objetivos = OKR.query.all()
        krs = KR.query.all()
    else:
        empresas = Empresa.query.filter_by(id=current_user.id_empresa).all()
        squads = Squad.query.filter_by(empresa_id=current_user.id_empresa).all()
        objetivos = OKR.query.filter_by(id_empresa=current_user.id_empresa).all()
        krs = KR.query.filter_by(id_empresa=current_user.id_empresa).all()

    return render_template('cadastrar_macro_acao.html', empresas=empresas, squads=squads, objetivos=objetivos, krs=krs)



@app.route('/cadastrar/sprint', methods=['GET', 'POST'])
@app.route('/cadastrar/sprint/<string:redirect_page>', methods=['GET', 'POST'])
@login_required
def cadastrar_sprint(redirect_page=None):
    if request.method == 'POST':
        id_empresa = int(request.form.get('empresa', '0'))
        id_usuario = int(request.form.get('usuario', '0'))
        tarefa = request.form['tarefa']
        prioridade = int(request.form.get('prioridade', '0'))

        empresa = Empresa.query.get(id_empresa)
        usuario = Usuario.query.get(id_usuario)

        if empresa is None or usuario is None:
            return "Empresa ou Usuário não encontrado", 404

        sprint = Sprint(
            nome_empresa=empresa.nome_contato,
            empresa_id=empresa.id,
            prioridade=prioridade,
            tarefa=tarefa,
            usuario_id=usuario.id,
            usuario_grupo='',  # Definido como string vazia
            data_criacao=datetime.utcnow()
        )
        db.session.add(sprint)
        db.session.commit()

        if redirect_page == 'revisao':
            return redirect(url_for('listar_revisao_sprint_semana', empresa_id=id_empresa))
        else:
            return redirect(url_for('listar_sprints_semana'))

    if current_user.is_admin:
        empresas = Empresa.query.all()
        usuarios = Usuario.query.all()
    else:
        empresas = Empresa.query.filter_by(id=current_user.id_empresa).all()
        usuarios = Usuario.query.filter_by(id_empresa=current_user.id_empresa).all()

    return render_template('cadastrar_sprint.html', empresas=empresas, usuarios=usuarios, redirect_page=redirect_page)




@app.route('/get_usuarios/<int:empresa_id>')
@login_required
def get_usuarios(empresa_id):
    if current_user.is_admin or empresa_id == current_user.id_empresa:
        usuarios = Usuario.query.filter_by(id_empresa=empresa_id).all()
        return jsonify([{'id': usuario.id, 'nome': usuario.nome} for usuario in usuarios])
    else:
        abort(403)  # Forbidden


@app.route('/cadastrar/tarefa_semanal', methods=['GET', 'POST'])
@login_required
def cadastrar_tarefa_semanal():
    usuario = Usuario.query.get(current_user.id)  # Obtenha o usuário atualmente logado
    empresa = Empresa.query.get(usuario.id_empresa)  # Obtenha a empresa associada ao usuário

    if usuario.is_admin:
        empresas = Empresa.query.all()  # Obtenha todas as empresas para um administrador
        usuarios = Usuario.query.all()  # Obtenha todos os usuários para um administrador
    else:
        empresas = [empresa]  # Apenas a empresa do usuário para um usuário final
        usuarios = [usuario]  # Apenas o usuário logado para um usuário final

    if request.method == 'POST':
        empresa_id = request.form['empresa']
        usuario_id = request.form['usuario']
        tarefa_semana = request.form['tarefa_semana']
        data_para_conclusao_str = request.form['data_para_conclusao']

        # Converta a string da data para um objeto datetime
        data_para_conclusao = datetime.strptime(data_para_conclusao_str, '%Y-%m-%d')

        passos = []
        datas = []
        i = 0
        while True:
            passo_key = 'passo_' + str(i)
            data_key = 'data_' + str(i)
            if passo_key in request.form:
                passo = request.form[passo_key]
                data_str = request.form[data_key]

                # Converta a string da data para um objeto datetime
                if data_str:  # Verifique se data_str não é uma string vazia
                    data = datetime.strptime(data_str, '%Y-%m-%d')
                else:
                    data = None  # Ou algum valor padrão

                passos.append(passo)
                if data:  # Verifique se data não é None antes de chamar strftime
                    datas.append(data.strftime('%Y-%m-%d'))  # Converta o objeto datetime para uma string
                else:
                    datas.append(None)  # Ou algum valor padrão
                i += 1
            else:
                break

        to_do = json.dumps({"passos": passos, "datas": datas})

        tarefa_semanal = TarefaSemanal(
            empresa_id=empresa_id,
            usuario_id=usuario_id,
            tarefa_semana=tarefa_semana,
            to_do=to_do,
            data_para_conclusao=data_para_conclusao,
        )
        db.session.add(tarefa_semanal)
        db.session.commit()
        return redirect(url_for('listar_tarefas_semanais_usuario'))

    return render_template('cadastrar_tarefas_semanais_usuario.html', empresas=empresas, usuarios=usuarios)





@app.route('/selecionar_empresa_mural', methods=['GET', 'POST'])
@login_required
def selecionar_empresa_mural():
    empresas = Empresa.query.all()
    if request.method == 'POST':
        empresa_id = request.form.get('empresa')
        return redirect(url_for('mural', empresa_id=empresa_id))
    return render_template('selecionar_empresa_mural.html', empresas=empresas)





@app.route('/mural/<int:empresa_id>', methods=['GET', 'POST'])
@login_required
def mural(empresa_id):
    empresa = Empresa.query.get(empresa_id)
    if not empresa:
        flash('Empresa não encontrada.', 'error')
        return redirect(url_for('index'))

    # Buscar todos os OKRs para a empresa
    objetivos = OKR.query.filter_by(id_empresa=empresa_id).all()

    # Para cada OKR, buscar os KRs e MacroAções relacionados
    for objetivo in objetivos:
        objetivo.krs = KR.query.filter_by(id_okr=objetivo.id).all()
        for kr in objetivo.krs:
            kr.macro_acoes = MacroAcao.query.filter_by(kr_id=kr.id).all()

    tarefas = TarefaSemanal.query.filter_by(empresa_id=empresa_id).all()

    # Organiza as tarefas por usuário
    tarefas_por_usuario = defaultdict(list)
    for tarefa in tarefas:
        tarefas_por_usuario[tarefa.usuario].append(tarefa)

    return render_template('mural.html', empresa=empresa, objetivos=objetivos, tarefas_por_usuario=tarefas_por_usuario)



@app.route('/revisao_sprint_semana', methods=['GET', 'POST'])
def revisao_sprint_semana():
    if request.method == 'POST':
        empresa_id = request.form.get('empresa_id')
        return redirect(url_for('listar_revisao_sprint_semana', empresa_id=empresa_id))
    empresas = Empresa.query.all()
    return render_template('revisao_sprint_semana.html', empresas=empresas)


@app.route('/listar_revisao_sprint_semana/<int:empresa_id>', methods=['GET'])
def listar_revisao_sprint_semana(empresa_id):
    if current_user.is_admin:
        sprints = Sprint.query.filter_by(empresa_id=empresa_id).all()
    else:
        sprints = Sprint.query.filter_by(empresa_id=empresa_id, usuario_id=current_user.id).all()
    return render_template('listar_revisao_sprint_semana.html', sprints=sprints)



@app.route('/montagem_email_tarefas', methods=['GET', 'POST'])
def montagem_email_tarefas():
    empresas = Empresa.query.all()
    return render_template('montagem_email_tarefas.html', empresas=empresas)

@app.route('/listar_email_tarefas', methods=['GET', 'POST'])
def listar_email_tarefas():
    empresa_id = request.form.get('empresa')
    tarefas = TarefaSemanal.query.filter_by(empresa_id=empresa_id).all()

    # Agrupar tarefas por usuário
    tarefas_por_usuario = {}
    for tarefa in tarefas:
        if tarefa.usuario_id not in tarefas_por_usuario:
            tarefas_por_usuario[tarefa.usuario_id] = []
        tarefas_por_usuario[tarefa.usuario_id].append(tarefa)

    return render_template('listar_email_tarefas.html', tarefas_por_usuario=tarefas_por_usuario)


@app.route('/atualizar_sprint_revisao/<int:sprint_id>', methods=['GET', 'POST'])
def atualizar_sprint_revisao(sprint_id):
    sprint = Sprint.query.get(sprint_id)
    if sprint is None or (not current_user.is_admin and sprint.usuario_id != current_user.id):
        abort(404)

    if request.method == 'POST':
        sprint.prioridade = request.form.get('prioridade')
        sprint.tarefa = request.form.get('tarefa')
        if sprint.dado_1_sprint is None:
            sprint.dado_1_sprint = {}
        # Cria uma nova cópia do dicionário
        novo_dado_1_sprint = sprint.dado_1_sprint.copy()
        novo_dado_1_sprint['status'] = request.form.get('status')
        novo_dado_1_sprint['observacoes'] = request.form.get('observacoes')
        novo_dado_1_sprint['data_conclusao'] = request.form.get('data_conclusao')
        # Atribui a nova cópia de volta ao campo JSON
        sprint.dado_1_sprint = novo_dado_1_sprint
        db.session.commit()
        return redirect(url_for('listar_revisao_sprint_semana', empresa_id=sprint.empresa_id))

    return render_template('atualizar_sprint_revisao.html', sprint=sprint)



@app.route('/montagem_sprint_semana_rotina', methods=['GET', 'POST'])
@login_required
def montagem_sprint_semana_rotina():
    # Buscar o sprint da semana anterior
    uma_semana_atras = datetime.now() - timedelta(weeks=1)
    sprint_anterior = Sprint.query.filter(Sprint.data_criacao >= uma_semana_atras).order_by(Sprint.data_criacao.desc()).first()

    # Buscar a empresa
    empresa = None
    if sprint_anterior:
        empresa = Empresa.query.get(sprint_anterior.empresa_id)


    if request.method == 'POST':
        # Coletar informações da empresa
        empresa_id = request.form.get('empresa')
        empresa = db.session.get(Empresa, empresa_id)  # Obter a empresa pelo ID
        if empresa is None:
            return redirect(url_for('montagem_sprint_semana_rotina'))  # Se a empresa não existir, redirecionar

        # Obter as macro ações associadas à empresa
        macro_acoes = MacroAcao.query.filter_by(empresa_id=empresa.id).all()

        # Obter os OKRs e usuários associados à empresa
        okrs = OKR.query.filter_by(id_empresa=empresa.id).all()
        usuarios = Usuario.query.filter_by(id_empresa=empresa.id).all()

        # Formatar as listas como strings
        macro_acoes_str = ', '.join([acao.texto for acao in macro_acoes])
        okrs_str = ', '.join([okr.objetivo for okr in okrs])
        usuarios_str = ', '.join([f'{usuario.nome} ({usuario.cargo})' for usuario in usuarios])

        # Informações sobre o sprint da semana anterior
        sprint_anterior_str = ''
        if sprint_anterior:
            sprint_anterior_str = f", Levando em consideração o sprint da semana anterior com status {sprint_anterior.dado_1_sprint['status']}, data de criação {sprint_anterior.data_criacao}, data de conclusão {sprint_anterior.dado_1_sprint['data_conclusao']}, observações {sprint_anterior.dado_1_sprint['observacoes']} e usuário {sprint_anterior.usuario.nome if sprint_anterior.usuario else 'N/A'}"

        # Construir a pergunta para o GPT-4
        pergunta = f"Inteligência Artificial GPT, considerando a lista de macro ações estratégicas geradas a partir dos OKRs {okrs_str} da empresa para os próximos 90 dias, e as habilidades específicas dos colaboradores da equipe {usuarios_str}, peço que você desenvolva um plano de sprint mensurável e orientado a resultados para a próxima semana.{sprint_anterior_str} Para moldar este plano, aqui estão as informações que você precisa considerar: Lista de macro ações: {macro_acoes_str}, Habilidades dos colaboradores: {usuarios_str}, Resumo sobre a empresa: {empresa.descricao_empresa}. Com base nessas informações, por favor, crie um plano de sprint para a semana atual. Defina as tareas específicas a serem realizadas na próxima semana, priorizando as ações mais críticas. As tarefas devem ser descritas usando verbos orientados a ação e resultados, como 'aprovar', 'entregar', 'fechar' ou 'alcançar X'. Detalhe como essas tarefas suportam os OKRs definidos e designe o responsável por cada tarefa, de acordo com a tarefa e o cargo dos colaboradores. No final do plano, inclua uma pergunta reflexiva para cada membro da equipe que os estimule a pensar sobre como eles podem melhorar seus resultados de maneira inovadora. Provide them in JSON format with the following keys: prioridade, tarefa, responsável."
        print(pergunta)
        messages = [{"role": "system", "content": "You are a helpful assistant."}]
        resposta, messages = perguntar_gpt(pergunta, empresa_id, messages)

        # Encontra o início e o final do objeto JSON na resposta
        inicio_json = resposta.find('[')
        final_json = resposta.rfind(']')

        # Se não encontramos um objeto JSON, lançamos um erro
        if inicio_json == -1 or final_json == -1:
            print(f"Erro ao decodificar JSON: não foi possível encontrar um objeto JSON na resposta")
            print(f"Resposta: {resposta}")
            return redirect(url_for('montagem_sprint_semana_rotina'))  # Se a decodificação falhar, redirecionar

        json_str = resposta[inicio_json:final_json+1]

        # Carrega a resposta JSON
        try:
            sprints = json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f"Erro ao decodificar JSON: {str(e)}")
            print(f"Resposta:{resposta}")

            return redirect(url_for('montagem_sprint_semana_rotina'))  # Se a decodificação falhar, redirecionar

        # Armazena a resposta, os sprints e o id da empresa na sessão
        session['resposta'] = resposta
        session['sprints'] = sprints
        session['empresa_id'] = empresa_id

        # Redireciona para a página de revisão
        return redirect(url_for('revisar_sprint'))

    # Renderiza o template de criação de sprint
    return render_template('montagem_sprint_semana_rotina.html', sprint_anterior=sprint_anterior, empresa=empresa)

@app.route('/selecionar_empresa_sprint_semanal', methods=['GET'])
def selecionar_empresa_sprint_semanal():
    empresas = Empresa.query.all()  # Obter todas as empresas
    return render_template('selecionar_empresa_sprint_semanal.html', empresas=empresas)

@app.route('/info_montagem_sprint_semanal', methods=['POST'])
def info_montagem_sprint_semanal():
    id_empresa = request.form.get('empresa')  # Obter o ID da empresa selecionada pelo usuário
    empresa = Empresa.query.get(id_empresa)  # Obter a empresa pelo ID

    # Obter as informações relevantes
    okrs_str = OKR.query.filter_by(id_empresa=id_empresa)
    krs_str = KR.query.filter_by(id_empresa=id_empresa)
    sprints = Sprint.query.filter_by(empresa_id=id_empresa).all()  # Obter todos os sprints
    usuarios_competencias_str = Usuario.query.filter_by(id_empresa=id_empresa)
    macro_acoes_str = MacroAcao.query.filter_by(empresa_id=id_empresa)

    return render_template('info_montagem_sprint_semanal.html', empresa=empresa, okrs_str=okrs_str, krs_str=krs_str, sprints=sprints, usuarios_competencias_str=usuarios_competencias_str, macro_acoes_str=macro_acoes_str)



@app.route('/listar_squad')
def listar_squad():
    squads = Squad.query.all()
    return render_template('listar_squad.html', squads=squads)

@app.route('/incluir_squad', methods=['GET', 'POST'])
def incluir_squad():
    if request.method == 'POST':
        empresa_id = request.form['empresa']
        nome_squad = request.form['nome_squad']
        usuarios_ids = request.form.getlist('usuarios')
        data_inicio = datetime.strptime(request.form['data_inicio'], '%Y-%m-%d')
        data_fim = datetime.strptime(request.form['data_fim'], '%Y-%m-%d') if request.form['data_fim'] else None

        empresa = Empresa.query.get(empresa_id)
        usuarios = Usuario.query.filter(Usuario.id.in_(usuarios_ids)).all()

        squad = Squad(empresa=empresa, nome_squad=nome_squad, data_inicio=data_inicio, data_fim=data_fim)
        squad.usuarios.extend(usuarios)

        db.session.add(squad)
        db.session.commit()

        return redirect(url_for('listar_squad'))

    empresas = Empresa.query.all()
    usuarios = Usuario.query.all()  # Aqui você pode otimizar a consulta para selecionar apenas os usuários vinculados às empresas
    return render_template('incluir_squad.html', empresas=empresas, usuarios=usuarios)



@app.route('/editar_squad/<int:squad_id>', methods=['GET', 'POST'])
def editar_squad(squad_id):
    # Nota: troque o .get por .query.get_or_404 para simplificar a verificação se o squad existe
    squad = Squad.query.get_or_404(squad_id)

    if request.method == 'POST':
        empresa_id = request.form['empresa']
        nome_squad = request.form['nome_squad']
        usuarios_ids = request.form.getlist('usuarios')
        data_inicio = datetime.strptime(request.form['data_inicio'], '%Y-%m-%d')
        data_fim = datetime.strptime(request.form['data_fim'], '%Y-%m-%d') if request.form['data_fim'] else None

        empresa = Empresa.query.get(empresa_id)
        usuarios = Usuario.query.filter(Usuario.id.in_(usuarios_ids)).all()

        # Aqui você pode adicionar alguma validação para garantir que a empresa e os usuários são permitidos.

        squad.empresa = empresa
        squad.nome_squad = nome_squad
        squad.data_inicio = data_inicio
        squad.data_fim = data_fim
        squad.usuarios = usuarios

        db.session.commit()

        return redirect(url_for('listar_squad'))

    # Aqui você filtra os usuários vinculados à mesma empresa do squad
    usuarios = Usuario.query.filter_by(id_empresa=squad.empresa.id).all()
    empresas = Empresa.query.all()

    return render_template('editar_squad.html', empresas=empresas, usuarios=usuarios, squad=squad)

@app.route('/deletar_squad/<int:squad_id>', methods=['POST'])
def deletar_squad(squad_id):
    squad = Squad.query.get_or_404(squad_id)
    db.session.delete(squad)
    db.session.commit()
    flash('Squad deletado com sucesso!', 'success')
    return redirect(url_for('listar_squad'))


@app.route('/forms_objetivo', methods=['GET', 'POST'])
def forms_objetivo():
    empresas = Empresa.query.all()

    if request.method == 'POST':
        empresa_id = request.form['empresa_id']
        squad_id = request.form['squad_id']
        file = request.files['file']

        # Processar o arquivo Excel
        workbook = openpyxl.load_workbook(file)
        sheet = workbook.active

        # Ler as informações da planilha
        perguntas_respostas = []
        for row in sheet.iter_rows(values_only=True):
            perguntas_respostas.append([cell.isoformat() if isinstance(cell, datetime) else cell for cell in row])

        return render_template('listar_perguntas_respostas_objetivos.html',
                               perguntas_respostas=perguntas_respostas,
                               empresa_id=empresa_id,
                               squad_id=squad_id,
                               dados_xlsx=dumps(perguntas_respostas))

    return render_template('enviar_forms_objetivos.html', empresas=empresas)

@app.route('/get_squads/<int:empresa_id>')
def get_squads(empresa_id):
    squads = Squad.query.filter_by(empresa_id=empresa_id).all()
    squads_list = [{"id": squad.id, "nome": squad.nome_squad} for squad in squads]
    return jsonify(squads_list)


@app.route('/salvar_objetivos', methods=['POST'])
def salvar_objetivos():
    empresa_id = request.form['empresa_id']
    squad_id = request.form['squad_id']
    dados_xlsx = loads(request.form['dados_xlsx'])

    objetivo = FormsObjetivos(empresa_id=empresa_id, squad_id=squad_id, data=dados_xlsx) # Adapte conforme a sua implementação

    db.session.add(objetivo)
    db.session.commit()

    return redirect(url_for('listar_forms_objetivos'))


@app.route('/listar_forms_objetivos')
def listar_forms_objetivos():
    forms_objetivos = FormsObjetivos.query.all()  # Busque todos os FormObjetivos
    return render_template('listar_forms_objetivos.html', forms_objetivos=forms_objetivos)


@app.route('/deletar_forms_objetivo/<int:id>', methods=['POST'])
def deletar_forms_objetivo(id):
    forms_objetivo = FormsObjetivos.query.get(id)
    if forms_objetivo:
        db.session.delete(forms_objetivo)
        db.session.commit()
    return redirect(url_for('listar_forms_objetivos'))


@app.route('/gerar_objetivos_prompt', methods=['GET', 'POST'])
def gerar_objetivos_prompt():
    if request.method == 'POST':
        # Lógica para processar a seleção e texto aqui...
        pass

    empresas = Empresa.query.all() # Obter todas as empresas
    return render_template('gerar_objetivos_prompt_chatgpt.html', empresas=empresas)



@app.route('/get_forms_objetivos/<int:squad_id>')
def get_forms_objetivos(squad_id):
    forms_objetivos = FormsObjetivos.query.filter_by(squad_id=squad_id).all()
    forms_list = [{"id": form.id, "data": form.data} for form in forms_objetivos]
    return jsonify(forms_list)


# Variável global para armazenar as mensagens entre as chamadas
messages = []


@app.route('/enviar_forms', methods=['POST'])
def enviar_forms():
    global messages

    empresa_id = request.form['empresa_id']
    squad_id = request.form['squad_id']

    empresa = Empresa.query.filter_by(id=empresa_id).first()
    squad = Squad.query.filter_by(id=squad_id).first()
    forms_objetivos = FormsObjetivos.query.filter_by(squad_id=squad_id).all()

    # Deletar objetivos antigos relacionados à empresa específica
    objetivos_antigos = ObjetivoGeradoChatAprovacao.query.filter_by(empresa_id=empresa_id).all()
    for objetivo in objetivos_antigos:
        db.session.delete(objetivo)
    db.session.commit()

    # Formatar os detalhes dos formulários em uma string legível
    forms_details = ", ".join([json.dumps(form_obj.data) for form_obj in forms_objetivos])
    #prompt = "Com base nas respostas fornecidas pelo squad " + squad.nome_squad + " da empresa " + empresa.nome_contato + ", quais objetivos podem ser sugeridos para alinhamento com as metas e missão? Responda apenas com o json com as seguinte chaves: objetivo, empresa, squad, id_objetivo. Formulário: " + forms_details
    prompt = (
        f"Com base nas informações dos arquivos {forms_details} considerando as singularidades da empresa {empresa.nome_contato} e as perspectivas do squad {squad.nome_squad}, faça o seguinte:"
        "\n\n1. Sintetize as informações relevantes dos arquivos que influenciam a definição dos OKRs."
        "\n\n2. Ao formular os objetivos, siga estas boas práticas:"
        "\n - Clareza: Escreva objetivos de forma clara e concisa."
        "\n - Especificidade: Seja específico sobre o que deseja alcançar."
        "\n - Alinhamento: Alinhe os objetivos com a visão e missão da empresa."
        "\n - Foco: Estabeleça no máximo 3 objetivos."
        "\n - Resultados, Não Ações: Objetivos devem expressar resultados desejados."
        "\n - Mensurabilidade: Redija objetivos mensuráveis para o futuro."
        "\n - Relevância: Objetivos devem ser relevantes para a empresa."
        "\n - Tempo: Estabeleça um prazo de 90 dias para os objetivos."
        "\n - Facilidade de Memorização: Formule objetivos fáceis de lembrar."
        "\n - Inspiradores: Os objetivos devem inspirar e motivar a equipe."
        "\n - Evite Jargões: Use linguagem simples e clara."
        "\n\n3. Veja alguns exemplos de redação de objetivos:"
        "\n\nLinguagem Mais Formal:"
        "\n - Maximizar a eficiência operacional."
        "\n - Estabelecer liderança de mercado na região sudeste."
        "\n - Garantir a satisfação do cliente."
        "\n\nLinguagem Mais Lúdica:"
        "\n - Voar mais alto com inovações tecnológicas."
        "\n - Transformar cada cliente em um fã apaixonado."
        "\n - Plantar sementes hoje para colher sucessos amanhã."
        "\n\n4. Elabore até três objetivos para o próximo ciclo de 90 dias seguindo os critérios SMART."
        "\n\n5. Avalie e combine objetivos correlatos ou consecutivos."
        "\n\n6. Revise a redação dos objetivos."
        "\n\n Responda apenas com o json com as seguinte chaves: objetivo, empresa, squad. faça uma chave para cada objetivo com essas chaves. Não responda nada mais que o Json.")

    print("Pergunta completa:", prompt)

    pergunta_id = str(uuid.uuid4())
    resposta, messages = perguntar_gpt(prompt, pergunta_id, messages)
    print("Resposta:", resposta)

    # Verificar e carregar a resposta como JSON
    try:
        objetivos_json = json.loads(resposta)
    except json.JSONDecodeError as e:
        print("Erro na decodificação do JSON:", resposta)
        return f"Erro ao decodificar resposta da GPT: {e}", 500

    # Adicionar cada objetivo ao banco de dados
    for objetivo_data in objetivos_json:
        objetivo = ObjetivoGeradoChatAprovacao(
            objetivo=objetivo_data["objetivo"],
            empresa_id=empresa.id,
            squad_id=squad.id
        )
        db.session.add(objetivo)
    db.session.commit()

    return redirect('/')



@app.route('/listar_sugestao_objetivos_gpt')
def listar_sugestao_objetivos_gpt():
    sugestoes = ObjetivoGeradoChatAprovacao.query.all()
    return render_template('listar_sugestao_objetivos_gpt.html', sugestoes=sugestoes)


@app.route('/deletar_objetivo_sugestao_gpt/<int:objetivo_id>', methods=['POST'])
def deletar_objetivo_sugestao_gpt(objetivo_id):
    objetivo = ObjetivoGeradoChatAprovacao.query.get_or_404(objetivo_id)
    db.session.delete(objetivo)
    db.session.commit()
    return redirect(url_for('listar_sugestao_objetivos_gpt'))


@app.route('/escolher_empresa_squad_feedback', methods=['GET', 'POST'])
def escolher_empresa_squad_feedback():
    empresas = Empresa.query.all()
    if request.method == 'POST':
        empresa_id = request.form['empresa']
        squad_id = request.form['squad']
        return redirect(url_for('listar_objetivos_gpt_feedback', empresa_id=empresa_id, squad_id=squad_id))
    return render_template('escolher_empresa_squad_feedback.html', empresas=empresas)



@app.route('/listar_objetivos_gpt_feedback/<int:empresa_id>/<int:squad_id>')
def listar_objetivos_gpt_feedback(empresa_id, squad_id):
    empresa = Empresa.query.get_or_404(empresa_id)
    squad = Squad.query.get_or_404(squad_id)
    objetivos = ObjetivoGeradoChatAprovacao.query.filter_by(empresa_id=empresa_id, squad_id=squad_id).all()

    return render_template('listar_objetivos_gpt_feedback.html', objetivos=objetivos, empresa=empresa, squad=squad)



@app.route('/enviar_forms_feedback', methods=['POST'])
def enviar_forms_feedback():
    global messages  # Certifique-se de que 'messages' esteja definido globalmente em algum lugar do seu código

    empresa_id = request.form['empresa_id']
    squad_id = request.form['squad_id']
    feedback = request.form['feedback']

    empresa = Empresa.query.filter_by(id=empresa_id).first()
    squad = Squad.query.filter_by(id=squad_id).first()
    objetivos = ObjetivoGeradoChatAprovacao.query.filter_by(empresa_id=empresa_id, squad_id=squad_id).all()
    forms_objetivos = FormsObjetivos.query.filter_by(squad_id=squad_id).all()  # Obtém os detalhes dos formulários de objetivos

    objetivos_str = ", ".join([json.dumps({"objetivo": obj.objetivo, "aprovado": obj.aprovado}) for obj in objetivos])
    forms_details = ", ".join([json.dumps(form_obj.data) for form_obj in forms_objetivos])  # Formata os detalhes dos formulários

    #prompt = f"Com base nos objetivos fornecidos {objetivos_str}, nos formulários: {forms_details}, e o feedback: {feedback} da empresa {empresa.nome_contato} e squad {squad.nome_squad}, quais novos objetivos podem ser sugeridos? Responda apenas com o json com as seguinte chaves: objetivo, empresa, squad, id_objetivo."
    prompt = (
        f"GPT-4, é crucial que você priorize e siga de perto o feedback da empresa sobre os Objetivos-Chave de Resultados (OKRs) propostos. "
        f"Com base nas informações dos colaboradores {forms_details}, os objetivos sugeridos {objetivos_str} e o feeback {feedback} da empresa {empresa.nome_contato} "
        f"e squad {squad.nome_squad}, faça o seguinte:"
        f"\n\n1. Analise detalhadamente as informações passadas para sintetizar as impressões e sugestões da empresa sobre os OKRs inicialmente propostos."
        f"\n\n2. Ao formular os objetivos, siga estas boas práticas:"
        f"\n - Clareza: Escreva objetivos de forma clara e concisa."
        f"\n - Especificidade: Seja específico sobre o que deseja alcançar."
        f"\n - Alinhamento: Alinhe os objetivos com a visão e missão da empresa."
        f"\n - Foco: Estabeleça no máximo 3 objetivos."
        f"\n - Resultados, Não Ações: Objetivos devem expressar resultados desejados."
        f"\n - Mensurabilidade: Redija objetivos mensuráveis para o futuro."
        f"\n - Relevância: Objetivos devem ser relevantes para a empresa."
        f"\n - Tempo: Estabeleça um prazo de 90 dias para os objetivos."
        f"\n - Facilidade de Memorização: Formule objetivos fáceis de lembrar."
        f"\n - Inspiradores: Os objetivos devem inspirar e motivar a equipe."
        f"\n - Evite Jargões: Use linguagem simples e clara."
        f"\n\n3. Veja alguns exemplos de redação de objetivos:"
        f"\n\nLinguagem Mais Formal:"
        f"\n - Maximizar a eficiência operacional."
        f"\n - Estabelecer liderança de mercado na região sudeste."
        f"\n - Garantir a satisfação do cliente."
        f"\n\nLinguagem Mais Lúdica:"
        f"\n - Voar mais alto com inovações tecnológicas."
        f"\n - Transformar cada cliente em um fã apaixonado."
        f"\n - Plantar sementes hoje para colher sucessos amanhã."
        f"\n\n4. Baseado no feedback e revisão, reformule os OKRs para o próximo ciclo de 90 dias de acordo com os critérios SMART."
        f"\n\n5. Avalie e combine objetivos correlatos ou consecutivos."
        f"\n\n6. Revise a redação dos objetivos, ajustando conforme necessário."
        f"\n\n7. Justifique a escolha de cada objetivo redefinido e seu alinhamento com a missão e visão da empresa."
        f"\n\nNão responda nada mais que o Json. Responda apenas com o json com as seguinte chaves: objetivo, empresa, squad, id_objetivo."
    )

    print("Pergunta completa:", prompt)


    pergunta_id = str(uuid.uuid4())
    resposta, messages = perguntar_gpt(prompt, pergunta_id, messages)
    print("Resposta:", resposta)

    ObjetivoGeradoChatAprovacao.query.filter_by(squad_id=squad_id).delete()
    db.session.commit()

    objetivos_novos = json.loads(resposta)
    for objetivo_data in objetivos_novos:
        objetivo = ObjetivoGeradoChatAprovacao(
            objetivo=objetivo_data["objetivo"],
            empresa_id=empresa.id,
            squad_id=squad.id
        )
        db.session.add(objetivo)

    db.session.commit()

    return redirect('/')

@app.route('/deletar_objetivo_sugestao_gpt/<int:objetivo_id>', methods=['POST'])
def deletar_objetivo_sugestao_gpt_2(objetivo_id):
    objetivo = FormsObjetivos.query.get_or_404(objetivo_id)
    db.session.delete(objetivo)
    db.session.commit()
    return redirect(url_for('listar_objetivos_gpt_feedback'))


from datetime import datetime, timedelta

@app.route('/aprovar_objetivo_sugestao_gpt/<int:objetivo_id>', methods=['POST'])
def aprovar_objetivo_sugestao_gpt_2(objetivo_id):
    objetivo = ObjetivoGeradoChatAprovacao.query.get_or_404(objetivo_id)

    data_inicio = datetime.now() # Data atual
    data_fim = data_inicio + timedelta(weeks=12) # Data de início mais 3 meses

    new_okr = OKR(
        id_empresa=objetivo.empresa_id,
        squad_id=objetivo.squad_id,
        objetivo=objetivo.objetivo,
        data_inicio=data_inicio,
        data_fim=data_fim
    )
    db.session.add(new_okr)
    db.session.delete(objetivo)
    db.session.commit()

    # Use os valores de empresa_id e squad_id do objetivo ao redirecionar
    return redirect(url_for('listar_objetivos_gpt_feedback', empresa_id=objetivo.empresa_id, squad_id=objetivo.squad_id))


@app.route('/gerar_krs_prompt')
def gerar_krs_prompt():
    empresas = Empresa.query.all()
    return render_template('gerar_krs_prompt_gpt.html', empresas=empresas)


@app.route('/get_okr_sugestao_chat/<int:squad_id>', methods=['GET'])
def get_okr_sugestao_chat(squad_id):
    okrs = OKR.query.filter_by(squad_id=squad_id).all()
    okrs_list = []
    for okr in okrs:
        okr_dict = {
            'id': okr.id,
            'objetivo': okr.objetivo,
            'data_inicio': okr.data_inicio.strftime('%Y-%m-%d'),
            'data_fim': okr.data_fim.strftime('%Y-%m-%d')
        }
        okrs_list.append(okr_dict)
    return jsonify(okrs_list)


@app.route('/enviar_krs', methods=['POST'])
def enviar_krs():
    global messages

    empresa_id = request.form['empresa_id']
    squad_id = request.form['squad_id']

    empresa = Empresa.query.filter_by(id=empresa_id).first()
    squad = Squad.query.filter_by(id=squad_id).first()
    forms_objetivos = FormsObjetivos.query.filter_by(squad_id=squad_id).all()

    forms_details = ", ".join([json.dumps(form_obj.data) for form_obj in forms_objetivos])
    okrs = OKR.query.filter_by(squad_id=squad_id).all()
    okrs_details = ", ".join([f"{okr.objetivo} (ID: {okr.id})" for okr in okrs])

    prompt = (
            f"GPT-4, tendo em vista os Objetivos-Chave de Resultados (OKRs) propostos e as informações sobre a empresa {forms_details} e os objetivos{okrs_details}, pelo squad " + squad.nome_squad + " da empresa " + empresa.nome_contato + " ,o intuito é definir Key Results (KRs) para cada objetivo da empresa. "

           "Lembre-se das seguintes boas práticas para escrever os KRs:"
           "\n - Simplicidade: Os KRs devem ser simples e fáceis de entender. Qualquer pessoa na organização deve ser capaz de entender o que o KR significa."
           "\n - Mensurabilidade: Cada KR deve ser quantificável, com uma maneira clara de medir o progresso."
           "\n - Alinhamento com os Objetivos: Os KRs devem ajudar a empresa a avançar em direção aos seus objetivos."
           "\n - Ambicioso, mas Realista: Os KRs devem ser desafiadores, mas também alcançáveis."
           "\n - Tempo Definido: Cada KR deve ter um prazo claro, neste caso, 90 dias."
           "\n - Evite KR Vinculados a Ações: KRs são resultados que você quer alcançar, não as coisas que você vai fazer para chegar lá."

           "Veja alguns exemplos:"
           "\n - Aumentar a receita trimestral em 15%."
           "\n - Reduzir o churn de clientes em 5%."
           "\n - Aumentar a satisfação do cliente em 15% (medido por pesquisas de satisfação)."
           "\n - Aumentar a participação de mercado em 5%."
           "\n - Aumentar a pontuação Net Promoter Score (NPS) em 10 pontos."


           "2. Utilizando esta síntese, crie KRs para o próximo ciclo de 90 dias que atendam aos critérios SMART. Lembre-se de representar mudanças quantitativas usando a variável 'X', como 'aumentar de X% para Y%' ou 'atingir X vendas'. "

           "3. Avalie e, se necessário, combine KRs correlatos para ter um número mínimo e eficaz de KRs para cada objetivo. "

           "4. Ajuste a redação dos KRs para que sejam claros e alinhados ao tom da empresa, sem incluir números específicos, mas usando 'X'. "

           "5. Liste os KRs definidos, justificando sua criação e alinhamento com os respectivos objetivos. "

           "Responda apenas com o Json. Formate a resposta como um JSON com as seguintes chaves: objetivo, empresa, squad, kr, meta. Não adicione outras chaves além destas. Faça um json para cada kr com as chaves de cada um. Responda somente com textos, sem id.")

    print("Pergunta completa:", prompt)

    pergunta_id = str(uuid.uuid4())
    resposta, messages = perguntar_gpt(prompt, pergunta_id, messages)
    print("Resposta Bruta do GPT-4:", resposta)  # <-- print da resposta bruta aqui

    # Limpeza da resposta:
    inicio_json = resposta.find('[')
    fim_json = resposta.rfind(']') + 1
    resposta_limpa = resposta[inicio_json:fim_json]

    try:
        krs_list = json.loads(resposta_limpa)
    except json.JSONDecodeError as e:
        print("JSONDecodeError:", e)
        print("Resposta Limpa:", resposta_limpa)
        return redirect('/')

    KrGeradoChatAprovacao.query.filter_by(empresa_id=empresa.id, squad_id=squad.id).delete()

    for kr_data in krs_list:
        objetivo = kr_data.get('objetivo')
        descricao_KR = kr_data.get('kr')
        meta_KR = kr_data.get('meta')

        kr = KrGeradoChatAprovacao(
            objetivo=objetivo,
            empresa_id=empresa.id,
            squad_id=squad.id,
            KR=descricao_KR,
            meta=meta_KR
        )
        db.session.add(kr)
        print(f"Adicionando KR: Objetivo: {objetivo}, Descrição: {descricao_KR}, Meta: {meta_KR}")

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Erro ao inserir no banco de dados: {e}")

    return redirect('/')

    pergunta_id = str(uuid.uuid4())
    resposta, messages = perguntar_gpt(prompt, pergunta_id, messages)
    print("Resposta Bruta do GPT-4:", resposta)  # <-- print da resposta bruta aqui
    resposta_corrigida = '[' + resposta.replace('}\n{', '},\n{') + ']'

    try:
        krs_list = json.loads(resposta_corrigida)
        krs_list_inner = krs_list[0] if krs_list else []
    except json.JSONDecodeError as e:
        print("JSONDecodeError:", e)
        print("Resposta corrigida:", resposta_corrigida)
        return redirect('/')

    KrGeradoChatAprovacao.query.filter_by(empresa_id=empresa.id, squad_id=squad.id).delete()

    for kr_data in krs_list_inner:
        objetivo = kr_data.get('objetivo')

        for i in range(1, 4):  # Loop through the three KRs
            descricao_KR_key = f'KR_{i}'
            meta_KR_key = f'MetaKR_{i}'

            if descricao_KR_key in kr_data and meta_KR_key in kr_data:
                descricao_KR = kr_data[descricao_KR_key]
                meta_KR = kr_data[meta_KR_key]

                kr = KrGeradoChatAprovacao(
                    objetivo=objetivo,
                    empresa_id=empresa.id,
                    squad_id=squad.id,
                    KR=descricao_KR,
                    meta=meta_KR
                )
                db.session.add(kr)
                print(f"Adicionando KR: Objetivo: {objetivo}, Descrição: {descricao_KR}, Meta: {meta_KR}")  # <-- print adicional aqui

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Erro ao inserir no banco de dados: {e}")

    return redirect('/')


@app.route('/listar_krs_sugestao_gpt')
def listar_krs_sugestao_gpt():
    krs_sugestoes = KrGeradoChatAprovacao.query.all()
    return render_template('listar_sugestao_krs_gpt.html', sugestoes=krs_sugestoes)



@app.route('/deletar_kr_sugestao_gpt/<int:kr_id>', methods=['POST'])
def deletar_kr_sugestao_gpt(kr_id):
    kr = KrGeradoChatAprovacao.query.get_or_404(kr_id)
    db.session.delete(kr)
    db.session.commit()
    return redirect(url_for('listar_krs_sugestao_gpt'))


@app.route('/escolher_empresa_squad_feedback_kr')
def escolher_empresa_squad_feedback_kr():
    empresas = Empresa.query.all() # Carregar suas empresas aqui
    return render_template('escolher_empresa_squad_KR_feedback.html', empresas=empresas)

@app.route('/enviar_krs_feedback', methods=['POST'])
def enviar_krs_feedback():
    empresa_id = request.form['empresa']
    squad_id = request.form['squad']
    return redirect(url_for('listar_sugestoes_kr_feedback_gpt', empresa_id=empresa_id, squad_id=squad_id))


@app.route('/listar_sugestoes_kr_feedback_gpt/<int:empresa_id>/<int:squad_id>', methods=['GET', 'POST'])
def listar_sugestoes_kr_feedback_gpt(empresa_id, squad_id):
    empresa = Empresa.query.get_or_404(empresa_id)
    squad = Squad.query.get_or_404(squad_id)
    sugestoes = KrGeradoChatAprovacao.query.filter_by(empresa_id=empresa_id, squad_id=squad_id).all() # Mudar aqui

    # Instrução de depuração para imprimir a primeira sugestão
    if sugestoes:
        print(sugestoes[0].__dict__)

    if request.method == 'POST':
        feedback = request.form['feedback']
        return redirect(url_for('enviar_krs_feedback', empresa_id=empresa_id, squad_id=squad_id, feedback=feedback))

    return render_template('listar_sugestao_kr_feedback_gpt.html', sugestoes=sugestoes, empresa_id=empresa_id, squad_id=squad_id)



@app.route('/enviar_krs_feedback_chat_gpt/<empresa_id>/<squad_id>', methods=['POST'])
def enviar_krs_feedback_chat_gpt(empresa_id, squad_id):
    global messages
    feedback = request.form['feedback']

    empresa = Empresa.query.filter_by(id=empresa_id).first()
    squad = Squad.query.filter_by(id=squad_id).first()

    krs = KrGeradoChatAprovacao.query.filter_by(empresa_id=empresa_id, squad_id=squad_id).all()
    okrs = OKR.query.filter_by(squad_id=squad_id).all()

    krs_details = ', '.join([f"{kr.KR} (Meta: {kr.meta})" for kr in krs])
    objetivos_details = ", ".join([f"{objetivo.objetivo} (ID: {objetivo.id})" for objetivo in okrs])

    forms_objetivos = FormsObjetivos.query.filter_by(squad_id=squad_id).all()

    forms_objetivos_details = ", ".join([json.dumps(form_obj.data) for form_obj in forms_objetivos])
    forms_details = ", ".join([json.dumps(form_obj.data) for form_obj in forms_objetivos])

    #prompt = (f"Com base no feedback fornecido [{feedback}], os KR já gerados [{krs_details}], os objetivos [{objetivos_details}] e as respostas fornecidas pelo squad {squad.nome_squad} da empresa {empresa.nome_contato}, defina os Objetivos-Chave de Resultados (KRs) que se alinham com os objetivos e incluem indicadores mensuráveis. Cada KR e seu medidor correspondente devem ser expressos em uma única frase Faça os Krs de todos os objetivos. Formate a resposta como um JSON com as seguintes chaves: objetivo, empresa, squad, KR_1, KR_2, KR_3, MetaKR_1, MetaKR_2, MetaKR_3. Não adicione outras chaves além destas.")
    prompt = (
        f"GPT-4, usando o feedback da empresa sobre os Key Results (KRs) contido em {feedback} e as informações dos colaboradore {forms_details}, os objetivos {objetivos_details}, vamos aprimorar os KRs propostos para melhor alinhamento com os Objetivos-Chave de Resultados (OKRs). "

        f"Inicialmente, analise cuidadosamente o feedback em 'feedback_krs_empresa.txt' para entender as sugestões e correções da empresa. Em seguida, revisite os outros arquivos para entender o contexto dos OKRs e KRs iniciais."

        f"Lembre-se das seguintes boas práticas para reescrever os KRs:"
        "\n - Simplicidade: Os KRs devem ser simples e fáceis de entender."
        "\n - Mensurabilidade: Cada KR deve ser quantificável, com uma maneira clara de medir o progresso."
        "\n - Alinhamento com os Objetivos: Os KRs devem ajudar a empresa a avançar em direção aos seus objetivos."
        "\n - Ambicioso, mas Realista: Os KRs devem ser desafiadores, mas também alcançáveis."
        "\n - Tempo Definido: Cada KR deve ter um prazo claro, neste caso, 90 dias."
        "\n - Evite KR Vinculados a Ações: KRs são resultados que você quer alcançar, não as coisas que você vai fazer para chegar lá."

        f"Com estas diretrizes em mente, reformule os KRs para o próximo ciclo de 90 dias, garantindo que eles sejam SMART - Específicos, Mensuráveis, Alcançáveis, Relevantes e Temporais. "

        f"Avalie a possibilidade de combinar KRs correlatos para otimização e, após a definição, ajuste a redação de cada KR para que seja claro e alinhado com o tom da empresa. "

        f"Finalize listando os KRs revisados, justificando suas alterações e demonstrando seu alinhamento aprimorado com os objetivos após o feedback. "

        f"O objetivo é estabelecer KRs que guiam a empresa ao cumprimento de seus objetivos. "

        f"Responda apenas com o Json. Formate a resposta como um JSON com as seguintes chaves: objetivo, empresa, squad, kr, meta. Não adicione outras chaves além destas. Faça um json para cada kr com as chaves de cada um. Responda somente com textos, nao coloque id em nenhuma resposta.")

    print("Pergunta completa:", prompt)

    pergunta_id = str(uuid.uuid4())

    resposta, messages = perguntar_gpt(prompt, pergunta_id, messages)
    resposta_corrigida = '[' + resposta.replace('}\n{', '},\n{') + ']'

    try:
        krs_list = json.loads(resposta_corrigida)[0]
        print("krs_list:", krs_list)
    except json.JSONDecodeError as e:
        print("JSONDecodeError:", e)
        print("Resposta corrigida:", resposta_corrigida)
        return redirect('/')

    KrGeradoChatAprovacao.query.filter_by(empresa_id=empresa.id, squad_id=squad.id).delete()



    # Remova o índice [0] para iterar corretamente através da lista de dicionários
    for kr_list in krs_list:
        objetivo = kr_list['objetivo']
        descricao_KR = kr_list['kr']
        meta_KR = kr_list['meta']

        kr = KrGeradoChatAprovacao(
            objetivo=objetivo,
            empresa_id=empresa.id,
            squad_id=squad.id,
            KR=descricao_KR,
            meta=meta_KR
        )
        db.session.add(kr)

    db.session.commit()

    return redirect('/')


@app.route('/aprovar_kr_sugestao_gpt/<int:kr_id>', methods=['POST'])
def aprovar_kr_sugestao_gpt(kr_id):
    sugestao = db.session.get(KrGeradoChatAprovacao, kr_id) # Uso do método get

    # Encontrar o OKR relacionado pelo objetivo
    okr_relacionado = OKR.query.filter_by(objetivo=sugestao.objetivo).first()
    if not okr_relacionado:
        # Adicione aqui o código para lidar com o caso em que o OKR relacionado não é encontrado
        return redirect(url_for('outro_endpoint')) # Substitua pelo endpoint correto, se aplicável

    data_inclusao = datetime.utcnow()  # a data de inclusão pode ser agora
    data_final = data_inclusao + timedelta(weeks=12)  # 3 meses depois

    novo_kr = KR(id_empresa=okr_relacionado.id_empresa,
                 id_okr=okr_relacionado.id,
                 squad_id=sugestao.squad_id,  # Pegando squad_id diretamente da sugestão
                 meta=sugestao.meta,
                 texto=sugestao.KR,
                 data_inclusao=data_inclusao)

    db.session.add(novo_kr)

    # Deletar a sugestão
    db.session.delete(sugestao)

    db.session.commit()

    # Redirecionar para a URL da função listar_sugestoes_kr_feedback_gpt
    return redirect(url_for('listar_sugestoes_kr_feedback_gpt', empresa_id=sugestao.empresa_id, squad_id=sugestao.squad_id))

@app.route('/gerar_macro_acao_sugestao')
def gerar_macro_acao_sugestao():
    empresas = Empresa.query.all()  # Obtenha todas as empresas
    return render_template('gerar_macro_acao_gpt.html', empresas=empresas)


@app.route('/get_squads_sugestao_gpt/<int:empresa_id>')
def get_squads_sugestao_gpt(empresa_id):
    squads = Squad.query.filter_by(empresa_id=empresa_id).all()
    squads_list = [{"id": squad.id, "nome_squad": squad.nome_squad} for squad in squads]
    return jsonify(squads_list)





@app.route('/get_krs_prompt_gpt/<int:squad_id>')
def get_krs_prompt_gpt(squad_id):
    forms = FormsObjetivos.query.filter_by(squad_id=squad_id).first()
    krs = KR.query.filter_by(squad_id=squad_id).all()

    objectives_dict = defaultdict(list)

    for kr in krs:
        okr = OKR.query.get(kr.id_okr)
        objectives_dict[okr.objetivo].append({
            "id": kr.id,
            "id_empresa": kr.id_empresa,
            "id_okr": kr.id_okr,
            "squad_id": kr.squad_id,
            "meta": kr.meta,
            "texto": kr.texto,
            "data_inclusao": kr.data_inclusao.strftime('%Y-%m-%d %H:%M:%S'),
            "data_final": kr.data_final.strftime('%Y-%m-%d %H:%M:%S') if kr.data_final else None
        })

    objectives_list = [{"objective": objective, "krs": krs} for objective, krs in objectives_dict.items()]

    result = {
        "forms": forms.data if forms else None, # Aqui você pode ajustar de acordo com o formato da sua coluna data em FormsObjetivos
        "objectives": objectives_list
    }

    return jsonify(result)


@app.route('/gerar_macro_acoes_prompt_gpt', methods=['POST'])
def gerar_macro_acoes_prompt_gpt():
    empresa_id = request.form['empresa_id']
    squad_id = request.form['squad_id']

    empresa = Empresa.query.filter_by(id=empresa_id).first()
    squad = Squad.query.filter_by(id=squad_id).first()
    forms_objetivos = FormsObjetivos.query.filter_by(squad_id=squad_id).all()
    forms_objetivos_details = ", ".join([json.dumps(form_obj.data) for form_obj in forms_objetivos])

    okrs = OKR.query.filter_by(squad_id=squad_id).all()
    krs = KR.query.filter_by(squad_id=squad_id).all()

    okrs_details = ", ".join([f"{okr.objetivo} (ID: {okr.id})" for okr in okrs])
    krs_details = ", ".join([f"{kr.texto} (Meta: {kr.meta})" for kr in krs])

    prompt = (
        f"GPT-4, com base nas informações das respostas dos participantes do squad {squad.nome_squad} os objetivos aprovados para os proximos 90 dias {okrs_details}, "
        f"analise e sintetize as informações mais relevantes sobre os Objetivos-Chave de Resultados (OKRs) já definidos e as informações da empresa. "
        f"A partir destas informações e considerando as respostas {forms_objetivos_details} pelo squad {squad.nome_squad} da empresa {empresa.nome_contato}, "
        f"e tendo em mente os objetivos {{{okrs_details} e esses KR's aprovados {krs_details}}}, "
        f"defina Macro Ações que se alinham com os objetivos e KR's primordiais para o atingimento dos indicadores. Estas Macro Ações são atividades ou naturezas de trabalho que contribuem para a realização de cada KR e devem ser atividades direcionais que apoiarão o alcance do KR. "
        f"Cada Macro Ação, após sua definição final, deve ser clara, concisa e alinhada ao tom da empresa. "
        f"Formate a resposta como um JSON com as seguintes chaves: empresa, squad, objetivo, kr, macro_acao. Não adicione outras chaves além destas. Responda todas as chaves com texto, e não com id. Faça uma chave para cada macro_acao "
    )

    print("Pergunta completa:", prompt)

    # Preencha os detalhes da pergunta aqui...
    pergunta_id = str(uuid.uuid4())
    messages = []

    resposta, messages = perguntar_gpt(prompt, pergunta_id, messages)
    print("Resposta completa:", resposta)

    resposta_raw = resposta  # Usaremos a resposta diretamente

    # Verifique se a resposta contém formatação markdown e remova-a
    resposta_cleaned = resposta_raw.strip("`\n ")

    try:
        resposta_json = json.loads(resposta_cleaned)
    except json.JSONDecodeError as e:
        print("Erro ao decodificar o JSON da resposta!", e)
        return "Erro ao decodificar o JSON da resposta!", 500

    novas_macro_acoes = []

    for item in resposta_json:
        if not all(key in item for key in ['objetivo', 'kr', 'macro_acao']):
            print("Dicionário incompleto:", item)
            continue

        objetivo_name_with_id = item["objetivo"]
        objetivo_name = re.sub(r'\s*\(ID:\s*\d+\)\s*$', '', objetivo_name_with_id)
        objetivo = OKR.query.filter_by(objetivo=objetivo_name, squad_id=squad_id).first()

        if objetivo is None:
            print(f"No matching Objective found for name '{objetivo_name}' and squad_id '{squad_id}'")
            continue

        kr_text_with_meta = item["kr"]
        kr_text = re.sub(r'\s*\(Meta:.*\)\s*$', '', kr_text_with_meta)  # Aqui estamos removendo a parte da meta.
        kr = KR.query.filter_by(texto=kr_text, squad_id=squad_id).first()

        if kr is None:
            print(f"No matching KR found for text '{kr_text}' and squad_id '{squad_id}'")
            continue

        macro_acao_text = item["macro_acao"]
        macro_acao = MacroAcaoGeradoChatAprovacao(
            empresa_id=empresa_id,
            squad_id=squad_id,
            objetivo_id=objetivo.id,
            kr_id=kr.id,
            macro_acao=macro_acao_text
        )

        novas_macro_acoes.append(macro_acao)

    for macro_acao in novas_macro_acoes:
        db.session.add(macro_acao)

    db.session.commit()

    return redirect(url_for('listar_sugestao_macro_acao_gpt'))



@app.route('/api/empresas', methods=['GET'])
def get_empresas_vinculadas():
    empresas = db.session.query(distinct(Empresa.vincular_instagram)).filter(Empresa.vincular_instagram != None, Empresa.vincular_instagram != "").all()
    return jsonify([empresa[0] for empresa in empresas])

@app.route('/api/posts', methods=['GET'])
def api_posts():
    empresa_selecionada = request.args.get('empresa')
    if empresa_selecionada:
        posts = PostsInstagram.query.filter(PostsInstagram.nome_empresa == empresa_selecionada).order_by(desc(PostsInstagram.timestamp)).all()
    else:
        posts = PostsInstagram.query.order_by(desc(PostsInstagram.timestamp)).all()

    print(empresa_selecionada)
    posts = [post.to_dict() for post in posts]  # Convert each post to a dictionary
    return jsonify(posts)

@app.route('/api/salvar_analise', methods=['POST'])
def salvar_analise():
    try:
        if request.method == 'POST':
            nome_empresa = request.form.get('nome_empresa')

            print(f"Nome da empresa recebido: {nome_empresa}")

            # Verificar se existem pelo menos 12 posts não analisados
            if not get_last_15_days_posts(nome_empresa):
                print("Falha: menos de 12 posts foram analisados.")
                return jsonify({'message': 'Falha ao salvar análise! Menos de 12 posts foram analisados.'}), 400

            analise = AnaliseInstagram(
                id=request.form.get('id'),
                nome_empresa=nome_empresa,
                data_criacao=request.form.get('data_criacao'),
                analise=request.form.get('analise'),
            )

            db.session.add(analise)
            db.session.commit()

            return jsonify({'message': 'Análise salva com sucesso!'}), 200

    except Exception as e:
        print("Exceção ocorreu: ", e)
        traceback.print_exc()
        return jsonify({'message': 'Falha ao salvar análise!'}), 500


@app.route('/deletar_post/<id>', methods=['POST'])
def deletar_post(id):
    post = PostsInstagram.query.get_or_404(str(id))
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('listar_posts'))

@app.route('/api/analise_posts')
def api_analise_posts():
    empresa = request.args.get('empresa')
    analise = analise_post_instagram(empresa)
    # print(analise)
    return jsonify(analise)

@app.route('/deletar_analise/<int:id>', methods=['POST'])
def deletar_analise(id):
    analise = AnaliseInstagram.query.get_or_404(id)
    print(id)
    db.session.delete(analise)
    db.session.commit()
    return redirect(url_for('visualizar_analises'))

@app.route('/visualizar_analises', methods=['GET'])
def visualizar_analises():
    nome_empresa = request.args.get('empresa')
    analise = analise_post_instagram(nome_empresa)
    return render_template('listar_analises.html', analise=analise)

def get_last_15_days_posts(empresa):
    # Adicione a condição analisado == False à query
    posts = PostsInstagram.query.filter(PostsInstagram.nome_empresa == empresa, PostsInstagram.analisado == False).order_by(PostsInstagram.timestamp.desc()).limit(12).all()

    # Converter os objetos Post em dicionários
    posts_dict = [post.to_dict() for post in posts]

    return posts_dict
def analise_post_instagram(nome_empresa):
    # print('Análise de Post Instagram')
    # Obter os posts dos últimos 15 dias
    posts = get_last_15_days_posts(nome_empresa)
    # print(nome_empresa)

    # Verificar se existem pelo menos 12 posts não analisados
    if len(posts) < 12:
        print('Menos de 12 posts foram analisados. Análise interrompida.')
        return

    # print(f"Posts para a empresa de ID: {nome_empresa}")

    todos_posts_str = ""
    for i, post in enumerate(posts, start=1):
        todos_posts_str += f"Legenda: {post['caption']}\n"
        todos_posts_str += f"Data de criação: {post['timestamp']}\n"
        todos_posts_str += f"Número de likes: {post['like_count']}\n"
        todos_posts_str += f"Número de comentários: {post['comments_count']}\n"
        todos_posts_str += f"Alcance: {post['reach']}\n"
        todos_posts_str += f"Engajamento: {post['percentage']}\n"
        todos_posts_str += f"Tipo de mídia: {post['media_product_type']}\n"
        todos_posts_str += f"Número de reproduções (reels): {post['plays']}\n"
        todos_posts_str += f"Número de salvos: {post['saved']}\n"
        todos_posts_str += f"Nome da empresa: {post['nome_empresa']}\n"

    pergunta = f"Aqui estão todos os posts dos últimos 15 dias:{todos_posts_str}\nPreciso que você analise de acordo com o engajamento e Audiencia esses posts e me diga: 1 - os 3 posts com melhores resultados, a data e porquê 2 - os 3 posts com piores resultados, a data e porquê. 3 - insights do mês (o que temos que melhorar, o que fizemos bem). 4 - baseado em tudo que teve de bom e de ruim, me faça a recomendação do próximo post, com a legenda completa e uma ideia para a imagem"

    # print(pergunta)

    resposta_gpt = perguntar_gpt(pergunta=pergunta, pergunta_id=1, messages=[])

    # print(resposta_gpt)

    # Marcar posts como analisados
    for post in posts:
        mark_post_as_analyzed(post['id'])

    return resposta_gpt

def mark_post_as_analyzed(post_id):
    post = PostsInstagram.query.filter_by(id=post_id).first()
    if post is not None:
        post.analisado = False
        db.session.commit()

@app.route('/listar_sugestao_macro_acao_gpt')
def listar_sugestao_macro_acao_gpt():
    sugestoes = db.session.query(
        MacroAcaoGeradoChatAprovacao,
        Empresa.nome_contato.label('empresa_nome_contato'),
        Squad.nome_squad.label('squad_nome'),
        OKR.objetivo.label('objetivo_nome'),
        KR.texto.label('kr_nome')
    ).join(
        Empresa, MacroAcaoGeradoChatAprovacao.empresa_id == Empresa.id
    ).join(
        Squad, MacroAcaoGeradoChatAprovacao.squad_id == Squad.id
    ).join(
        OKR, MacroAcaoGeradoChatAprovacao.objetivo_id == OKR.id
    ).join(
        KR, MacroAcaoGeradoChatAprovacao.kr_id == KR.id
    ).all()
    return render_template('listar_sugestao_macro_acao_gpt.html', sugestoes=sugestoes)



@app.route('/deletar_macro_acao_gpt/<int:id>', methods=['POST'])
def deletar_macro_acao_gpt_prompt_gpt(id):
    macro_acao = MacroAcaoGeradoChatAprovacao.query.get_or_404(id)
    db.session.delete(macro_acao)
    db.session.commit()
    return redirect(url_for('listar_sugestao_macro_acao_gpt'))


@app.route('/escolher_empresa_macro_acao_feedback', methods=['GET', 'POST'], endpoint='escolher_empresa_macro_acao_feedback')
def escolher_empresa_squad():
    if request.method == 'POST':
        empresa_id = request.form['empresa']
        squad_id = request.form['squad']
        return redirect(url_for('listar_sugestao_macro_acao_feedback_gpt', empresa_id=empresa_id, squad_id=squad_id)) # nome da função atualizado

    empresas = Empresa.query.all()
    return render_template('escolher_empresa_macro_acao_feedback.html', empresas=empresas)


@app.route('/listar_sugestao_macro_acao_feedback_gpt/<int:empresa_id>/<int:squad_id>', methods=['GET'])
def listar_sugestao_macro_acao_feedback_gpt(empresa_id, squad_id):
    sugestoes = db.session.query(MacroAcaoGeradoChatAprovacao).filter_by(empresa_id=empresa_id, squad_id=squad_id).all()

    sugestoes_formatadas = []
    for sugestao in sugestoes:
        sugestoes_formatadas.append({
            'id': sugestao.id,  # Adicionar esta linha
            'empresa_nome_contato': sugestao.empresa.nome_contato,
            'squad_nome': sugestao.squad.nome_squad,
            'objetivo_nome': sugestao.okr.objetivo,
            # Certifique-se de que 'objetivo' é o atributo correto na classe OKR
            'kr_nome': sugestao.kr.texto,  # Atributo atualizado para 'texto'
            'macro_acao': sugestao.macro_acao,
        })

    return render_template('listar_sugestao_macro_acao_feedback_gpt.html', sugestoes=sugestoes_formatadas, empresa_id=empresa_id, squad_id=squad_id)



@app.route('/caminho/para/gerar_macro_acoes_prompt_gpt_feedback', methods=['POST'])
def gerar_macro_acoes_prompt_gpt_feedback():
    data = request.json
    feedback = data['feedback']
    empresa_id = data['empresa_id']
    squad_id = data['squad_id']

    empresa = Empresa.query.filter_by(id=empresa_id).first()
    squad = Squad.query.filter_by(id=squad_id).first()
    forms_objetivos = FormsObjetivos.query.filter_by(squad_id=squad_id).all()
    forms_objetivos_details = ", ".join([json.dumps(form_obj.data) for form_obj in forms_objetivos])

    okrs = OKR.query.filter_by(squad_id=squad_id).all()
    krs = KR.query.filter_by(squad_id=squad_id).all()
    okrs_details = ", ".join([f"{okr.objetivo} (ID: {okr.id})" for okr in okrs])
    krs_details = ", ".join([f"{kr.texto} (Meta: {kr.meta})" for kr in krs])

    forms_details = ", ".join([json.dumps(form_obj.data) for form_obj in forms_objetivos])

    macro_acoes = MacroAcaoGeradoChatAprovacao.query.filter_by(empresa_id=empresa_id, squad_id=squad_id).all()
    macro_acoes_details = ", ".join([f"{macro_acao.macro_acao} (ID: {macro_acao.id})" for macro_acao in macro_acoes])

    #prompt = (f"Com esse feedback '{feedback}', com essa sugestão de macro ações '{macro_acoes_details}', com essas respostas fornecidas "
    #          f"{forms_objetivos_details} pelo squad {squad.nome_squad} da empresa {empresa.nome_contato} e considerando os objetivos e KR's aprovados "
    #          f"{{{okrs_details}, {krs_details}}}, defina macro ações que se alinham com os objetivos e KR's primordiais para o atingimento dos indicadores. "
    #          f"Cada macro ação devem ser expressos em uma única frase. Faça as macro ações para todos os objetivos e KR's. Formate a resposta como um JSON com as seguintes chaves: empresa, squad, objetivo, kr, macro_acao, meta. Não adicione outras chaves além destas.")
    prompt = (
        f"GPT-4, com base no feedback contido no arquivo 'feedback_macro_acoes.txt' sobre as Macro Ações propostas, nas informações da empresa em {forms_details}, nos OKRs definidos em {okrs_details} e os RK de medição {krs_details} e nas Macro Ações iniciais em {macro_acoes_details}, o objetivo é revisar e aprimorar essas Macro Ações conforme o feedback recebido. "
        f"1. Inicie pela análise do feedback no {feedback}, sintetizando as sugestões e críticas do cliente. "
        f"2. Usando este feedback, refine as Macro Ações para os KR do próximo ciclo de 90 dias. "
        f"3. Avalie para consolidar Macro Ações similares ou sequenciais, buscando eficiência e clareza. "
        f"4. Revise a redação de cada Macro Ação para que seja clara e esteja alinhada com a visão da empresa. "
        f"5. Finalize apresentando as Macro Ações revisadas, com justificativas claras para cada revisão realizada. "
        f"O foco é ter Macro Ações claras e alinhadas para atingir eficientemente os KRs definidos. "
        f"Formate a resposta como um JSON com as seguintes chaves: empresa, squad, objetivo, kr, macro_acao. Não adicione outras chaves além destas. Responda todas as chaves com texto, e não com id")

    print("Pergunta completa:", prompt)

    pergunta_id = str(uuid.uuid4())
    messages = []

    resposta, messages = perguntar_gpt(prompt, pergunta_id, messages)
    print("Resposta completa:", resposta)

    resposta_json = json.loads(resposta)

    novas_macro_acoes = []
    for item in resposta_json:
        objetivo_name = item["objetivo"]
        objetivo = OKR.query.filter_by(objetivo=objetivo_name, squad_id=squad_id).first()
        if objetivo is None:
            print(f"No matching Objective found for name '{objetivo_name}' and squad_id '{squad_id}'")
            continue
        objetivo_id = objetivo.id

        kr_name = item["kr"]
        kr = KR.query.filter_by(texto=kr_name, squad_id=squad_id).first()
        if kr is None:
            print(f"No matching KR found for name '{kr_name}' and squad_id '{squad_id}'")
            continue
        kr_id = kr.id

        macro_acao_text = item["macro_acao"]

        macro_acao = MacroAcaoGeradoChatAprovacao(
            empresa_id=empresa_id,
            squad_id=squad_id,
            objetivo_id=objetivo_id,
            kr_id=kr_id,
            macro_acao=macro_acao_text
        )

        novas_macro_acoes.append(macro_acao)

    try:
        # Inicia uma transação
        db.session.begin_nested()

        # Deleta as macro ações antigas
        MacroAcaoGeradoChatAprovacao.query.filter_by(empresa_id=empresa_id, squad_id=squad_id).delete()

        # Adiciona as novas macro ações
        for macro_acao in novas_macro_acoes:
            db.session.add(macro_acao)

        # Tenta confirmar as alterações
        db.session.commit()
    except IntegrityError:
        # Se algo der errado, faz rollback
        db.session.rollback()
        # Você pode adicionar algum código de log aqui para entender o que deu errado
        print("Falha ao atualizar as macro ações.")
        # Retornar uma resposta de erro apropriada ao cliente, se desejado
        return "Erro ao atualizar", 400

    return redirect(url_for('listar_sugestao_macro_acao_gpt'))


@app.route('/aprovar_macro_acao_gpt/<int:id>', methods=['POST'])
def aprovar_macro_acao_gpt(id):
    # Recuperando a sugestão
    sugestao = MacroAcaoGeradoChatAprovacao.query.get_or_404(id)

    # Diagnóstico: Verificando o valor de squad_id
    print("Squad ID:", sugestao.squad_id)

    # Verificando se todos os campos necessários estão presentes
    if not (sugestao.macro_acao and sugestao.kr_id and sugestao.okr and sugestao.squad and sugestao.empresa):
        logging.error(f"Dados inválidos na sugestão de id {id}")
        return jsonify(success=False, message="Dados inválidos na sugestão"), 400

    try:
        # Refresh para garantir que as relações estejam atualizadas
        db.session.refresh(sugestao)

        # Criando a aprovação
        aprovacao = MacroAcao(
            texto=sugestao.macro_acao,
            aprovada=True,
            data_inclusao=datetime.utcnow(),
            kr_id=sugestao.kr_id,
            objetivo=sugestao.okr.objetivo,
            squad_id=sugestao.squad_id,
            objetivo_id=sugestao.objetivo_id,
            empresa=sugestao.empresa.nome_contato if sugestao.empresa else None,
            empresa_id=sugestao.empresa_id
        )

        # Adicionando a aprovação e removendo a sugestão
        db.session.add(aprovacao)
        db.session.delete(sugestao)
        db.session.commit()
    except Exception as e:
        logging.error(f"Erro ao atualizar o banco de dados: {e}")
        return jsonify(success=False, message=str(e)), 500

    return jsonify(success=True), 200


@app.route('/deletar_macro_acao_gerado_chat_aprovacao/<int:id>', methods=['DELETE'])
def deletar_macro_acao_gerado_chat_aprovacao(id):
    macro_acao = MacroAcaoGeradoChatAprovacao.query.get_or_404(id)

    db.session.delete(macro_acao)
    db.session.commit()

    return jsonify(success=True), 200


@app.route('/escolher_empresa_tarefa')
def escolher_empresa_tarefa():
    empresas = Empresa.query.all()
    squads = Squad.query.all() # ou vazio se quiser carregar dinamicamente
    return render_template('escolher_empresa_tarefa.html', empresas=empresas, squads=squads)



def serialize_forms_objetivos(obj):
    return {
        'id': obj.id,
        # Adicione outros atributos conforme necessário
    }

def serialize_okr(obj):
    return {
        'id': obj.id,
        # Adicione outros atributos conforme necessário
    }

def serialize_kr(obj):
    return {
        'id': obj.id,
        # Adicione outros atributos conforme necessário
    }

def serialize_macro_acoes(obj):
    return {
        'id': obj.id,
        # Adicione outros atributos conforme necessário
    }


@app.route('/get_macroacoes/<int:empresa_id>/<int:squad_id>', methods=['GET'])
def get_macroacoes(empresa_id, squad_id):
    empresa = Empresa.query.get_or_404(empresa_id)
    squad = Squad.query.get_or_404(squad_id)
    forms_objetivos = FormsObjetivos.query.filter_by(empresa_id=empresa_id, squad_id=squad_id).all()
    okrs = OKR.query.filter_by(id_empresa=empresa_id, squad_id=squad_id).all()

    resultado_okrs = []
    for okr in okrs:
        krs = KR.query.filter_by(id_okr=okr.id).all()
        resultado_krs = []
        for kr in krs:
            macro_acoes = MacroAcao.query.filter_by(kr_id=kr.id).all()
            resultado_macro_acoes = [ma.texto for ma in macro_acoes]
            resultado_krs.append({
                'texto': kr.texto,
                'meta': kr.meta,
                'macro_acoes': resultado_macro_acoes
            })
        resultado_okrs.append({
            'objetivo': okr.objetivo,
            'krs': resultado_krs
        })

    return jsonify({
        'empresa': {
            'id': empresa.id,
            'nome': empresa.nome_contato  # Adicione outros atributos da empresa conforme necessário
        },
        'squad': {
            'id': squad.id,
            'nome_squad': squad.nome_squad  # Adicione outros atributos do squad conforme necessário
        },
        'forms_objetivos': [obj.data for obj in forms_objetivos],  # adicionado
        'okrs': resultado_okrs
    })



@app.route('/gerar_tarefas_metas_semanais', methods=['POST'])
def gerar_tarefas_metas_semanais():
    empresa_id = request.form['empresa_id']
    squad_id = request.form['squad_id']

    empresa = Empresa.query.filter_by(id=empresa_id).first()
    squad = Squad.query.filter_by(id=squad_id).first()
    forms_objetivos = FormsObjetivos.query.filter_by(squad_id=squad_id).all()

    forms_objetivos_details = ", ".join([json.dumps(form_obj.data) for form_obj in forms_objetivos])
    okrs = OKR.query.filter_by(squad_id=squad_id).all()
    krs = KR.query.filter_by(squad_id=squad_id).all()

    okrs_details = ", ".join([f"{okr.objetivo} (ID: {okr.id})" for okr in okrs])
    krs_details = ", ".join([f"{kr.texto} (Meta: {kr.meta})" for kr in krs])
    macro_acoes_details = ", ".join([ma.texto for ma in MacroAcao.query.filter_by(squad_id=squad_id).all()])

    forms_details = ", ".join([json.dumps(form_obj.data) for form_obj in forms_objetivos])

    prompt = (
        f"Com base nas informações dos colaborares da empresa {forms_details}, pelo squad {squad.nome_squad}, os objetivos para o periodo de 90 dias {okrs_details}, os KR's medidores dos objetivos {krs_details}, as macro ações {macro_acoes_details}."
        f"Considerando o progresso atual de cada KR, sugira tarefas e metas da semana para a próxima semana que auxiliem no atingimento dos indicadores. "
        f"Cada tarefa sugerida e sua meta da semana devem ser direcionadas ao progresso dos KR's e alinhadas com as macro ações e os objetivos. "
        f"Cada tarefa e meta semanal deve ser expressa em uma única frase."
        f"Formate a resposta como um JSON com as seguintes chaves: tarefa, meta_semanal, squad, empresa. Não adicione outras chaves além destas. Responda apenas com o JSON")

    print("Pergunta completa:", prompt)

    pergunta_id = str(uuid.uuid4())
    messages = []

    resposta, messages = perguntar_gpt(prompt, pergunta_id, messages)
    print("Resposta completa:", resposta)

    resposta_corrigida = "[" + resposta.replace("},", "},\n") + "]"
    tarefas_metas_semanais_list = json.loads(resposta_corrigida)

    try:
        # Certifique-se de que a resposta é uma lista de dicionários
        if not isinstance(tarefas_metas_semanais_list, list):
            raise ValueError("A resposta não é uma lista.")

        for tarefa_metas_semanais_data in tarefas_metas_semanais_list:
            # Cheque se o item atual é um dicionário
            if not isinstance(tarefa_metas_semanais_data, dict):
                print(f"Item inesperado na resposta: {tarefa_metas_semanais_data}")
                continue

            tarefa = tarefa_metas_semanais_data.get('tarefa')
            meta_semanal = tarefa_metas_semanais_data.get('meta_semanal')

            # Cheque se as chaves necessárias estão presentes
            if not all([tarefa, meta_semanal]):
                print(f"Dados incompletos ou ausentes no registro: {tarefa_metas_semanais_data}")
                continue

            # Crie o objeto e adicione ao banco de dados
            tarefa_metas_semanais = TarefasMetasSemanais(
                empresa=empresa.nome_contato,
                squad_name=squad.nome_squad,
                squad_id=squad_id,
                tarefa=tarefa,
                meta_semanal=meta_semanal
            )
            db.session.add(tarefa_metas_semanais)

        # Tente fazer o commit
        db.session.commit()
    except Exception as e:
        # Se algo der errado, imprima o erro e faça rollback da sessão
        print(f"Erro ao adicionar os dados ao banco: {e}")
        db.session.rollback()

    return redirect(url_for('listar_tarefas_metas_semanais'))


@app.route('/listar_tarefas_metas_semanais')
def listar_tarefas_metas_semanais():
    tarefas_metas_semanais = TarefasMetasSemanais.query.all()
    return render_template('listar_tarefas_metas_semanais.html', tarefas=tarefas_metas_semanais)

@app.route('/deletar_tarefa_metas_semanais/<int:id>', methods=['POST'])
def deletar_tarefa_metas_semanais(id):
    tarefa_metas_semanais = TarefasMetasSemanais.query.get_or_404(id)
    db.session.delete(tarefa_metas_semanais)
    db.session.commit()
    return redirect(url_for('listar_tarefas_metas_semanais'))


@app.route('/escolher_empresa_tarefas_andamento', methods=['GET', 'POST'])
def escolher_empresa_tarefas_andamento():
    if request.method == 'POST':
        empresa_id = request.form.get('empresa')
        squad_id = request.form.get('squad')
        return redirect(url_for('listar_tarefas_andamento', empresa_id=empresa_id, squad_id=squad_id))

    empresas = Empresa.query.all()
    return render_template('escolher_empresa_tarefas_andamentos.html', empresas=empresas)


@app.route('/listar_tarefas_andamento/<int:empresa_id>/<int:squad_id>')
def listar_tarefas_andamento(empresa_id, squad_id):
    tarefas = TarefasAndamento.query.filter_by(squad_id=squad_id).all()
    return render_template('listar_tarefas_andamento.html', tarefas=tarefas)


@app.route('/escolher_empresa_tarefas_finalizadas/')
def escolher_empresa_tarefas_finalizadas():
    empresas = Empresa.query.all()
    return render_template('escolher_empresa_tarefas_finalizadas.html', empresas=empresas)


@app.route('/escolher_empresa_tarefas_finalizadas/listar/<int:empresa_id>/<int:squad_id>')
def listar_tarefas_finalizadas(empresa_id, squad_id):
    empresa = Empresa.query.get(empresa_id)
    if not empresa:
        # Aqui você pode redirecionar para uma página de erro ou retornar uma mensagem
        return "Empresa não encontrada", 404

    tarefas = TarefasFinalizadas.query.filter_by(empresa=empresa.nome_contato, squad_id=squad_id).all()
    squad_nome = Squad.query.get(squad_id).nome_squad
    return render_template('listar_tarefas_finalizadas.html', tarefas=tarefas, empresa_nome=empresa.nome_contato,
                           squad_nome=squad_nome)



from flask import render_template, request, redirect, url_for


@app.route('/montar_sprint_semana', methods=['GET', 'POST'])
def montar_sprint_semana():
    if request.method == 'POST':
        empresa_id = int(request.form.get('empresa_id'))
        squad_id = int(request.form.get('squad_id'))

        # Carregar os dados relacionados à empresa e squad selecionados
        forms_objetivos = FormsObjetivos.query.filter_by(empresa_id=empresa_id, squad_id=squad_id).all()
        okrs = OKR.query.filter_by(id_empresa=empresa_id, squad_id=squad_id).all()
        krs = KR.query.filter_by(id_empresa=empresa_id, squad_id=squad_id).all()
        macroacoes = MacroAcao.query.filter_by(empresa_id=empresa_id, squad_id=squad_id).all()
        tarefas_andamento = TarefasAndamento.query.filter_by(squad_id=squad_id).all()
        tarefas_finalizadas = TarefasFinalizadas.query.filter_by(squad_id=squad_id).all()

        return render_template('escolher_empresa_squad_sprint_semanal.html',
                               forms_objetivos=forms_objetivos,
                               okrs=okrs,
                               krs=krs,
                               macroacoes=macroacoes,
                               tarefas_andamento=tarefas_andamento,
                               tarefas_finalizadas=tarefas_finalizadas)

    empresas = Empresa.query.all()
    squads = Squad.query.all()
    return render_template('escolher_empresa_squad_sprint_semanal.html', empresas=empresas, squads=squads)


@app.route('/get_squad_id', methods=['GET'])
def get_squad_id():
    try:
        squad_name = request.args.get('squad_name')
        empresa_name = request.args.get('empresa_name')
        print(squad_name, empresa_name)

        # Filtrando por nome_squad e nome da empresa usando join
        squad = db.session.query(Squad).join(Empresa).filter(
            Squad.nome_squad == squad_name,
            Empresa.nome_contato == empresa_name
        ).first()

        if not squad:
            return jsonify(success=False, error="Squad não encontrado")
        return jsonify(success=True, squad_id=squad.id)
    except Exception as e:
        return jsonify(success=False, error=str(e))

@app.route('/get_tarefas_concluidas', methods=['GET'])
def get_tarefas_concluidas():
    try:
        tarefas = TarefasFinalizadas.query.all()
        result = []
        for tarefa in tarefas:
            print(tarefa.subtarefas)
            result.append({
                'id': tarefa.id,  # Inclua o ID da tarefa aqui
                'nome_tarefa': tarefa.tarefa,
                'desc': tarefa.descricao_empresa if hasattr(tarefa, 'descricao_empresa') else '',
                'pos': tarefa.squad_name,
                'start': tarefa.data_inclusao.strftime('%Y-%m-%d') if hasattr(tarefa, 'data_inclusao') else '',
                # Ajuste se necessário
                'close': tarefa.data_conclusao.strftime('%Y-%m-%d') if tarefa.data_conclusao else '',
                'nome_empresa': tarefa.empresa,
                'nome_squad': tarefa.squad_name,
                'plataforma': '',
                'subtarefas': tarefa.subtarefas  # Adicionando o campo subtarefas

            })
        return jsonify(result)
    except Exception as e:
        return jsonify(error=str(e))


@app.route('/get_tarefas_atuais', methods=['GET'])
def get_tarefas_atuais():
    try:
        tarefas = TarefasAndamento.query.all()
        print(tarefas)
        result = []
        for tarefa in tarefas:
            result.append({
                'id': tarefa.id,
                'nome_tarefa': tarefa.tarefa,
                'desc': tarefa.descricao_empresa if hasattr(tarefa, 'descricao_empresa') else '',
                'pos': tarefa.squad_name,
                'start': tarefa.data_inclusao.strftime('%Y-%m-%d'),
                'close': tarefa.data_conclusao.strftime('%Y-%m-%d') if tarefa.data_conclusao else '',
                'nome_empresa': tarefa.empresa,
                'nome_squad': tarefa.squad_name,
                'plataforma': '',  # Adicione o campo de plataforma se necessário
                'subtarefas': tarefa.subtarefas  # Adicionando o campo subtarefas
            })
        return jsonify(result)
    except Exception as e:
        return jsonify(error=str(e))


@app.route('/deletar_tarefa_concluida/<int:id>', methods=['POST'])
def deletar_tarefa_concluida(id):
    tarefa = TarefasFinalizadas.query.get_or_404(id)
    db.session.delete(tarefa)
    db.session.commit()
    return jsonify(success=True)


@app.route('/deletar_tarefa/<int:id>', methods=['POST'])
def deletar_tarefa(id):
    tarefa = TarefasAndamento.query.get_or_404(id)
    db.session.delete(tarefa)
    db.session.commit()
    return jsonify(success=True)


@app.route('/cadastrar_tarefas_atuais', methods=['POST'])
def cadastrar_tarefas_atuais():
    try:
        tarefas_data = request.json['tarefas']
        for tarefa_data in tarefas_data:

            empresa = Empresa.query.filter_by(nome_contato=tarefa_data['empresa']).first()
            if not empresa:
                return jsonify(success=False, error="Empresa não encontrada")

            squad = Squad.query.filter_by(id=tarefa_data['squad_id'], empresa_id=empresa.id).first()
            if not squad:
                return jsonify(success=False, error="Squad não encontrado")

            tarefa = TarefasAndamento(
                empresa=tarefa_data['empresa'],
                squad_name=tarefa_data['squad_name'],
                squad_id=squad.id,
                tarefa=tarefa_data['tarefa'],
                data_inclusao=datetime.utcnow(),
                subtarefas=tarefa_data.get('subtarefas', {})
            )
            db.session.add(tarefa)
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))


@app.route('/cadastrar_tarefas_concluidas', methods=['POST'])
def cadastrar_tarefas_concluidas():
    try:
        tarefas_data = request.json['tarefas']
        for tarefa_data in tarefas_data:

            # Obter a empresa pelo nome_contato (ou o campo correto que representa o nome da empresa)
            empresa = Empresa.query.filter_by(nome_contato=tarefa_data['empresa']).first()
            if not empresa:
                return jsonify(success=False, error="Empresa não encontrada")

            # Obter o squad pelo ID
            squad = Squad.query.filter_by(id=tarefa_data['squad_id'], empresa_id=empresa.id).first()
            if not squad:
                return jsonify(success=False, error="Squad não encontrado")

            # Criar a tarefa
            tarefa = TarefasFinalizadas(
                empresa=tarefa_data['empresa'],
                squad_name=tarefa_data['squad_name'],
                squad_id=squad.id,
                tarefa=tarefa_data['tarefa'],
                data_conclusao=datetime.utcnow(),
                subtarefas=tarefa_data.get('subtarefas', {})
            )
            db.session.add(tarefa)
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))


@app.route('/get_squads_sprint/<int:empresa_id>')
def get_squads_sprint(empresa_id):
    squads = Squad.query.filter_by(empresa_id=empresa_id).all()
    squads_list = [{"id": squad.id, "nome": squad.nome_squad} for squad in squads]
    return jsonify(squads_list)



@app.route('/gerar_tarefas_metas_semanais_novo', methods=['POST'])
def gerar_tarefas_metas_semanais_novo():
    empresa_id = request.json['empresa_id']
    print(empresa_id)
    squad_id = request.json['squad_id']
    print(f"Empresa ID: {empresa_id}, Squad ID: {squad_id}")

    empresa = Empresa.query.filter_by(id=empresa_id).first()
    squad = Squad.query.filter_by(id=squad_id).first()
    forms_objetivos = FormsObjetivos.query.filter_by(squad_id=squad_id).all()
    response_data = []


    forms_objetivos_details = ", ".join([json.dumps(form_obj.data) for form_obj in forms_objetivos])
    okrs = OKR.query.filter_by(squad_id=squad_id).all()
    krs = KR.query.filter_by(squad_id=squad_id).all()
    tarefas_andamento = TarefasAndamento.query.filter_by(squad_id=squad_id).all()
    tarefas_finalizadas = TarefasFinalizadas.query.filter_by(squad_id=squad_id).all()

    okrs_details = ", ".join([f"{okr.objetivo} (ID: {okr.id})" for okr in okrs])
    krs_details = ", ".join([f"{kr.texto} (Meta: {kr.meta})" for kr in krs])
    macro_acoes_details = ", ".join([ma.texto for ma in MacroAcao.query.filter_by(squad_id=squad_id).all()])
    tarefas_andamento_details = ", ".join([
        f"{tarefa.tarefa} (ID: {tarefa.id}, Data Inclusão: {tarefa.data_inclusao}, Data Conclusão: {tarefa.data_conclusao}, Subtarefas: {json.dumps(tarefa.subtarefas) if tarefa.subtarefas else 'Nenhuma'})"
        for tarefa in tarefas_andamento
    ])
    tarefas_finalizadas_details = ", ".join([
        f"{tarefa.tarefa} (ID: {tarefa.id}, Data Inclusão: {tarefa.data_inclusao}, Data Conclusão: {tarefa.data_conclusao}, Subtarefas: {json.dumps(tarefa.subtarefas) if tarefa.subtarefas else 'Nenhuma'})"
        for tarefa in tarefas_finalizadas
    ])
    """
    prompt = (
        f"Informações da empresa {empresa.nome_contato} e squad {squad.nome_squad}:"
        f"FormsObjetivos: {forms_objetivos_details}, OKRs: {okrs_details}, "
        f"KRs: {krs_details}, MacroAções: {macro_acoes_details}, "
        f"Tarefas em Andamento: {tarefas_andamento_details}, Tarefas Finalizadas: {tarefas_finalizadas_details}. "
        f"Com base nessas informações, sugira tarefas para a proxima semana."
        f"Formate a resposta como um JSON com as seguintes chaves: tarefa, meta_semanal, squad, empresa. Não adicione outras chaves além destas. Responda apenas com o JSON"
    )
    """
    prompt = (
        f"Informações da empresa {empresa.nome_contato} e squad {squad.nome_squad}:"
        f"FormsEquipe: {forms_objetivos_details}, OKRs: {okrs_details}, "
        f"KRs: {krs_details}, MacroAções: {macro_acoes_details}, "
        f"Tarefas em Andamento: {tarefas_andamento_details}, Tarefas Finalizadas: {tarefas_finalizadas_details}. "
        f"Considerando o progresso atual de cada KR, faça sugestões de tarefas e metas da semana para a próxima semana que auxiliem no atingimento dos indicadores. "
        f"Cada tarefa sugerida e sua meta da semana devem ser direcionadas ao progresso dos KR's e alinhadas com as macro ações e os objetivos. "
        f"Com base nessas informações, sugira tarefas para a proxima semana."
        f"Formate a resposta como um JSON com as seguintes chaves: tarefa, meta_semanal, squad, empresa. Não adicione outras chaves além destas. Responda apenas com o JSON"
    )


    pergunta_id = str(uuid.uuid4())
    messages = []
    print("Prompt completo:", prompt)

    resposta, messages = perguntar_gpt(prompt, pergunta_id, messages)
    print("Resposta completa:", resposta)

    # Correção na formatação do JSON:
    resposta_corrigida = "[" + resposta.replace("}\n{", "},\n{") + "]"
    tarefas_metas_semanais_list = json.loads(resposta_corrigida)

    try:
        # Remova registros anteriores relacionados à squad e à empresa.
        TarefasMetasSemanais.query.filter_by(squad_id=squad_id, empresa=empresa.nome_contato).delete()
        db.session.commit()

        # Certifique-se de que a resposta é uma lista de dicionários
        if not isinstance(tarefas_metas_semanais_list, list):
            raise ValueError("A resposta não é uma lista.")

        for tarefa_metas_semanais_data in tarefas_metas_semanais_list:
            # Cheque se o item atual é um dicionário
            if not isinstance(tarefa_metas_semanais_data, dict):
                print(f"Item inesperado na resposta: {tarefa_metas_semanais_data}")
                continue

            # Verificação das chaves necessárias
            tarefa = tarefa_metas_semanais_data.get('tarefa')
            meta_semanal = tarefa_metas_semanais_data.get('meta_semanal')
            squad_name = tarefa_metas_semanais_data.get('squad')
            empresa_name = tarefa_metas_semanais_data.get('empresa')

            if not all([tarefa, meta_semanal, squad_name, empresa_name]):
                print(f"Dados incompletos ou ausentes no registro: {tarefa_metas_semanais_data}")
                continue

            # Crie o objeto e adicione ao banco de dados
            tarefa_metas_semanais = TarefasMetasSemanais(
                empresa=empresa_name,
                squad_name=squad_name,
                squad_id=squad_id,
                tarefa=tarefa,
                meta_semanal=meta_semanal
            )
            db.session.add(tarefa_metas_semanais)
            response_data.append({"tarefa": tarefa, "meta_semanal": meta_semanal, "squad": squad_name, "empresa": empresa_name})

        # Tente fazer o commit
        db.session.commit()
    except Exception as e:
        # Se algo der errado, imprima o erro e faça rollback da sessão
        print(f"Erro ao adicionar os dados ao banco: {e}")
        db.session.rollback()

    return jsonify({'status': 'success', 'data': response_data})

@app.route('/verificar_tarefa_existente', methods=['POST'])
def verificar_tarefa_existente():
    tarefa_data = request.json['tarefa']

    empresa = tarefa_data['empresa']
    squad_name = tarefa_data['squad_name']
    tarefa_nome = tarefa_data['tarefa']

    tarefa_existente = TarefasAndamento.query.filter_by(empresa=empresa, squad_name=squad_name, tarefa=tarefa_nome).first()

    return jsonify(existe=bool(tarefa_existente))

@app.route('/verificar_tarefa_concluida_existente', methods=['POST'])
def verificar_tarefa_concluida_existente():
    tarefa_data = request.json['tarefa']

    empresa = tarefa_data['empresa']
    squad_name = tarefa_data['squad_name']
    tarefa_nome = tarefa_data['tarefa']

    tarefa_existente = TarefasFinalizadas.query.filter_by(empresa=empresa, squad_name=squad_name, tarefa=tarefa_nome).first()

    return jsonify(existe=bool(tarefa_existente))
@app.route('/get_squad_name', methods=['GET'])
def get_squad_name():
    empresa_id = request.args.get('empresa_id')
    squad_id = request.args.get('squad_id')

    # Supondo que você tenha um modelo para Empresa e Squad, e um relacionamento entre eles
    squad = Squad.query \
        .join(Squad.empresa) \
        .filter(Empresa.id == empresa_id, Squad.id == squad_id) \
        .first()

    if squad:
        return jsonify(squad_name=squad.nome_squad)
    else:
        return jsonify(error="Erro ao buscar nome do squad"), 404

@app.route('/get_empresa_name', methods=['GET'])
def get_empresa_name():
    empresa_id = request.args.get('id')
    empresa = Empresa.query.get(empresa_id)
    if empresa:
        return jsonify({'nome': empresa.nome_contato})
    else:
        return jsonify({'error': 'Empresa não encontrada'}), 404

@app.route('/get_kr_id', methods=['GET'])
def get_kr_id():
    try:
        kr_name = request.args.get('name')
        kr = KR.query.filter_by(texto=kr_name).first()
        if kr:
            return jsonify(success=True, kr_id=kr.id)
        else:
            return jsonify(success=False, message="KR não encontrado.")
    except Exception as e:
        return jsonify(success=False, message=str(e))
@app.route('/cadastrar_metas', methods=['POST'])
def cadastrar_metas():
    try:
        data = request.json
        kr_id = data.get('id')
        descricao = data.get('descricao')

        # Certifique-se de que kr_id não seja nulo
        if not kr_id:
            return jsonify(success=False, message="ID do KR não fornecido.")

        # Buscar o KR pelo ID usando Session.get()
        kr = db.session.get(KR, kr_id)

        # Se o KR existir e a descrição recebida for diferente da atual, atualizar o campo meta
        if kr and descricao and kr.meta != descricao:
            kr.meta = descricao
            db.session.commit()
            return jsonify(success=True, message="Meta atualizada com sucesso!")
        else:
            return jsonify(success=False, message="KR não encontrado ou descrição já é a mesma.")
    except Exception as e:
        return jsonify(success=False, message=str(e))

@app.route('/get_empresaId', methods=['GET'])
def get_empresaId():
    try:
        empresa_name = request.args.get('empresa_name')

        empresa = Empresa.query.filter_by(nome_contato=empresa_name).first()

        if not empresa:
            return jsonify(success=False, error="Empresa não encontrada")
        return jsonify(success=True, empresa_id=empresa.id)
    except Exception as e:
        return jsonify(success=False, error=str(e))




@app.route('/escolher_empresa_instagram', methods=['GET'])
def escolher_empresa_instagram():
    empresas = Empresa.query.all()
    return render_template('escolher_empresa_instagram.html', empresas=empresas)

@app.route('/listar/posts', methods=['GET'])
def listar_posts():
    empresas = Empresa.query.filter(Empresa.vincular_instagram.isnot(None)).all()
    posts = PostsInstagram.query.filter(PostsInstagram.timestamp.isnot(None)).all()
    return render_template('listar_posts.html', posts=posts, empresas=empresas)


@app.route('/listar_reunioes')
def listar_reunioes():
    reunioes = Reuniao.query.all()
    return render_template('listar_reunioes.html', reunioes=reunioes)


@app.route('/cadastrar_reuniao', methods=['GET', 'POST'])
def cadastrar_reuniao():
    if request.method == 'POST':
        empresa_id = request.form['empresa']
        squad_id = request.form['squad']
        transcricao = request.form['transcricao']
        thread = request.form['thread']
        data_realizacao = request.form['data_realizacao']

        nova_reuniao = Reuniao(empresa_id=empresa_id, squad_id=squad_id, transcricao=transcricao, thread=thread,
                               data_realizacao=data_realizacao)
        db.session.add(nova_reuniao)
        db.session.commit()
        return redirect(url_for('listar_reunioes'))

    empresas = Empresa.query.all()
    return render_template('cadastrar_reuniao.html', empresas=empresas)


@app.route('/atualizar_reuniao/<int:id>', methods=['GET', 'POST'])
def atualizar_reuniao(id):
    reuniao = Reuniao.query.get(id)
    if request.method == 'POST':
        reuniao.transcricao = request.form['transcricao']
        reuniao.thread = request.form['thread']
        reuniao.data_realizacao = request.form['data_realizacao']
        db.session.commit()
        return redirect(url_for('listar_reunioes'))
    return render_template('atualizar_reuniao.html', reuniao=reuniao)


@app.route('/deletar_reuniao/<int:id>', methods=['POST'])
def deletar_reuniao(id):
    reuniao = Reuniao.query.get(id)
    db.session.delete(reuniao)
    db.session.commit()
    return redirect(url_for('listar_reunioes'))



if __name__ == '__main__':
    app.run()



