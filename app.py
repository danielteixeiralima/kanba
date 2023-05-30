from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from models import db, Empresa, Resposta, Usuario, OKR, KR, MacroAcao, Sprint, TarefaSemanal, LoginForm
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required  # importações do Flask-Login
import requests
import json
import time
from flask_migrate import Migrate
from flask import jsonify
from datetime import datetime


app = Flask(__name__)
app.secret_key = 'Omega801'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\USER\\PycharmProjects\\bizarte\\test.db'
migrate = Migrate(app, db)
db.init_app(app)

login_manager = LoginManager()  # Cria uma instância do gerenciador de login
login_manager.init_app(app)  # Inicializa o gerenciador de login com o app
login_manager.login_view = "login"  # Define a rota de login

# Função de callback para recarregar o usuário do ID de sessão armazenado
@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

def json_loads(value):
    return json.loads(value)

app.jinja_env.globals.update(json=json)

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required

# Inicializando o gerenciador de login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Nome da rota de login

# Atualizando a classe User para incluir UserMixin, que inclui métodos padrão usados pelo Flask-Login
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.password == form.password.data:
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return 'Invalid username or password'
    return render_template('login.html', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/dashboard")
@login_required
def dashboard():
    return "Welcome to the dashboard!"

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/empresas', methods=['GET'])
def listar_empresas():
    empresas = Empresa.query.all()
    return render_template('listar_empresas.html', empresas=empresas)

@app.route('/cadastrar/empresa', methods=['GET', 'POST'])
def cadastrar_empresa():
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
def atualizar_empresa(id):
    empresa = Empresa.query.get(id)
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
def deletar_empresa(id):
    empresa = Empresa.query.get_or_404(id)
    db.session.delete(empresa)
    db.session.commit()
    return redirect(url_for('listar_empresas'))

@app.route('/cadastrar/usuario', methods=['GET', 'POST'])
def cadastrar_usuario():
    if request.method == 'POST':
        usuario = Usuario(
            nome=request.form.get('nome'),
            sobrenome=request.form.get('sobrenome'),
            email=request.form.get('email'),
            celular=request.form.get('celular'),
            id_empresa=request.form.get('id_empresa'),
            cargo=request.form.get('cargo'),
            status=request.form.get('status')
        )
        db.session.add(usuario)
        db.session.commit()
        return redirect(url_for('listar_usuarios'))
    empresas = Empresa.query.all()
    return render_template('cadastrar_usuario.html', empresas=empresas)


@app.route('/usuarios', methods=['GET'])
def listar_usuarios():
    usuarios = Usuario.query.all()
    return render_template('listar_usuarios.html', usuarios=usuarios)

@app.route('/atualizar/usuario/<int:id>', methods=['GET', 'POST'])
def atualizar_usuario(id):
    usuario = Usuario.query.get(id)
    if request.method == 'POST':
        usuario.nome = request.form['nome']
        usuario.sobrenome = request.form['sobrenome']
        usuario.email = request.form['email']
        usuario.celular = request.form['celular']
        usuario.id_empresa = request.form['id_empresa']  # Alterado aqui
        usuario.cargo = request.form['cargo']
        usuario.status = request.form['status']
        db.session.commit()
        return redirect(url_for('listar_usuarios'))
    empresas = Empresa.query.all()
    return render_template('atualizar_usuario.html', usuario=usuario, empresas=empresas)



@app.route('/deletar_usuario/<int:id>', methods=['POST'])
def deletar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    db.session.delete(usuario)
    db.session.commit()
    return redirect(url_for('listar_usuarios'))





@app.route('/planejamento_redes', methods=['GET', 'POST'])
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
        "Authorization": "Bearer API_KEY_GPT_4"
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
def cadastrar_okr():
    if request.method == 'POST':
        try:
            okr = OKR(
                id_empresa=request.form.get('empresa'),
                objetivo=request.form.get('objetivo'),
                data_inicio=convert_string_to_datetime(request.form.get('data_inicio')),
                data_fim=convert_string_to_datetime(request.form.get('data_fim')),
            )
            db.session.add(okr)
            db.session.commit()
            return redirect(url_for('listar_okrs'))  # Redireciona para a página de listagem de OKRs
        except ValueError:
            flash('A data fornecida é inválida. Use o formato YYYY-MM-DD.', 'error')
    empresas = Empresa.query.all()
    return render_template('cadastrar_okr.html', empresas=empresas)


@app.route('/listar/okrs', methods=['GET'])
def listar_okrs():
    okrs = OKR.query.all()  # Substitua OKR pela classe do seu modelo de OKR
    return render_template('listar_okrs.html', okrs=okrs)


@app.route('/atualizar/okr/<int:id>', methods=['GET', 'POST'])
def atualizar_okr(id):
    okr = OKR.query.get(id)
    empresas = Empresa.query.all()
    if request.method == 'POST':
        okr.id_empresa = request.form['empresa']
        okr.objetivo = request.form['objetivo']
        okr.data_inicio = datetime.strptime(request.form['data_inicio'], "%Y-%m-%d")
        okr.data_fim = datetime.strptime(request.form['data_fim'], "%Y-%m-%d")
        db.session.commit()
        return redirect(url_for('listar_okrs'))
    return render_template('atualizar_okr.html', okr=okr, empresas=empresas)




@app.route('/deletar/okr/<int:id>', methods=['POST'])
def deletar_okr(id):
    okr = OKR.query.get(id)
    for kr in okr.krs:
        db.session.delete(kr)
    db.session.delete(okr)
    db.session.commit()
    return redirect(url_for('listar_okrs'))



@app.route('/listar/krs', methods=['GET'])
def listar_krs():
    krs = KR.query.all()
    return render_template('listar_krs.html', krs=krs)



@app.route('/cadastrar/kr', methods=['GET', 'POST'])
def cadastrar_kr():
    if request.method == 'POST':
        id_empresa = int(request.form.get('empresa', '0'))  # Obtenha o valor do campo 'empresa' como uma string e converta-o para um inteiro
        id_okr = int(request.form.get('objetivo', '0'))  # Obtenha o valor do campo 'objetivo' como uma string e converta-o para um inteiro
        texto = request.form['texto']

        # Obtenha a instância OKR e atribua-a ao KR.
        okr = OKR.query.get(id_okr)
        if okr is None:
            return "OKR não encontrado", 404

        kr = KR(id_empresa=id_empresa, id_okr=id_okr, texto=texto, data_inclusao=datetime.utcnow())
        db.session.add(kr)
        db.session.commit()
        return redirect(url_for('listar_krs'))

    empresas = Empresa.query.all()
    return render_template('cadastrar_kr.html', empresas=empresas)




@app.route('/atualizar/kr/<int:id>', methods=['GET', 'POST'])
def atualizar_kr(id):
    kr = KR.query.get(id)
    if request.method == 'POST':
        id_empresa = request.form['empresa']
        id_okr = request.form['okr']
        texto = request.form['texto']

        # Obtenha a instância OKR e atribua-a ao KR.
        okr = OKR.query.get(id_okr)
        kr.okr = okr
        kr.id_empresa = id_empresa  # Atualize o id da empresa
        kr.texto = texto
        db.session.commit()
        return redirect(url_for('listar_krs'))

    empresas = Empresa.query.all()
    okrs = OKR.query.filter_by(id_empresa=kr.id_empresa).all()

    return render_template('atualizar_kr.html', empresas=empresas, kr=kr, okrs=okrs)




@app.route('/update_kr/<int:krId>', methods=['POST'])
def update_kr(krId):
    okrId = request.form['objetivo']  # assumindo que isso retorna um id de OKR
    kr = KR.query.get(krId)

    # Obtenha a instância OKR e atribua-a ao KR.
    okr = OKR.query.get(okrId)
    if okr is None:
        return "OKR não encontrado", 404
    kr.okr = okr

    db.session.commit()
    return 'OK', 200



@app.route('/get_okrs/<int:empresa_id>', methods=['GET'])
def get_okrs(empresa_id):
    empresa = Empresa.query.get(empresa_id)
    if not empresa:
        abort(404)  # Retorna um erro 404 se a empresa não for encontrada
    okrs = OKR.query.filter_by(id_empresa=empresa.id).all()

    # Converte a lista de OKRs em uma lista de dicionários para poder ser serializada em JSON
    okrs_dict = []
    for okr in okrs:
        okrs_dict.append({'id': okr.id, 'objetivo': okr.objetivo})

    return jsonify(okrs_dict)




@app.route('/deletar/kr/<int:id>', methods=['POST'])
def deletar_kr(id):
    kr = KR.query.get(id)
    db.session.delete(kr)
    db.session.commit()
    return redirect(url_for('listar_krs'))

@app.route('/get_objectives/<int:empresa_id>', methods=['GET'])
def get_objectives(empresa_id):
    okrs = OKR.query.filter_by(id_empresa=empresa_id).all()
    objectives = [{'id': okr.id, 'objetivo': okr.objetivo} for okr in okrs]
    return jsonify(objectives)



@app.route('/listar_macro_acao')
def listar_macro_acao():
    krs = KR.query.all()  # Busca todos os KR do banco de dados
    return render_template('listar_macro_acao.html', krs=krs)


@app.route('/gerar_macro_acao/<int:id>', methods=['GET', 'POST'])
def gerar_macro_acao(id):
    time_now = datetime.utcnow()  # Salve o horário atual
    kr = KR.query.get(id)  # Busca o KR específico pelo id
    if kr is None:
        return redirect(url_for('listar_macro_acao'))  # Se o KR não existir, redireciona para a lista

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

            # Cria uma nova entrada em MacroAcao para cada ação na resposta
            macro_acao = MacroAcao(
                texto=acao['acao'],
                aprovada=False,  # Inicialmente, a ação não é aprovada
                kr_id=id,
                objetivo=kr.okr.objetivo,
                objetivo_id=kr.okr.id,  # Alteramos de kr.okr_id para kr.okr.id
                empresa=kr.okr.empresa.nome_contato,
                empresa_id=kr.okr.empresa.id  # Alteramos de kr.okr.empresa_id para kr.okr.empresa.id
            )

            # Salva a nova entrada no banco de dados
            db.session.add(macro_acao)
        db.session.commit()

        # Armazena a resposta, as macro ações e o id do KR na sessão
        session['resposta'] = resposta
        session['macro_acoes'] = macro_acoes
        session['kr_id'] = id

        print(resposta)
        print(type(resposta_dict))
        print(resposta_dict)

        # Redireciona para a página de resultados
        return redirect(url_for('mostrar_resultados', kr_id=id))  # Adicionamos o parâmetro kr_id

    return render_template('gerar_macro_acao.html', kr=kr)





@app.route('/mostrar_resultados/<int:kr_id>')
def mostrar_resultados(kr_id):
    kr = KR.query.get(kr_id)  # Busca o KR novamente do banco de dados

    # Busca as macro ações no banco de dados e as ordena por data_inclusao (descendente)
    macro_acoes = MacroAcao.query.filter_by(kr_id=kr_id, aprovada=False)\
                      .order_by(MacroAcao.data_inclusao.desc())\
                      .all()  # Remova `.all()` e adicione `.first()` para obter apenas a mais recente ou `.limit(n)` para as `n` mais recentes

    return render_template('mostrar_resultados.html', macro_acoes=macro_acoes, kr=kr)





@app.route('/atualizar_macro_acao/<int:id>', methods=['GET', 'POST'])
def atualizar_macro_acao(id):
    macro_acao = MacroAcao.query.get(id)
    if request.method == 'POST':
        macro_acao.texto = request.form['texto']
        macro_acao.aprovada = True if request.form['aprovada'] == 'sim' else False
        db.session.commit()
        return redirect(url_for('listar_macro_acoes_aprovadas'))
    return render_template('atualizar_macro_acao.html', acao=macro_acao)


@app.route('/deletar_macro_acao/<int:id>', methods=['GET'])
def deletar_macro_acao(id):
    macro_acao = MacroAcao.query.get(id)
    db.session.delete(macro_acao)
    db.session.commit()
    return redirect(url_for('listar_macro_acoes_aprovadas'))


@app.route('/listar_macro_acoes_aprovadas', methods=['GET'])
def listar_macro_acoes_aprovadas():
    macro_acoes = MacroAcao.query.all()
    return render_template('listar_macro_acoes_aprovadas.html', macro_acoes=macro_acoes)


@app.route('/montagem_sprint_semana')
def montagem_sprint_semana():
    empresas = Empresa.query.all()
    return render_template('montagem_sprint_semana.html', empresas=empresas)

@app.route('/get_objetivos/<int:empresa_id>')
def get_objetivos(empresa_id):
    objetivos = OKR.query.filter_by(id_empresa=empresa_id).all()
    return jsonify([{'id': objetivo.id, 'objetivo': objetivo.objetivo} for objetivo in objetivos])


@app.route('/get_krs/<int:objetivo_id>')
def get_krs(objetivo_id):
    krs = KR.query.filter_by(id_okr=objetivo_id).all()
    return jsonify([{'id': kr.id, 'texto': kr.texto} for kr in krs])




@app.route('/get_empresa_info/<int:empresa_id>', methods=['GET'])
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
def get_descricao_sprint(empresa_id):
    empresa = Empresa.query.get(empresa_id)
    return jsonify(descricao=empresa.descricao_empresa)

@app.route('/get_cargos_sprint/<int:empresa_id>')
def get_cargos_sprint(empresa_id):
    usuarios = Usuario.query.filter_by(id_empresa=empresa_id)
    return jsonify([usuario.cargo for usuario in usuarios])

@app.route('/get_okrs_sprint/<int:empresa_id>')
def get_okrs_sprint(empresa_id):
    okrs = OKR.query.filter_by(id_empresa=empresa_id)
    return jsonify([okr.objetivo for okr in okrs])

@app.route('/get_krs_sprint/<int:empresa_id>')
def get_krs_sprint(empresa_id):
    krs = KR.query.filter_by(id_empresa=empresa_id)
    return jsonify([kr.texto for kr in krs])

@app.route('/get_macro_acoes_sprint/<int:empresa_id>')
def get_macro_acoes_sprint(empresa_id):
    macro_acoes = MacroAcao.query.filter_by(id_empresa=empresa_id)
    return jsonify([macro_acao.texto for macro_acao in macro_acoes])


@app.route('/criar_sprint_semana', methods=['GET', 'POST'])
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

        # Adiciona um ID a cada sprint e salva no banco de dados
        for sprint in sprints:
            if isinstance(sprint, dict):  # Verifica se o sprint é um dicionário
                nome_usuario_responsavel = sprint.get('responsável', '')
                usuario_responsavel = Usuario.query.filter_by(nome=nome_usuario_responsavel).first()
                sprint_db = Sprint(
                    empresa_id=empresa_id,
                    nome_empresa=empresa.nome_contato,
                    prioridade=sprint.get('prioridade', ''),  # Usa o método get para evitar KeyError
                    tarefa=sprint.get('tarefa', ''),  # Usa o método get para evitar KeyError
                    usuario=usuario_responsavel  # Usa o método get para evitar KeyError
                )
                db.session.add(sprint_db)
            else:
                print(f"Erro: esperava um dicionário, mas recebeu {type(sprint)}")
        db.session.commit()

        # Armazena a resposta, os sprints e o id da empresa na sessão
        session['resposta'] = resposta
        session['sprints'] = sprints
        session['empresa_id'] = empresa_id

        # Redireciona para a página de resultados
        return redirect(url_for('resultado_sprint'))

    # Renderiza o template de criação de sprint
    return render_template('montagem_sprint_semana.html')







@app.route('/resultado_sprint')
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
def listar_sprints_semana():
    sprints = Sprint.query.all()
    return render_template('listar_sprints_semana.html', sprints=sprints)


@app.route('/atualizar_sprint/<int:id>', methods=['GET', 'POST'])
def atualizar_sprint(id):
    sprint = Sprint.query.get(id)
    if request.method == 'POST':
        tarefa = request.form.get('tarefa')
        sprint.tarefa = tarefa
        db.session.commit()
        return redirect(url_for('listar_sprints_semana'))
    return render_template('atualizar_sprint.html', sprint=sprint)

@app.route('/deletar_sprint/<int:id>', methods=['GET', 'POST'])
def deletar_sprint(id):
    sprint = Sprint.query.get(id)
    db.session.delete(sprint)
    db.session.commit()
    return redirect(url_for('listar_sprints_semana'))

@app.route('/montagem_lista_usuario_sprint', methods=['GET', 'POST'])
def montagem_lista_usuario_sprint():
    if request.method == 'POST':
        empresa_id = request.form.get('empresa')
        usuarios = Usuario.query.filter_by(id_empresa=empresa_id).all()
        return render_template('lista_usuario_sprint.html', usuarios=usuarios)
    empresas = Empresa.query.all()
    return render_template('montagem_lista_usuario_sprint.html', empresas=empresas)

@app.route('/lista_usuario_sprint', methods=['GET', 'POST'])
def lista_usuario_sprint():
    if request.method == 'POST':
        empresa_id = request.form.get('empresa')
        usuarios = Usuario.query.filter_by(empresa_id=empresa_id).all()
        return render_template('lista_usuario_sprint.html', usuarios=usuarios)
    empresas = Empresa.query.all()
    return render_template('selecionar_empresa.html', empresas=empresas)

@app.route('/montar_tarefas_semana/<int:usuario_id>', methods=['GET', 'POST'])
def montar_tarefas_semana(usuario_id):
    usuario = Usuario.query.get(usuario_id)
    empresa = Empresa.query.get(usuario.id_empresa)
    okrs = OKR.query.filter_by(id_empresa=usuario.id_empresa).all()
    krs = KR.query.filter_by(id_empresa=usuario.id_empresa).all()  # Adicionado aqui
    macro_acoes = MacroAcao.query.filter_by(empresa_id=usuario.id_empresa).all()
    sprints = Sprint.query.filter_by(usuario_id=usuario.id).all()

    if request.method == 'POST':
        # Aqui você pode iniciar o processo que mencionou
        pass

    return render_template('montar_tarefas_semana.html', empresa=empresa, usuario=usuario, okrs=okrs, macro_acoes=macro_acoes, sprints=sprints)


@app.route('/iniciar_processo/<usuario_id>', methods=['POST'])
def iniciar_processo(usuario_id):
    usuario = Usuario.query.get(usuario_id)
    if usuario is None:
        return redirect(url_for('montagem_sprint_semana'))  # Se o usuário não existir, redirecionar

    empresa = Empresa.query.get(usuario.id_empresa)
    if empresa is None:
        return redirect(url_for('montagem_sprint_semana'))  # Se a empresa não existir, redirecionar

    okrs = OKR.query.filter_by(id_empresa=empresa.id).all()
    krs = KR.query.all()  # Adicionado aqui
    macro_acoes = MacroAcao.query.filter_by(empresa_id=empresa.id).all()
    sprints = Sprint.query.filter_by(usuario_id=usuario.id).all()

    # Formatar as listas como strings
    okrs_str = ', '.join([f'{okr.objetivo}: {" - ".join([kr.texto for kr in krs if kr.id_okr == okr.id])}' for okr in okrs])  # Modificado aqui
    macro_acoes_str = ', '.join([acao.texto for acao in macro_acoes])
    sprints_str = ', '.join([f'{sprint.tarefa} - Criado em: {sprint.data_criacao}' for sprint in sprints])

    # Construir a pergunta para o GPT-4
    pergunta = f"Inteligência Artificial GPT, considerando a lista de macro ações estratégicas geradas a partir dos OKRs {okrs_str}, Resumo sobre a empresa: {empresa.descricao_empresa} e a Lista de macro ações: {macro_acoes_str}, o sprint da semana para o colaborador {usuario.nome} {usuario.cargo} é {sprints_str}. Peço que você desenvolva um plano de sprint específico para esse usuario OBSERVANDO O RELACIONAMENTO DE IMPACTO DE MACRO AÇÕES QUE POSSA INFLUENCIAR A PRIORIZAÇÃO DE AÇÕES OU DE PROGRAMAÇÃO DA AGENDA DO COLABORADOR {usuario.nome} para a próxima semana. Defina quais as tarefas devem ser realizadas durante a proxima semana para esse usuário. Provide them in JSON format with the following keys: tarefa_semana, usuario, data_para_conclusão, passo1, data1, passo2, data2, passo3, data3, passo4, data4, passo5, data5, passo6, data6."

    # Substituir perguntar_gpt pela função real
    # Resposta da GPT-4
    resposta, messages = perguntar_gpt(pergunta, empresa.id, [])
    print("Resposta do GPT-4:", resposta)

    # Encontra o início e o final do objeto JSON na resposta
    inicio_json = resposta.find('{')
    final_json = resposta.rfind('}')

    # Se não encontramos um objeto JSON, lançamos um erro
    if inicio_json == -1 or final_json == -1:
        print(f"Erro ao decodificar JSON: não foi possível encontrar um objeto JSON na resposta")
        print(f"Resposta: {resposta}")
        return redirect(url_for('montagem_sprint_semana'))  # Se a decodificação falhar, redirecionar

    json_str = resposta[inicio_json:final_json + 1]

    #Carrega a resposta JSON
    try:
        sprint = json.loads(json_str)
    except json.JSONDecodeError as e:
        print(f"Erro ao decodificar JSON: {str(e)}")
        print(f"Resposta:{resposta}")
        return redirect(url_for('montagem_sprint_semana'))  # Se a decodificação falhar, redirecionar

    # Adiciona um ID a cada sprint e salva no banco de dados
    if isinstance(sprint, dict):  # Verifica se o sprint é um dicionário
        tarefa_semana = sprint.get('tarefa_semana', '')  # Usa o método get para evitar KeyError
        data_para_conclusao_str = sprint.get('data_para_conclusão', '')  # Usa o método get para evitar KeyError

        # Convert a string de data para datetime
        if data_para_conclusao_str:
            data_para_conclusao = datetime.strptime(data_para_conclusao_str, '%Y-%m-%d')
        else:
            data_para_conclusao = None

        # Adiciona os passos e datas
        passos = []
        datas = []
        for i in range(1, 7):
            passo = sprint.get(f'passo{i}', '')
            data = sprint.get(f'data{i}', '')
            if passo and data:
                passos.append(passo)
                datas.append(datetime.strptime(data, '%Y-%m-%d').strftime('%Y-%m-%d'))  # Convert datetime object to string
            else:
                passos.append(None)
                datas.append(None)

        # Cria um dicionário para armazenar os passos e datas
        to_do = {"passos": passos, "datas": datas}

        if tarefa_semana and data_para_conclusao:  # Somente crie a TarefaSemanal se os campos forem não nulos
            tarefa_semanal_db = TarefaSemanal(
                empresa_id=empresa.id,  # Adicionado aqui
                usuario_id=usuario_id,
                tarefa_semana=tarefa_semana,
                data_para_conclusao=data_para_conclusao,
                to_do=json.dumps(to_do)  # Armazena os passos e datas como uma string JSON
            )
            db.session.add(tarefa_semanal_db)
    else:
        print(f"Erro: esperava um dicionário, mas recebeu {type(sprint)}")
    db.session.commit()

    # Armazena a resposta e os sprints na sessão
    session['resposta'] = resposta
    session['sprints'] = sprint

    # Redireciona para a página de resultados
    return redirect(url_for('resultado_sprint'))






@app.route('/listar_tarefas_semanais_usuario', methods=['GET'])
def listar_tarefas_semanais_usuario():
    tarefas_semanais = TarefaSemanal.query.all()
    tarefas_decodificadas = []
    for tarefa in tarefas_semanais:
        tarefa_dict = tarefa.__dict__
        tarefa_dict['to_do_decoded'] = tarefa.to_do_decoded
        tarefa_dict['usuario'] = tarefa.usuario.nome  # Adicione essa linha
        tarefas_decodificadas.append(tarefa_dict)
    return render_template('listar_tarefas_semanais_usuario.html', tarefas_semanais=tarefas_decodificadas)


@app.route('/atualizar_tarefa_semanal/<int:id>', methods=['GET', 'POST'])
def atualizar_tarefa_semanal(id):
    tarefa = TarefaSemanal.query.get_or_404(id)

    if request.method == 'POST':
        tarefa.tarefa_semana = request.form['tarefa_semana']
        tarefa.data_para_conclusao = datetime.strptime(request.form['data_para_conclusao'], '%Y-%m-%d')
        tarefa.to_do = json.dumps({
            'passos': [request.form[f'passo{i}'] for i in range(1, 7)],
            'datas': [request.form[f'data{i}'] for i in range(1, 7)]
        })
        tarefa.data_atualizacao = datetime.utcnow()
        db.session.commit()
        return redirect(url_for('listar_tarefas_semanais_usuario'))

    return render_template('atualizar_tarefa_semanal.html', tarefa=tarefa)


@app.route('/deletar_tarefa_semanal/<int:id>', methods=['POST'])
def deletar_tarefa_semanal(id):
    tarefa = TarefaSemanal.query.get_or_404(id)
    db.session.delete(tarefa)
    db.session.commit()
    return redirect(url_for('listar_tarefas_semanais_usuario'))




if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)


