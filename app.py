from flask import Flask, render_template, request, redirect, url_for, session, flash
from models import db, Empresa, Resposta, Usuario, OKR, KR
import requests
import json
import time
from flask_migrate import Migrate
from flask import jsonify



app = Flask(__name__)
app.secret_key = 'Omega801'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\USER\\PycharmProjects\\bizarte\\test.db'
migrate = Migrate(app, db)


db.init_app(app)

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
            "Monte uma persona para esse negocio com a dores, objetivos e interesses?",
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
        "Authorization": "Bearer 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"
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
            if e.response.status_code in (429, 520):  # Limite de requisições atingido ou erro de servidor
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


@app.route('/cadastrar/okr', methods=['GET', 'POST'])
def cadastrar_okr():
    if request.method == 'POST':
        okr = OKR(
            id_empresa=request.form.get('empresa'),
            objetivo_1=request.form.get('objetivo_1'),
            objetivo_2=request.form.get('objetivo_2'),
            objetivo_3=request.form.get('objetivo_3'),
            objetivo_4=request.form.get('objetivo_4'),
            objetivo_5=request.form.get('objetivo_5'),
        )
        db.session.add(okr)
        db.session.commit()
        return redirect(url_for('listar_okrs'))  # Redireciona para a página de listagem de OKRs
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
        okr.objetivo_1 = request.form['objetivo_1']
        okr.objetivo_2 = request.form['objetivo_2']
        okr.objetivo_3 = request.form['objetivo_3']
        okr.objetivo_4 = request.form['objetivo_4']
        okr.objetivo_5 = request.form['objetivo_5']
        db.session.commit()
        return redirect(url_for('listar_okrs'))
    return render_template('atualizar_okr.html', okr=okr, empresas=empresas)

@app.route('/deletar/okr/<int:id>', methods=['POST'])
def deletar_okr(id):
    okr = OKR.query.get(id)
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
        id_empresa = request.form['empresa']
        id_objetivo = request.form['objetivo']  # Altere 'okr' para 'objetivo'
        texto = request.form['texto']
        kr = KR(id_empresa=id_empresa, id_objetivo=id_objetivo, texto=texto)
        db.session.add(kr)
        db.session.commit()
        return redirect(url_for('listar_krs'))
    empresas = Empresa.query.all()
    return render_template('cadastrar_kr.html', empresas=empresas)



@app.route('/atualizar/kr/<int:id>', methods=['GET', 'POST'])
def atualizar_kr(id):
    kr = KR.query.get(id)
    if request.method == 'POST':
        kr.id_okr = request.form['okr']
        kr.texto = request.form['texto']
        db.session.commit()
        return redirect(url_for('listar_krs'))
        pass
    else:
        empresas = Empresa.query.all()
        return render_template('cadastrar_kr.html', empresas=empresas)
@app.route('/deletar/kr/<int:id>', methods=['POST'])
def deletar_kr(id):
    kr = KR.query.get(id)
    db.session.delete(kr)
    db.session.commit()
    return redirect(url_for('listar_krs'))

@app.route('/get_objectives/<int:empresa_id>', methods=['GET'])
def get_objectives(empresa_id):
    okrs = OKR.query.filter_by(id_empresa=empresa_id).all()
    objectives = []
    for okr in okrs:
        for i in range(1, 6):
            objetivo = getattr(okr, f'objetivo_{i}')
            if objetivo:
                objectives.append({'id': okr.id, 'objetivo': objetivo})
    return jsonify(objectives)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)


