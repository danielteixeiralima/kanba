from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask import json
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from base64 import b64decode
from base64 import b64decode, b64encode

db = SQLAlchemy()

class Empresa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome_contato = db.Column(db.String(80))
    email_contato = db.Column(db.String(120))
    telefone_contato = db.Column(db.String(20))
    endereco_empresa = db.Column(db.String(200))
    setor_atuacao = db.Column(db.String(200))
    tamanho_empresa = db.Column(db.String(200))
    descricao_empresa = db.Column(db.Text)
    objetivos_principais = db.Column(db.Text)
    historico_interacoes = db.Column(db.Text)
    vincular_instagram = db.Column(db.String(200))
    vincular_anuncio = db.Column(db.String(200))




class Resposta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_empresa = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    pergunta = db.Column(db.Text, nullable=False)
    resposta = db.Column(db.Text)
    classificacao = db.Column(db.String(200))
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    data_atualizacao = db.Column(db.DateTime, onupdate=datetime.utcnow)


class Usuario(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), nullable=False)
    sobrenome = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    celular = db.Column(db.String(20), nullable=False)
    id_empresa = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    empresa = db.relationship('Empresa', backref='usuarios')
    data_entrada = db.Column(db.DateTime, default=datetime.utcnow)
    cargo = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    sprint = db.Column(db.String(200))  # Novo campo
    dayling_1 = db.Column(db.String(200))  # Novo campo
    dayling_2 = db.Column(db.String(200))  # Novo campo
    dayling_3 = db.Column(db.String(200))  # Novo campo
    dayling_4 = db.Column(db.String(200))  # Novo campo
    dayling_5 = db.Column(db.String(200))  # Novo campo
    sprint = db.Column(db.String(200))
    dayling_1 = db.Column(db.String(200))
    dayling_2 = db.Column(db.String(200))
    dayling_3 = db.Column(db.String(200))
    dayling_4 = db.Column(db.String(200))
    dayling_5 = db.Column(db.String(200))
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    def to_dict(self):
        return {
            'id': self.id,
            'nome': self.nome,
            'sobrenome': self.sobrenome,
            'email': self.email,
        }
    @property
    def password(self):
        raise AttributeError('password: campo de leitura apenas')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)



class Squad(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    empresa_id = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    nome_squad = db.Column(db.String(100), nullable=False)
    data_inicio = db.Column(db.DateTime, nullable=False)
    data_fim = db.Column(db.DateTime)

    empresa = db.relationship('Empresa', backref='squads')
    usuarios = db.relationship('Usuario', secondary='squad_usuarios', backref=db.backref('squads', lazy='dynamic'))

# Tabela associativa para relação muitos-para-muitos entre Squad e Usuario
squad_usuarios = db.Table('squad_usuarios',
    db.Column('squad_id', db.Integer, db.ForeignKey('squad.id')),
    db.Column('usuario_id', db.Integer, db.ForeignKey('usuario.id'))
)


class FormsObjetivos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    empresa_id = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    squad_id = db.Column(db.Integer, db.ForeignKey('squad.id'), nullable=False)
    data = db.Column(db.JSON)  # Você pode armazenar as informações do xlsx em um campo JSON

    empresa = db.relationship('Empresa', backref='forms_objetivos')
    squad = db.relationship('Squad', backref='forms_objetivos')


class ObjetivoGeradoChatAprovacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    objetivo = db.Column(db.String, nullable=False)
    empresa_id = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    squad_id = db.Column(db.Integer, db.ForeignKey('squad.id'), nullable=False)
    aprovado = db.Column(db.Boolean, default=False) # Você pode adicionar este campo se precisar aprovar os objetivos

    empresa = db.relationship('Empresa', backref='objetivos_gerados')
    squad = db.relationship('Squad', backref='objetivos_gerados')

class KrGeradoChatAprovacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    objetivo = db.Column(db.String(255), nullable=False)
    empresa_id = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    squad_id = db.Column(db.Integer, db.ForeignKey('squad.id'), nullable=False)
    KR = db.Column(db.String(255), nullable=False)
    meta = db.Column(db.String(255), nullable=True) # Novo campo

    empresa = db.relationship('Empresa', backref='kr_gerados')
    squad = db.relationship('Squad', backref='kr_gerados')



class OKR(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_empresa = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    squad_id = db.Column(db.Integer, db.ForeignKey('squad.id'), nullable=False)  # Adicionada relação com o Squad
    objetivo = db.Column(db.String(200))
    data_inicio = db.Column(db.DateTime, nullable=False)
    data_fim = db.Column(db.DateTime, nullable=False)

    empresa = db.relationship('Empresa', backref='okrs')
    squad = db.relationship('Squad', backref='okrs')  # Adicionada relação com o Squad




class KR(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_empresa = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    id_okr = db.Column(db.Integer, db.ForeignKey('okr.id'), nullable=False)
    squad_id = db.Column(db.Integer, db.ForeignKey('squad.id'), nullable=False) # Novo campo
    meta = db.Column(db.String(255), nullable=True) # Novo campo
    texto = db.Column(db.String(200))
    data_inclusao = db.Column(db.DateTime, default=datetime.utcnow)
    data_final = db.Column(db.DateTime)
    okr = db.relationship('OKR', backref='krs')
    squad = db.relationship('Squad', backref='krs') # Relacionamento com a tabela Squad


class MacroAcaoGeradoChatAprovacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    empresa_id = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    squad_id = db.Column(db.Integer, db.ForeignKey('squad.id'), nullable=False)
    objetivo_id = db.Column(db.Integer, db.ForeignKey('okr.id'), nullable=False)
    kr_id = db.Column(db.Integer, db.ForeignKey('kr.id'), nullable=False)
    macro_acao = db.Column(db.Text)
    empresa = db.relationship('Empresa', backref='macro_acoes')
    squad = db.relationship('Squad', backref='macro_acoes')
    okr = db.relationship('OKR', backref='macro_acoes')
    kr = db.relationship('KR', backref='sugestao_macro_acoes')



class MacroAcao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    texto = db.Column(db.String(500), nullable=False)
    aprovada = db.Column(db.Boolean, default=False)
    data_inclusao = db.Column(db.DateTime, default=datetime.utcnow)
    kr_id = db.Column(db.Integer, db.ForeignKey('kr.id'), nullable=False)
    objetivo = db.Column(db.String(500), nullable=False)
    squad_id = db.Column(db.Integer, db.ForeignKey('squad.id'), nullable=False)
    objetivo_id = db.Column(db.Integer, nullable=False)
    empresa = db.Column(db.String(500), nullable=False)
    empresa_id = db.Column(db.Integer, nullable=False)
    kr = db.relationship('KR', backref='macro_acoes')
    squad = db.relationship('Squad', backref='macroacoes')




class TarefasMetasSemanais(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    empresa = db.Column(db.String(255), nullable=False)
    squad_name = db.Column(db.String(255), nullable=False)
    squad_id = db.Column(db.Integer, db.ForeignKey('squad.id'), nullable=False)
    tarefa = db.Column(db.Text, nullable=False)
    meta_semanal = db.Column(db.Text, nullable=False)
    data_inclusao = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    data_conclusao = db.Column(db.DateTime)
    squad = db.relationship('Squad', backref='tarefas')
    subtarefas = db.Column(db.JSON)

    def init(self, empresa, squad_name, tarefa, meta_semanal, data_conclusao=None, subtarefas=None):
        self.empresa = empresa
        self.squad_name = squad_name  # Atualizado aqui também
        self.tarefa = tarefa
        self.meta_semanal = meta_semanal
        self.data_conclusao = data_conclusao
    def repr(self):
        return f'<Tarefa e Meta Semanal {self.id}: {self.tarefa}>'



class Sprint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    empresa_id = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    nome_empresa = db.Column(db.String(120), nullable=False)
    prioridade = db.Column(db.Integer, nullable=False)
    tarefa = db.Column(db.Text, nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=True)
    usuario = db.relationship('Usuario', backref='sprints')
    usuario_grupo = db.Column(db.String(120), nullable=True)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    dado_1_sprint = db.Column(db.JSON, default={"status": "pendente", "data_conclusao": None, "observacoes": ""})


class SprintPendente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    empresa_id = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    nome_empresa = db.Column(db.String(120), nullable=False)
    prioridade = db.Column(db.Integer, nullable=False)
    tarefa = db.Column(db.Text, nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    usuario = db.relationship('Usuario', backref='sprints_pendentes')
    usuario_grupo = db.Column(db.String(120), nullable=True)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    dado_1_sprint = db.Column(db.JSON, default={"status": "pendente", "data_conclusao": None, "observacoes": ""})



def is_base64(s):
    try:
        return base64.b64encode(base64.b64decode(s)) == s
    except Exception:
        return False



class TarefaSemanal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    empresa_id = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    empresa = db.relationship('Empresa', backref='tarefas_semanais')
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    usuario = db.relationship('Usuario', backref='tarefas_semanais')
    tarefa_semana = db.Column(db.String(500), nullable=False)
    to_do = db.Column(db.String(10000), nullable=True)
    observacoes = db.Column(db.String(10000), nullable=True)
    data_para_conclusao = db.Column(db.DateTime, nullable=False)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    data_atualizacao = db.Column(db.DateTime, onupdate=datetime.utcnow)

    @property
    def to_do_decoded(self):
        return json.loads(self.to_do)

    def observacoes_decoded(self):
        decoded_dict = {}
        if self.observacoes is not None:
            observacoes = json.loads(self.observacoes)
            for key, value in observacoes.items():
                # verify if the length of value is a multiple of 4, if not add the necessary '='
                if len(value) % 4 != 0:
                    value += '=' * (4 - len(value) % 4)
                # Check if value is base64 encoded
                if is_base64(value):
                    # decode the base64 value to string
                    decoded_dict[key] = b64decode(value).decode('utf-8')
                else:
                    decoded_dict[key] = value
                print(f"{key}: {decoded_dict[key]}")  # print key-value pair
        else:
            print("No observations for this task.")  # print message if observations is None
        return decoded_dict


class PostsInstagram(db.Model):
    id = db.Column(db.String, primary_key=True)
    id_empresa = db.Column(db.String(64), index=True)
    timestamp = db.Column(db.String(64))
    caption = db.Column(db.String(4000))
    like_count = db.Column(db.Integer)
    comments_count = db.Column(db.Integer)
    reach = db.Column(db.Integer)
    percentage = db.Column(db.Float)
    media_product_type = db.Column(db.String(64))
    plays = db.Column(db.Integer)
    saved = db.Column(db.Integer)
    nome_empresa = db.Column(db.String(64))
    analisado = db.Column(db.Boolean)  # Campo "analisado" adicionado

    def to_dict(self):
        return {
            'id': self.id,  # incluir o id no dicionário
            'id_empresa': self.id_empresa,
            'timestamp': self.timestamp,
            'caption': self.caption,
            'like_count': self.like_count,
            'comments_count': self.comments_count,
            'reach': self.reach,
            'percentage': self.percentage,
            'media_product_type': self.media_product_type,
            'plays': self.plays,
            'saved': self.saved,
            'nome_empresa': self.nome_empresa,
            'analisado': self.analisado,  # Incluído o campo "analisado" no dicionário
        }

class AnaliseInstagram(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_criacao = db.Column(db.String(64))
    analise = db.Column(db.Text)
    nome_empresa = db.Column(db.String(64))
    recente = db.Column(db.Boolean)

    def to_dict(self):
        return {
            'id': self.id,
            'data_criacao': self.data_criacao,
            'analise': self.analise,
            'nome_empresa': self.nome_empresa,
            'recente': self.recente,
        }



class analise_anuncios(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_empresa = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    empresa = db.relationship('Empresa', backref='respostas')
    nome_campanha = db.Column(db.Text)
    nome_grupo = db.Column(db.Text)
    nome_anuncio = db.Column(db.Text)
    valor = db.Column(db.Float)
    impressoes = db.Column(db.Integer)
    landing = db.Column(db.Integer)
    cpm = db.Column(db.Float)
    ctr = db.Column(db.Float)
    cpc = db.Column(db.Float)

class Trello(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    nome_tarefa = db.Column(db.String(64))
    desc = db.Column(db.String(1000))
    start = db.Column(db.String(64))
    close = db.Column(db.String(64))
    pos = db.Column(db.String(64))

    def to_dict(self):
        return {
            'id': self.id,
            'nome_tarefa': self.nome_tarefa,
            'desc': self.desc,
            'start': self.start,
            'close': self.close,
            'pos': self.pos
        }


class TarefasAndamento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    empresa = db.Column(db.String(255), nullable=False)
    squad_name = db.Column(db.String(255), nullable=False)
    squad_id = db.Column(db.Integer, db.ForeignKey('squad.id'), nullable=False)
    tarefa = db.Column(db.Text, nullable=False)
    data_inclusao = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    data_conclusao = db.Column(db.DateTime)
    subtarefas = db.Column(db.JSON)  # Campo JSON para subtarefas
    squad = db.relationship('Squad', backref='tarefas_atuais')



class TarefasFinalizadas(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    empresa = db.Column(db.String(255), nullable=False)
    squad_name = db.Column(db.String(255), nullable=False)
    squad_id = db.Column(db.Integer, db.ForeignKey('squad.id'), nullable=False)
    tarefa = db.Column(db.Text, nullable=False)
    data_inclusao = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    data_conclusao = db.Column(db.DateTime)
    subtarefas = db.Column(db.JSON)  # Campo JSON para subtarefas
    squad = db.relationship('Squad', backref='tarefas_concluidas')



'''

class TarefasAtuais(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    empresa = db.Column(db.String(255), nullable=False)
    squad_name = db.Column(db.String(255), nullable=False)  # Aqui mudamos para squad_name
    squad_id = db.Column(db.Integer, db.ForeignKey('squad.id'), nullable=False)
    tarefa = db.Column(db.Text, nullable=False)
    data_inclusao = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    data_conclusao = db.Column(db.DateTime)
    squad = db.relationship('Squad', backref='tarefas_atuais')

class TarefasConcluidas(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    empresa = db.Column(db.String(255), nullable=False)
    squad_name = db.Column(db.String(255), nullable=False)  # Aqui mudamos para squad_name
    squad_id = db.Column(db.Integer, db.ForeignKey('squad.id'), nullable=False)
    tarefa = db.Column(db.Text, nullable=False)
    data_inclusao = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    data_conclusao = db.Column(db.DateTime)
    squad = db.relationship('Squad', backref='tarefas_concluidas')
    

'''

