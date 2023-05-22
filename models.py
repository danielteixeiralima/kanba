from flask_sqlalchemy import SQLAlchemy
from datetime import datetime


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


class Resposta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_empresa = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    pergunta = db.Column(db.Text, nullable=False)
    resposta = db.Column(db.Text)
    classificacao = db.Column(db.String(200))  # Nova coluna
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    data_atualizacao = db.Column(db.DateTime, onupdate=datetime.utcnow)


class Usuario(db.Model):
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

class OKR(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_empresa = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    empresa = db.relationship('Empresa', backref='okrs')
    objetivo_1 = db.Column(db.String(200))
    objetivo_2 = db.Column(db.String(200))
    objetivo_3 = db.Column(db.String(200))
    objetivo_4 = db.Column(db.String(200))
    objetivo_5 = db.Column(db.String(200))



class KR(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_okr = db.Column(db.Integer, db.ForeignKey('okr.id'), nullable=False)
    texto = db.Column(db.String(200))
    okr = db.relationship('OKR', backref='krs')
