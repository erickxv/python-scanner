import sqlite3


def buscar_usuario(conn: sqlite3.Connection):
    nome = input("Digite o nome: ")
    cursor = conn.cursor()
    query = "SELECT * FROM usuarios WHERE nome = '" + nome + "'"
    cursor.execute(query)
    return cursor.fetchall()

def login(usuario, senha, conn: sqlite3.Connection):
    cursor = conn.cursor()
    query = (
            "SELECT id, usuario FROM usuarios "
            f"WHERE usuario = '{usuario}' AND senha = '{senha}'")
    cursor.execute(query)
    return cursor.fetchall()
