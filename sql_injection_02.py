"""
Exemplo didático de SQL Injection em ambiente local.

ATENÇÃO:
- Este exemplo NÃO deve ser usado contra sistemas de terceiros.
- A vulnerabilidade é intencional e serve apenas para estudo.
- O banco é SQLite e é criado localmente pelo próprio script.
"""

import sqlite3

DB = "exemplo_sql_injection.db"


def criar_banco():
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS usuarios")
    cursor.execute("""
        CREATE TABLE usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT NOT NULL,
            senha TEXT NOT NULL
        )
    """)

    cursor.executemany(
        "INSERT INTO usuarios (usuario, senha) VALUES (?, ?)",
        [
            ("admin", "123456"),
            ("erick", "senha123"),
            ("aluno", "abc123"),
        ],
    )

    conn.commit()
    conn.close()


# VULNERÁVEL: entrada do usuário é concatenada diretamente na SQL.
def login_vulneravel(usuario, senha):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    query = (
        "SELECT id, usuario FROM usuarios "
        f"WHERE usuario = '{usuario}' AND senha = '{senha}'"
    )

    print("\nSQL executada:")
    print(query)

    cursor.execute(query)
    resultado = cursor.fetchone()

    conn.close()
    return resultado


# CORRETO: utiliza parâmetros, impedindo que a entrada seja interpretada
# como parte da estrutura da consulta SQL.
def login_seguro(usuario, senha):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    query = (
        "SELECT id, usuario FROM usuarios "
        "WHERE usuario = ? AND senha = ?"
    )

    print("\nSQL parametrizada:")
    print(query)

    cursor.execute(query, (usuario, senha))
    resultado = cursor.fetchone()

    conn.close()
    return resultado


if __name__ == "__main__":
    criar_banco()

    print("=== TESTE NORMAL ===")
    print("Resultado:",
          login_vulneravel("admin", "123456"))

    print("\n=== TESTE DE SQL INJECTION ===")
    entrada_usuario = "' OR '1'='1"
    entrada_senha = "' OR '1'='1"

    resultado = login_vulneravel(
        entrada_usuario,
        entrada_senha
    )

    print("Resultado:", resultado)

    print("\n=== MESMA ENTRADA NO LOGIN SEGURO ===")
    resultado = login_seguro(
        entrada_usuario,
        entrada_senha
    )

    print("Resultado:", resultado)