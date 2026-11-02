import sqlite3

conn = sqlite3.connect(r'D:\drishti\data\drishti.db')
cur = conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [r[0] for r in cur.fetchall() if not r[0].startswith('sqlite_')]
for t in tables:
    count = cur.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
    print(f"{t}: {count}")
conn.close()
