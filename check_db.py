import sqlite3

con = sqlite3.connect("patches.db")
cur = con.cursor()
cur.execute("SELECT cve_id, repo_owner, repo_name, commit_sha, LENGTH(diff_text) FROM patches ORDER BY id DESC LIMIT 1")
print(cur.fetchone())
con.close()
