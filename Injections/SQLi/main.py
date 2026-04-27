from flask import Flask, render_template_string, request
from markupsafe import escape, Markup

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>SQL Injection Visualizer</title>
    <style>
        :root {
            --bg: #090b1a;
            --panel: #14182e;
            --panel2: #101426;
            --border: #2b3155;
            --text: #f3f4ff;
            --muted: #a9afd1;
            --purple: #8b5cf6;
            --green: #5ee483;
            --red: #ff6b6b;
            --yellow: #ffd166;
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: Inter, Segoe UI, Arial, sans-serif;
            background:
                radial-gradient(circle at top left, rgba(139, 92, 246, 0.25), transparent 35%),
                radial-gradient(circle at bottom right, rgba(94, 228, 131, 0.12), transparent 30%),
                var(--bg);
            color: var(--text);
        }

        header {
            padding: 28px 40px;
            border-bottom: 1px solid var(--border);
            background: rgba(8, 10, 25, 0.8);
        }

        header h1 {
            margin: 0;
            font-size: 30px;
        }

        header p {
            margin: 8px 0 0;
            color: var(--muted);
        }

        main {
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: 22px;
            padding: 28px 40px;
        }

        .card {
            background: linear-gradient(180deg, var(--panel), var(--panel2));
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 22px;
            box-shadow: 0 18px 50px rgba(0,0,0,0.25);
        }

        .sidebar h2,
        .card h2 {
            margin-top: 0;
            font-size: 18px;
        }

        .sidebar p,
        .hint,
        .small {
            color: var(--muted);
            line-height: 1.5;
        }

        .flow {
            margin-top: 22px;
            display: grid;
            gap: 12px;
        }

        .flow div {
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 12px;
            text-align: center;
            background: rgba(255,255,255,0.03);
        }

        .arrow {
            text-align: center;
            color: var(--muted);
            font-size: 24px;
        }

        .content {
            display: grid;
            gap: 22px;
        }

        form {
            display: grid;
            gap: 16px;
        }

        label {
            display: grid;
            gap: 8px;
            font-weight: 700;
        }

        input, select {
            width: 100%;
            border: 1px solid #3d456f;
            border-radius: 12px;
            background: #0c1022;
            color: var(--text);
            padding: 13px 14px;
            font-size: 15px;
        }

        button {
            border: none;
            border-radius: 12px;
            background: linear-gradient(135deg, #8b5cf6, #5b21b6);
            color: white;
            padding: 14px 16px;
            font-size: 15px;
            font-weight: 800;
            cursor: pointer;
        }

        button:hover {
            filter: brightness(1.1);
        }

        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 22px;
        }

        .mode-box {
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 14px;
            background: rgba(255,255,255,0.03);
        }

        .unsafe {
            border-color: rgba(255,107,107,0.45);
            background: rgba(255,107,107,0.08);
        }

        .safe {
            border-color: rgba(94,228,131,0.45);
            background: rgba(94,228,131,0.08);
        }

        .query {
            margin-top: 12px;
            font-family: Consolas, monospace;
            font-size: 15px;
            line-height: 1.8;
            padding: 16px;
            border-radius: 12px;
            background: #070a16;
            border: 1px solid #30385e;
            overflow-x: auto;
        }

        .keyword {
            color: var(--green);
            font-weight: 900;
        }

        .input-highlight {
            color: #fff;
            background: rgba(255,107,107,0.35);
            border: 1px solid rgba(255,107,107,0.55);
            padding: 3px 6px;
            border-radius: 7px;
        }

        .result {
            font-size: 22px;
            font-weight: 900;
            padding: 18px;
            border-radius: 14px;
            margin-top: 12px;
        }

        .success {
            color: var(--green);
            background: rgba(94,228,131,0.08);
            border: 1px solid rgba(94,228,131,0.4);
        }

        .fail {
            color: var(--red);
            background: rgba(255,107,107,0.08);
            border: 1px solid rgba(255,107,107,0.4);
        }

        .examples {
            display: grid;
            gap: 10px;
        }

        .example {
            font-family: Consolas, monospace;
            background: #0c1022;
            border: 1px solid var(--border);
            padding: 10px 12px;
            border-radius: 10px;
            color: var(--muted);
        }

        .pill {
            display: inline-block;
            padding: 4px 9px;
            border-radius: 999px;
            font-size: 13px;
            font-weight: 800;
        }

        .pill-red {
            color: var(--red);
            background: rgba(255,107,107,0.12);
        }

        .pill-green {
            color: var(--green);
            background: rgba(94,228,131,0.12);
        }

        @media (max-width: 950px) {
            main, .grid-2 {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>

<header>
    <h1>SQL Injection Visualizer</h1>
    <p>See how user input can accidentally become part of SQL logic.</p>
</header>

<main>
    <aside class="card sidebar">
        <h2>What is happening?</h2>
        <p>
            SQL Injection happens when untrusted user input is inserted into a SQL query
            as command logic instead of being treated purely as data.
        </p>

        <div class="flow">
            <div>👤 User Input</div>
            <div class="arrow">↓</div>
            <div>🌐 Web Application</div>
            <div class="arrow">↓</div>
            <div>🗄️ Database</div>
        </div>

        <p class="small">
            <br>
            <span class="pill pill-red">Unsafe</span>
            String concatenation mixes input and SQL.
        </p>

        <p class="small">
            <span class="pill pill-green">Safe</span>
            Parameters keep input separate from SQL.
        </p>
    </aside>

    <section class="content">
        <div class="grid-2">
            <section class="card">
                <h2>1. Enter Login Data</h2>
                <p class="hint">Try normal input first, then an injected value.</p>

                <form method="POST">
                    <label>
                        Username
                        <input type="text" name="username" value="{{ username }}" placeholder="admin">
                    </label>

                    <label>
                        Password
                        <input type="text" name="password" value="{{ password }}" placeholder="password">
                    </label>

                    <label>
                        Mode
                        <select name="mode">
                            <option value="unsafe" {% if mode == "unsafe" %}selected{% endif %}>❌ Unsafe: String Concatenation</option>
                            <option value="safe" {% if mode == "safe" %}selected{% endif %}>✅ Safe: Parameterized Query</option>
                        </select>
                    </label>

                    <button type="submit">▶ Execute Query</button>
                </form>
            </section>

            <section class="card">
                <h2>2. Examples to Try</h2>
                <div class="examples">
                    <div class="example">admin / password</div>
                    <div class="example">admin / wrongpassword</div>
                    <div class="example">admin' OR '1'='1 / anything</div>
                    <div class="example">' OR '1'='1 / anything</div>
                    <div class="example">admin' -- / anything</div>
                </div>
            </section>
        </div>

        {% if query %}
        <section class="card">
            <h2>3. Generated Query</h2>

            {% if mode == "unsafe" %}
                <p><span class="pill pill-red">Unsafe Mode</span> User input is directly inserted into the SQL string.</p>
                <div class="mode-box unsafe">
                    <div class="query">{{ query }}</div>
                </div>
            {% else %}
                <p><span class="pill pill-green">Safe Mode</span> User input is bound separately as parameters.</p>
                <div class="mode-box safe">
                    <div class="query">{{ query }}</div>
                </div>
            {% endif %}
        </section>
        {% endif %}

        {% if result %}
        <section class="card">
            <h2>4. Simulated Result</h2>
            <div class="result {{ result_class }}">{{ result }}</div>

            {% if mode == "unsafe" %}
                <p class="hint">
                    In unsafe mode, injected input can change the meaning of the SQL query.
                </p>
            {% else %}
                <p class="hint">
                    In safe mode, the query structure stays fixed. The input remains data.
                </p>
            {% endif %}
        </section>
        {% endif %}
    </section>
</main>

</body>
</html>
"""


def highlight_sql(sql: str, user_values=None):
    user_values = user_values or []
    sql = escape(sql)

    for value in user_values:
        if value:
            sql = sql.replace(
                escape(value),
                Markup(f"<span class='input-highlight'>{escape(value)}</span>")
            )

    for keyword in ["SELECT", "FROM", "WHERE", "AND", "OR"]:
        sql = sql.replace(
            keyword,
            Markup(f"<span class='keyword'>{keyword}</span>")
        )

    return Markup(sql)


def simulate_login(username, password, mode):
    if mode == "unsafe":
        raw_query = (
            f"SELECT * FROM users "
            f"WHERE username = '{username}' "
            f"AND password = '{password}'"
        )

        query = highlight_sql(raw_query, [username, password])

        injected = (
            " OR " in username.upper()
            or " OR " in password.upper()
            or "--" in username
            or "--" in password
        )

        if injected:
            result = "✅ Login successful — injection changed the logic!"
            result_class = "success"
        elif username == "admin" and password == "password":
            result = "✅ Login successful"
            result_class = "success"
        else:
            result = "❌ Login failed"
            result_class = "fail"

    else:
        raw_query = (
            "SELECT * FROM users "
            "WHERE username = ? "
            "AND password = ?"
        )

        query = highlight_sql(raw_query)

        if username == "admin" and password == "password":
            result = "✅ Login successful"
            result_class = "success"
        else:
            result = "❌ Login failed — input was treated as data"
            result_class = "fail"

    return query, result, result_class


@app.route("/", methods=["GET", "POST"])
def index():
    username = ""
    password = ""
    query = None
    result = None
    result_class = ""
    mode = "unsafe"

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        mode = request.form.get("mode", "unsafe")

        query, result, result_class = simulate_login(username, password, mode)

    return render_template_string(
        HTML,
        username=username,
        password=password,
        query=query,
        result=result,
        result_class=result_class,
        mode=mode
    )


if __name__ == "__main__":
    app.run(debug=True)