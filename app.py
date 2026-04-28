import hashlib
import hmac
import base64
import hashlib
import hmac
from argon2 import PasswordHasher
from argon2.low_level import Type

from flask import Flask, render_template, request
from markupsafe import escape, Markup

app = Flask(__name__)


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


def simulate_sql_login(username, password, mode):
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
            return query, "✅ Login successful — injection changed the logic!", "success"

        if username == "admin" and password == "password":
            return query, "✅ Login successful", "success"

        return query, "❌ Login failed", "fail"

    raw_query = (
        "SELECT * FROM users "
        "WHERE username = ? "
        "AND password = ?"
    )

    query = highlight_sql(raw_query)

    if username == "admin" and password == "password":
        return query, "✅ Login successful", "success"

    return query, "❌ Login failed — input was treated as data", "fail"


@app.route("/")
def index():
    return render_template("index.html", active_page="home")


@app.route("/injections/sql-login", methods=["GET", "POST"])
def sql_login():
    username = ""
    password = ""
    mode = "unsafe"
    query = None
    result = None
    result_class = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        mode = request.form.get("mode", "unsafe")

        query, result, result_class = simulate_sql_login(username, password, mode)

    return render_template(
        "injections/sql_login.html",
        active_page="sql_login",
        username=username,
        password=password,
        mode=mode,
        query=query,
        result=result,
        result_class=result_class,
    )


def highlight_command(command: str, user_values=None):
    user_values = user_values or []
    command = escape(command)

    dangerous_tokens = [";", "&&", "||", "|", "`", "$(", ")"]

    for value in user_values:
        if value:
            command = command.replace(
                escape(value),
                Markup(f"<span class='input-highlight'>{escape(value)}</span>")
            )

    for token in dangerous_tokens:
        command = command.replace(
            escape(token),
            Markup(f"<span class='keyword'>{escape(token)}</span>")
        )

    for word in ["ls", "cat", "whoami", "id", "pwd", "find"]:
        command = command.replace(
            word,
            Markup(f"<span class='keyword'>{word}</span>")
        )

    return Markup(command)


def simulate_command_injection(filename, mode):
    simulated_context = {
        "user": "www-data",
        "cwd": "/var/www/html",
        "server": "Apache on Ubuntu",
    }

    if mode == "unsafe":
        raw_command = f"ls -l /var/www/html/uploads/{filename}"
        command = highlight_command(raw_command, [filename])

        injected = any(token in filename for token in [";", "&&", "||", "|", "`", "$("])

        if injected:
            result = "⚠️ Extra command executed — user input changed the shell command!"
            result_class = "success"
            simulated_output = (
                "www-data\n"
                "/var/www/html\n"
                "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
            )
        else:
            result = "✅ File lookup executed normally"
            result_class = "success"
            simulated_output = (
                "-rw-r--r-- 1 www-data www-data 2048 Apr 27 invoice.pdf"
            )

    else:
        raw_command = "ls -l /var/www/html/uploads/<validated_filename>"
        command = highlight_command(raw_command)

        if any(token in filename for token in [";", "&&", "||", "|", "`", "$("]):
            result = "❌ Rejected — filename contains shell-control characters"
            result_class = "fail"
            simulated_output = "Input rejected before command construction."
        else:
            result = "✅ File lookup executed safely"
            result_class = "success"
            simulated_output = (
                "-rw-r--r-- 1 www-data www-data 2048 Apr 27 invoice.pdf"
            )

    return command, result, result_class, simulated_output, simulated_context


@app.route("/injections/command", methods=["GET", "POST"])
def command_injection():
    filename = ""
    mode = "unsafe"
    command = None
    result = None
    result_class = ""
    simulated_output = None
    simulated_context = {
        "user": "www-data",
        "cwd": "/var/www/html",
        "server": "Apache on Ubuntu",
    }

    if request.method == "POST":
        filename = request.form.get("filename", "")
        mode = request.form.get("mode", "unsafe")

        command, result, result_class, simulated_output, simulated_context = simulate_command_injection(
            filename, mode
        )

    return render_template(
        "injections/command.html",
        active_page="command",
        filename=filename,
        mode=mode,
        command=command,
        result=result,
        result_class=result_class,
        simulated_output=simulated_output,
        simulated_context=simulated_context,
    )


def highlight_html(html: str, user_values=None):
    user_values = user_values or []
    html = escape(html)

    for value in user_values:
        if value:
            html = html.replace(
                escape(value),
                Markup(f"<span class='input-highlight'>{escape(value)}</span>")
            )

    for token in ["&lt;", "&gt;", "&lt;script", "&lt;/script&gt;", "onerror", "onclick"]:
        html = html.replace(
            token,
            Markup(f"<span class='keyword'>{token}</span>")
        )

    return Markup(html)


def simulate_xss(comment, mode):
    if mode == "unsafe":
        raw_html = f"<div class='comment'>{comment}</div>"
        rendered_preview = comment

        suspicious = any(
            token in comment.lower()
            for token in ["<script", "onerror", "onclick", "javascript:"]
        )

        html_output = highlight_html(raw_html, [comment])

        if suspicious:
            result = "⚠️ XSS risk — input became browser-interpreted markup or script!"
            result_class = "success"
        else:
            result = "✅ Comment rendered"
            result_class = "success"

    else:
        escaped_comment = escape(comment)
        raw_html = f"<div class='comment'>{escaped_comment}</div>"
        rendered_preview = escaped_comment

        html_output = highlight_html(raw_html)

        if comment:
            result = "✅ Safe rendering — input was treated as text"
            result_class = "success"
        else:
            result = "ℹ️ Enter a comment to render"
            result_class = "fail"

    return html_output, rendered_preview, result, result_class


@app.route("/injections/xss", methods=["GET", "POST"])
def xss_injection():
    comment = ""
    mode = "unsafe"
    html_output = None
    rendered_preview = None
    result = None
    result_class = ""

    if request.method == "POST":
        comment = request.form.get("comment", "")
        mode = request.form.get("mode", "unsafe")

        html_output, rendered_preview, result, result_class = simulate_xss(comment, mode)

    return render_template(
        "injections/xss.html",
        active_page="xss",
        comment=comment,
        mode=mode,
        html_output=html_output,
        rendered_preview=rendered_preview,
        result=result,
        result_class=result_class,
    )

def highlight_ldap_filter(filter_text: str, user_values=None):
    user_values = user_values or []
    filter_text = escape(filter_text)

    for value in user_values:
        if value:
            filter_text = filter_text.replace(
                escape(value),
                Markup(f"<span class='input-highlight'>{escape(value)}</span>")
            )

    for token in ["&amp;", "|", "!", "(", ")", "*", "uid", "userPassword", "ou", "objectClass"]:
        filter_text = filter_text.replace(
            escape(token),
            Markup(f"<span class='keyword'>{escape(token)}</span>")
        )

    return Markup(filter_text)


def escape_ldap_value(value: str):
    replacements = {
        "\\": r"\5c",
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }

    return "".join(replacements.get(char, char) for char in value)


def simulate_ldap_injection(username, password, mode):
    base_dn = "ou=people,dc=example,dc=org"

    if mode == "unsafe":
        raw_filter = f"(&(uid={username})(userPassword={password}))"
        ldap_filter = highlight_ldap_filter(raw_filter, [username, password])

        injected = any(token in username or token in password for token in ["*", "(", ")", "|", "&", "!"])

        if injected:
            result = "⚠️ LDAP filter changed — input became filter logic!"
            result_class = "success"
            simulated_output = (
                "Search base: ou=people,dc=example,dc=org\n"
                "Matched entries:\n"
                "  uid=admin,ou=people,dc=example,dc=org\n"
                "  uid=alice,ou=people,dc=example,dc=org\n"
                "  uid=bob,ou=people,dc=example,dc=org"
            )
        elif username == "admin" and password == "password":
            result = "✅ LDAP bind/search successful"
            result_class = "success"
            simulated_output = (
                "Search base: ou=people,dc=example,dc=org\n"
                "Matched entries:\n"
                "  uid=admin,ou=people,dc=example,dc=org"
            )
        else:
            result = "❌ LDAP search returned no matching user"
            result_class = "fail"
            simulated_output = (
                "Search base: ou=people,dc=example,dc=org\n"
                "Matched entries: none"
            )

    else:
        safe_username = escape_ldap_value(username)
        safe_password = escape_ldap_value(password)

        raw_filter = f"(&(uid={safe_username})(userPassword={safe_password}))"
        ldap_filter = highlight_ldap_filter(raw_filter)

        if username == "admin" and password == "password":
            result = "✅ LDAP search successful"
            result_class = "success"
            simulated_output = (
                "Search base: ou=people,dc=example,dc=org\n"
                "Matched entries:\n"
                "  uid=admin,ou=people,dc=example,dc=org"
            )
        else:
            result = "❌ LDAP search failed — input was escaped as data"
            result_class = "fail"
            simulated_output = (
                "Search base: ou=people,dc=example,dc=org\n"
                "Matched entries: none"
            )

    return ldap_filter, result, result_class, simulated_output, base_dn


@app.route("/injections/ldap", methods=["GET", "POST"])
def ldap_injection():
    username = ""
    password = ""
    mode = "unsafe"
    ldap_filter = None
    result = None
    result_class = ""
    simulated_output = None
    base_dn = "ou=people,dc=example,dc=org"

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        mode = request.form.get("mode", "unsafe")

        ldap_filter, result, result_class, simulated_output, base_dn = simulate_ldap_injection(
            username, password, mode
        )

    return render_template(
        "injections/ldap.html",
        active_page="ldap",
        username=username,
        password=password,
        mode=mode,
        ldap_filter=ldap_filter,
        result=result,
        result_class=result_class,
        simulated_output=simulated_output,
        base_dn=base_dn,
    )

def highlight_xml(xml_text: str, user_values=None):
    user_values = user_values or []
    xml_text = escape(xml_text)

    for value in user_values:
        if value:
            xml_text = xml_text.replace(
                escape(value),
                Markup(f"<span class='input-highlight'>{escape(value)}</span>")
            )

    for token in ["&lt;", "&gt;", "&lt;/", "/&gt;", "&quot;", "&apos;"]:
        xml_text = xml_text.replace(
            token,
            Markup(f"<span class='keyword'>{token}</span>")
        )

    return Markup(xml_text)


def simulate_xml_injection(display_name, mode):
    if mode == "unsafe":
        raw_xml = f"<user><name>{display_name}</name><role>student</role></user>"
        xml_output = highlight_xml(raw_xml, [display_name])

        injected = any(token in display_name for token in ["<", ">", "</", "/>"])

        if injected:
            result = "⚠️ XML structure changed — input became markup!"
            result_class = "success"
            simulated_output = (
                "Parser interpretation:\n"
                "  XML tree may contain additional elements or modified structure."
            )
        else:
            result = "✅ XML document generated normally"
            result_class = "success"
            simulated_output = (
                "Parser interpretation:\n"
                "  user.name = " + display_name + "\n"
                "  user.role = student"
            )
    else:
        safe_name = escape(display_name)
        raw_xml = f"<user><name>{safe_name}</name><role>student</role></user>"
        xml_output = highlight_xml(raw_xml)

        result = "✅ Safe XML — input was escaped as text"
        result_class = "success"
        simulated_output = (
            "Parser interpretation:\n"
            "  XML structure stayed fixed.\n"
            "  User input remained text."
        )

    return xml_output, result, result_class, simulated_output


@app.route("/injections/xml", methods=["GET", "POST"])
def xml_injection():
    display_name = ""
    mode = "unsafe"
    xml_output = None
    result = None
    result_class = ""
    simulated_output = None

    if request.method == "POST":
        display_name = request.form.get("display_name", "")
        mode = request.form.get("mode", "unsafe")

        xml_output, result, result_class, simulated_output = simulate_xml_injection(
            display_name, mode
        )

    return render_template(
        "injections/xml.html",
        active_page="xml",
        display_name=display_name,
        mode=mode,
        xml_output=xml_output,
        result=result,
        result_class=result_class,
        simulated_output=simulated_output,
    )


def highlight_json(json_text: str, user_values=None):
    user_values = user_values or []
    json_text = escape(json_text)

    for value in user_values:
        if value:
            json_text = json_text.replace(
                escape(value),
                Markup(f"<span class='input-highlight'>{escape(value)}</span>")
            )

    for token in ['"$where"', '"$ne"', '"$gt"', "{", "}", ":", ","]:
        json_text = json_text.replace(
            escape(token),
            Markup(f"<span class='keyword'>{escape(token)}</span>")
        )

    return Markup(json_text)


def simulate_nosql_injection(username, password, mode):
    if mode == "unsafe":
        query = (
            '{ "username": "' + username + '", '
            '"password": "' + password + '" }'
        )

        nosql_output = highlight_json(query, [username, password])

        injected = any(token in username + password for token in ["$where", "$ne", "$gt", "||", "true"])

        if injected:
            result = "⚠️ NoSQL query changed — input became query logic!"
            result_class = "success"
            simulated_output = (
                "MongoDB-like interpretation:\n"
                "  Additional operator or JavaScript-like logic detected.\n"
                "  Query may match more users than intended."
            )
        elif username == "admin" and password == "password":
            result = "✅ Login successful"
            result_class = "success"
            simulated_output = "Matched document: { username: 'admin', role: 'admin' }"
        else:
            result = "❌ No matching document"
            result_class = "fail"
            simulated_output = "Matched documents: none"

    else:
        query = (
            '{ "username": <string parameter>, '
            '"password": <string parameter> }'
        )

        nosql_output = highlight_json(query)

        if username == "admin" and password == "password":
            result = "✅ Login successful"
            result_class = "success"
            simulated_output = "Matched document: { username: 'admin', role: 'admin' }"
        else:
            result = "❌ Login failed — input was treated as literal strings"
            result_class = "fail"
            simulated_output = "Matched documents: none"

    return nosql_output, result, result_class, simulated_output


@app.route("/injections/nosql", methods=["GET", "POST"])
def nosql_injection():
    username = ""
    password = ""
    mode = "unsafe"
    nosql_output = None
    result = None
    result_class = ""
    simulated_output = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        mode = request.form.get("mode", "unsafe")

        nosql_output, result, result_class, simulated_output = simulate_nosql_injection(
            username, password, mode
        )

    return render_template(
        "injections/nosql.html",
        active_page="nosql",
        username=username,
        password=password,
        mode=mode,
        nosql_output=nosql_output,
        result=result,
        result_class=result_class,
        simulated_output=simulated_output,
    )


def simulate_request_smuggling(raw_request, mode):
    if mode == "unsafe":
        suspicious = "Content-Length" in raw_request and "Transfer-Encoding" in raw_request

        front_end_view = (
            "Front-end proxy interpretation:\n"
            "  Uses Content-Length\n"
            "  Believes request body has fixed length"
        )

        back_end_view = (
            "Back-end server interpretation:\n"
            "  Uses Transfer-Encoding: chunked\n"
            "  May see a different request boundary"
        )

        if suspicious:
            result = "⚠️ Parser disagreement — request boundary may be interpreted differently!"
            result_class = "success"
        else:
            result = "✅ No parser disagreement shown"
            result_class = "success"

    else:
        front_end_view = (
            "Front-end proxy interpretation:\n"
            "  Ambiguous request rejected before forwarding"
        )

        back_end_view = (
            "Back-end server interpretation:\n"
            "  Receives only normalized, unambiguous requests"
        )

        result = "✅ Safe handling — ambiguous framing rejected or normalized"
        result_class = "success"

    highlighted_request = escape(raw_request)
    for token in ["Content-Length", "Transfer-Encoding", "chunked", "GET", "POST", "HTTP/1.1"]:
        highlighted_request = highlighted_request.replace(
            token,
            Markup(f"<span class='keyword'>{token}</span>")
        )

    return Markup(highlighted_request), result, result_class, front_end_view, back_end_view


@app.route("/injections/request-smuggling", methods=["GET", "POST"])
def request_smuggling():
    default_request = (
        "POST /submit HTTP/1.1\n"
        "Host: example.org\n"
        "Content-Length: 13\n"
        "Transfer-Encoding: chunked\n"
        "\n"
        "0\n"
        "\n"
        "GET /admin HTTP/1.1\n"
        "Host: example.org\n"
    )

    raw_request = default_request
    mode = "unsafe"
    highlighted_request = None
    result = None
    result_class = ""
    front_end_view = None
    back_end_view = None

    if request.method == "POST":
        raw_request = request.form.get("raw_request", default_request)
        mode = request.form.get("mode", "unsafe")

        highlighted_request, result, result_class, front_end_view, back_end_view = simulate_request_smuggling(
            raw_request, mode
        )

    return render_template(
        "injections/request_smuggling.html",
        active_page="smuggling",
        raw_request=raw_request,
        mode=mode,
        highlighted_request=highlighted_request,
        result=result,
        result_class=result_class,
        front_end_view=front_end_view,
        back_end_view=back_end_view,
    )

@app.route("/prevention-detection")
def prevention_detection():
    return render_template(
        "prevention_detection.html",
        active_page="prevention_detection"
    )

def simulate_logging(mode):
    events = [
        {"time": "10:00:01", "type": "login_attempt", "user": "admin", "status": "fail"},
        {"time": "10:00:03", "type": "login_attempt", "user": "admin", "status": "fail"},
        {"time": "10:00:05", "type": "login_attempt", "user": "admin", "status": "fail"},
        {"time": "10:00:10", "type": "login_attempt", "user": "admin", "status": "success"},
    ]

    if mode == "unsafe":
        logs = [
            "User login failed",
            "User login failed",
            "User login failed",
            "User login successful"
        ]

        detection = "❌ No alert — events are not correlated"
        detection_class = "fail"

    else:
        logs = [
            "[10:00:01] LOGIN_FAIL user=admin ip=192.168.1.50",
            "[10:00:03] LOGIN_FAIL user=admin ip=192.168.1.50",
            "[10:00:05] LOGIN_FAIL user=admin ip=192.168.1.50",
            "[10:00:10] LOGIN_SUCCESS user=admin ip=192.168.1.50",
            "⚠️ ALERT: Possible brute-force attack detected"
        ]

        detection = "✅ Alert triggered — suspicious pattern detected"
        detection_class = "success"

    return events, logs, detection, detection_class


HASHING_METHODS = {
    "plaintext": {
        "label": "Plaintext",
        "purpose": "Never appropriate for password storage.",
        "explanation": (
            "The password is stored exactly as entered. If the database is leaked, "
            "all passwords are immediately exposed. This is not cryptography; it is just storage."
        ),
        "salt_note": "No salt is used.",
        "where_it_shines": "Nowhere for credentials. Only useful as a bad example.",
    },
    "sha256": {
        "label": "SHA-256",
        "purpose": "Fast cryptographic hash for integrity checks.",
        "explanation": (
            "SHA-256 is excellent for checking whether files or messages changed, "
            "but it is intentionally fast. That speed makes offline password guessing cheap."
        ),
        "salt_note": "No salt is used here, so identical passwords produce identical hashes.",
        "where_it_shines": "File integrity, checksums, digital signatures, Merkle trees.",
    },
    "salted_sha256": {
        "label": "Salted SHA-256",
        "purpose": "Shows what a salt does, but still not ideal for passwords.",
        "explanation": (
            "A salt prevents equal passwords from producing equal hashes and makes precomputed "
            "rainbow tables less useful. However, SHA-256 is still far too fast for password storage."
        ),
        "salt_note": "A random per-password salt is mixed into the hash input.",
        "where_it_shines": "Teaching salt concepts; not recommended for modern password storage.",
    },
    "hmac": {
        "label": "HMAC-SHA-256",
        "purpose": "Integrity and authenticity with a secret key.",
        "explanation": (
            "HMAC proves that someone with the secret key created or validated the message. "
            "It is great for API signatures and tamper detection, but it is not a password hashing scheme."
        ),
        "salt_note": "Uses a server-side secret key, often called a pepper in password discussions.",
        "where_it_shines": "API request signing, token integrity, webhook verification.",
    },
    "argon2id": {
        "label": "Argon2id",
        "purpose": "Modern password hashing.",
        "explanation": (
            "Argon2id is designed to be expensive for attackers by using configurable CPU time "
            "and memory. The stored hash contains the algorithm parameters, salt, and derived hash."
        ),
        "salt_note": "The Argon2 library automatically generates and embeds a random salt.",
        "where_it_shines": "Password storage and password-based key derivation.",
    },
}


def simulate_hashing(password, mode):
    method = HASHING_METHODS[mode]

    salt = ""
    pepper = ""
    stored = ""

    if mode == "plaintext":
        stored = password
        result_class = "fail"
        effort = "No cracking needed."

    elif mode == "sha256":
        stored = hashlib.sha256(password.encode()).hexdigest()
        result_class = "fail"
        effort = "Very cheap to brute-force."

    elif mode == "salted_sha256":
        salt = base64.b64encode(b"classroom_random_salt").decode()
        stored = hashlib.sha256((salt + password).encode()).hexdigest()
        result_class = "fail"
        effort = "Salt helps against precomputation, but guessing is still fast."

    elif mode == "hmac":
        pepper = "server_secret_pepper"
        stored = hmac.new(
            pepper.encode(),
            password.encode(),
            hashlib.sha256
        ).hexdigest()
        result_class = "fail"
        effort = "Secret key helps for message authentication, but this is not password hashing."

    else:
        ph = PasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        stored = ph.hash(password)
        result_class = "success"
        effort = "Expensive by design; memory-hard and tunable."

        # PHC format:
        # $argon2id$v=19$m=65536,t=3,p=4$base64salt$base64hash
        parts = stored.split("$")
        salt = parts[4] if len(parts) >= 6 else "embedded in hash"

    return {
        **method,
        "stored": stored,
        "salt": salt,
        "pepper": pepper,
        "effort": effort,
        "result_class": result_class,
    }


@app.route("/owasp/a04", methods=["GET", "POST"])
def cryptographic_failures():
    password = "password123"
    mode = "plaintext"

    if request.method == "POST":
        password = request.form.get("password", "password123")
        mode = request.form.get("mode", "plaintext")

    result = simulate_hashing(password, mode)

    return render_template(
        "owasp/a04.html",
        active_page="a04",
        password=password,
        mode=mode,
        result=result,
        methods=HASHING_METHODS,
    )


if __name__ == "__main__":
    app.run(debug=True)