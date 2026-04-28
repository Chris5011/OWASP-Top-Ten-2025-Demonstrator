import hashlib
import hmac
import base64
import hashlib
import hmac
import json
import pickle

from argon2 import PasswordHasher
from argon2.low_level import Type

from flask import Flask, render_template, request, jsonify, send_from_directory
from markupsafe import escape, Markup

app = Flask(__name__)

OWASP_NAV = [
    {
        "id": "a01",
        "label": "A01 Broken Access Control",
        "items": [
            {"id": "a01_idor", "label": "Account Access / IDOR", "endpoint": None},
        ],
    },
    {
        "id": "a02",
        "label": "A02 Security Misconfiguration",
        "items": [
            {"id": "a02_soon", "label": "Coming Soon", "endpoint": None},
        ],
    },
    {
        "id": "a03",
        "label": "A03 Software Supply Chain Failures",
        "items": [
            {"id": "a03_soon", "label": "Coming Soon", "endpoint": None},
        ],
    },
    {
        "id": "a04",
        "label": "A04 Cryptographic Failures",
        "items": [
            {"id": "a04", "label": "Password Hashing", "endpoint": "cryptographic_failures"},
            {"id": "a04_jwt", "label": "JWT Token Integrity", "endpoint": "jwt_crypto_failures"},
            {"id": "a04_transit", "label": "Data in Transit", "endpoint": None},
            {"id": "a04_keys", "label": "Key Management", "endpoint": None},
        ],
    },
    {
        "id": "a05",
        "label": "A05 Injection",
        "items": [
            {"id": "sql_login", "label": "SQL Injection", "endpoint": "sql_login"},
            {"id": "command", "label": "Command Injection", "endpoint": "command_injection"},
            {"id": "xss", "label": "Cross-Site Scripting", "endpoint": "xss_injection"},
            {"id": "ldap", "label": "LDAP Injection", "endpoint": "ldap_injection"},
            {"id": "xml", "label": "XML Injection", "endpoint": "xml_injection"},
            {"id": "nosql", "label": "NoSQL Injection", "endpoint": "nosql_injection"},
            {"id": "smuggling", "label": "HTTP Request Smuggling", "endpoint": "request_smuggling"},
        ],
    },
    {
        "id": "a06",
        "label": "A06 Insecure Design",
        "items": [
            {"id": "a06_insecure", "label": "insecure designed app", "endpoint": "insecure_design"},
        ],
    },
    {
        "id": "a07",
        "label": "A07 Authentication Failures",
        "items": [
            {"id": "a07_sessions", "label": "Session Hijacking / Fixation", "endpoint": "session_failures"},
            {"id": "a07_jwt", "label": "JWT Auth Bypass", "endpoint": "jwt_auth_failures"},
        ],
    },
    {
        "id": "a08",
        "label": "A08 Software and Data Integrity Failures",
        "items": [
            {"id": "a08_pickle", "label": "Insecure Deserialization", "endpoint": "a08_pickle_demo"},
            {"id": "a08_cdn", "label": "CDN Integrity / SRI", "endpoint": "a08_cdn_demo"},
        ],
    },
    {
        "id": "a09",
        "label": "A09 Security Logging and Alerting Failures",
        "items": [
            {"id": "a09", "label": "Login Attack Timeline", "endpoint": "logging_failures"},
        ],
    },
    {
        "id": "a10",
        "label": "A10 Mishandling of Exceptional Conditions",
        "items": [
            {"id": "a10_fail_open", "label": "Fail-open Authorization", "endpoint": "a10_fail_open_demo"},
            {"id": "a10_error_disclosure", "label": "Error Disclosure", "endpoint": "a10_error_disclosure_demo"},
        ],
    },
]


@app.context_processor
def inject_navigation():
    return {"owasp_nav": OWASP_NAV}


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


PRODUCTS = {
    "coffee": {"name": "Coffee Mug", "price": 12.99},
    "hoodie": {"name": "Cyber Hoodie", "price": 49.99},
    "sticker": {"name": "Sticker Pack", "price": 4.99},
}


def simulate_insecure_design(product_id, quantity, mode):
    product = PRODUCTS.get(product_id, PRODUCTS["coffee"])
    price = product["price"]

    try:
        quantity = int(quantity)
    except ValueError:
        quantity = 1

    if mode == "unsafe":
        total = price * quantity

        if total < 0:
            result = "⚠️ Order accepted — negative quantity created store credit!"
            result_class = "success"
        else:
            result = "✅ Order accepted"
            result_class = "success"

        decision_steps = [
            "1. User selected product ✅",
            "2. User entered quantity ✅",
            "3. System calculated price × quantity ✅",
            "4. Missing business rule: quantity must be positive ❌",
            "5. Order accepted ⚠️",
        ]

    else:
        if quantity <= 0:
            total = 0
            result = "❌ Order rejected — quantity must be at least 1"
            result_class = "fail"
            decision_steps = [
                "1. User selected product ✅",
                "2. User entered quantity ✅",
                "3. Business rule check: quantity >= 1 ❌",
                "4. Order rejected ✅",
            ]
        else:
            total = price * quantity
            result = "✅ Order accepted — business rule enforced"
            result_class = "success"
            decision_steps = [
                "1. User selected product ✅",
                "2. User entered quantity ✅",
                "3. Business rule check: quantity >= 1 ✅",
                "4. Order accepted ✅",
            ]

    return product, quantity, total, result, result_class, decision_steps




JWT_SECRET = "classroom-secret"

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def make_demo_jwt(username="alice", role="user", alg="HS256"):
    header = {"typ": "JWT", "alg": alg}
    payload = {"sub": username, "role": role, "lesson": "OWASP A04/A07"}

    header_b64 = b64url_encode(json.dumps(header).encode())
    payload_b64 = b64url_encode(json.dumps(payload).encode())

    if alg == "none":
        return f"{header_b64}.{payload_b64}."

    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()

    return f"{header_b64}.{payload_b64}.{b64url_encode(signature)}"


def parse_demo_jwt(token):
    try:
        header_b64, payload_b64, signature = token.split(".")
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
        return header, payload, signature, None
    except Exception as exc:
        return None, None, None, f"Invalid token format: {exc}"


def verify_demo_jwt(token, mode):
    header, payload, signature, error = parse_demo_jwt(token)

    if error:
        return {
            "header": None,
            "payload": None,
            "result": f"❌ {error}",
            "result_class": "fail",
            "decision_steps": ["1. Token parsing failed ❌"],
        }

    alg = header.get("alg", "none")

    if mode == "unsafe":
        decision_steps = [
            "1. Token parsed ✅",
            f"2. Header says alg={alg} ✅",
            "3. Application trusts the token header ❌",
            "4. Signature verification skipped or weakened ⚠️",
            "5. Payload accepted as identity ⚠️",
        ]

        if payload.get("role") == "admin":
            result = "⚠️ Admin access granted — token payload was trusted!"
            result_class = "success"
        else:
            result = "✅ User token accepted"
            result_class = "success"

    else:
        signing_input = ".".join(token.split(".")[:2]).encode()
        expected_signature = b64url_encode(
            hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        )

        decision_steps = [
            "1. Token parsed ✅",
            "2. Server ignores attacker-controlled alg header ✅",
            "3. Server enforces expected algorithm: HS256 ✅",
            "4. Signature recalculated with server secret ✅",
        ]

        if alg != "HS256":
            result = "❌ Token rejected — unsupported algorithm"
            result_class = "fail"
            decision_steps.append("5. Token rejected ✅")
        elif not hmac.compare_digest(signature, expected_signature):
            result = "❌ Token rejected — signature mismatch"
            result_class = "fail"
            decision_steps.append("5. Signature mismatch detected ✅")
        else:
            result = "✅ Token accepted — signature valid"
            result_class = "success"
            decision_steps.append("5. Signature valid ✅")

    return {
        "header": header,
        "payload": payload,
        "signature": signature,
        "result": result,
        "result_class": result_class,
        "decision_steps": decision_steps,
    }


def tamper_jwt_to_admin(token, alg="none"):
    header, payload, signature, error = parse_demo_jwt(token)
    if error:
        return token

    payload["role"] = "admin"
    header["alg"] = alg

    header_b64 = b64url_encode(json.dumps(header).encode())
    payload_b64 = b64url_encode(json.dumps(payload).encode())

    if alg == "none":
        return f"{header_b64}.{payload_b64}."

    return f"{header_b64}.{payload_b64}.{signature}"

@app.route("/owasp/a04/jwt", methods=["GET", "POST"])
def jwt_crypto_failures():
    token = make_demo_jwt()
    mode = "unsafe"
    action = "original"

    if request.method == "POST":
        token = request.form.get("token", token)
        mode = request.form.get("mode", "unsafe")
        action = request.form.get("action", "verify")

        if action == "tamper_none":
            token = tamper_jwt_to_admin(token, "none")
        elif action == "tamper_hs256":
            token = tamper_jwt_to_admin(token, "HS256")

    result = verify_demo_jwt(token, mode)

    return render_template(
        "owasp/a04_jwt.html",
        active_page="a04_jwt",
        token=token,
        mode=mode,
        result=result,
    )


@app.route("/owasp/a06", methods=["GET", "POST"])
def insecure_design():
    product_id = "coffee"
    quantity = "1"
    mode = "unsafe"

    if request.method == "POST":
        product_id = request.form.get("product_id", "coffee")
        quantity = request.form.get("quantity", "1")
        mode = request.form.get("mode", "unsafe")

    product, quantity, total, result, result_class, decision_steps = simulate_insecure_design(
        product_id,
        quantity,
        mode
    )

    return render_template(
        "owasp/a06.html",
        active_page="a06",
        products=PRODUCTS,
        product_id=product_id,
        product=product,
        quantity=quantity,
        total=total,
        mode=mode,
        result=result,
        result_class=result_class,
        decision_steps=decision_steps,
    )

DEMO_SESSIONS = {
    "ATTACKER-KNOWN-SESSION": {
        "user": None,
        "authenticated": False,
        "created_by": "attacker",
    }
}


def simulate_session_attack(action, mode, session_id, username):
    session_id = session_id or "ATTACKER-KNOWN-SESSION"
    username = username or "alice"

    if session_id not in DEMO_SESSIONS:
        DEMO_SESSIONS[session_id] = {
            "user": None,
            "authenticated": False,
            "created_by": "browser",
        }

    before_session_id = session_id
    session = DEMO_SESSIONS[session_id]

    if action == "visit":
        result = "ℹ️ Anonymous session created / reused"
        result_class = "success"

    elif action == "login":
        if mode == "unsafe":
            session["user"] = username
            session["authenticated"] = True

            result = "⚠️ Login successful — old session ID was reused!"
            result_class = "success"

        else:
            new_session_id = f"SERVER-GENERATED-{hashlib.sha256((session_id + username).encode()).hexdigest()[:12]}"

            DEMO_SESSIONS[new_session_id] = {
                "user": username,
                "authenticated": True,
                "created_by": "server",
            }

            session_id = new_session_id
            session = DEMO_SESSIONS[session_id]

            result = "✅ Login successful — session ID rotated after authentication"
            result_class = "success"

    elif action == "attacker_reuse":
        if session.get("authenticated"):
            result = f"⚠️ Attacker reused session and became {session.get('user')}!"
            result_class = "success"
        else:
            result = "❌ Attacker reused session, but it is not authenticated"
            result_class = "fail"

    elif action == "logout":
        if mode == "unsafe":
            session["authenticated"] = False
            session["user"] = None

            result = "⚠️ Logout performed — but session ID still exists and can be reused"
            result_class = "fail"
        else:
            DEMO_SESSIONS.pop(session_id, None)

            result = "✅ Logout performed — session invalidated server-side"
            result_class = "success"

    else:
        result = "ℹ️ Select an action"
        result_class = "fail"

    decision_steps = []

    if mode == "unsafe":
        decision_steps = [
            "1. Browser presents a session ID ✅",
            "2. Server accepts the existing session ID ✅",
            "3. User logs in ✅",
            "4. Server keeps the same session ID ❌",
            "5. Anyone with that ID can reuse the authenticated session ⚠️",
        ]
    else:
        decision_steps = [
            "1. Browser presents a session ID ✅",
            "2. User logs in ✅",
            "3. Server generates a new session ID ✅",
            "4. Old session ID becomes useless ✅",
            "5. Logout invalidates the server-side session ✅",
        ]

    return {
        "before_session_id": before_session_id,
        "session_id": session_id,
        "session": session,
        "result": result,
        "result_class": result_class,
        "decision_steps": decision_steps,
        "all_sessions": DEMO_SESSIONS,
    }


@app.route("/owasp/a07/sessions", methods=["GET", "POST"])
def session_failures():
    mode = "unsafe"
    action = "visit"
    session_id = "ATTACKER-KNOWN-SESSION"
    username = "alice"

    if request.method == "POST":
        mode = request.form.get("mode", "unsafe")
        action = request.form.get("action", "visit")
        session_id = request.form.get("session_id", "ATTACKER-KNOWN-SESSION")
        username = request.form.get("username", "alice")

    result = simulate_session_attack(action, mode, session_id, username)

    return render_template(
        "owasp/a07_sessions.html",
        active_page="a07_sessions",
        mode=mode,
        action=action,
        session_id=result["session_id"],
        before_session_id=result["before_session_id"],
        username=username,
        result=result,
    )

@app.route("/owasp/a07/jwt-auth", methods=["GET", "POST"])
def jwt_auth_failures():
    token = make_demo_jwt()
    mode = "unsafe"
    action = "original"

    if request.method == "POST":
        token = request.form.get("token", token)
        mode = request.form.get("mode", "unsafe")
        action = request.form.get("action", "verify")

        if action == "tamper_none":
            token = tamper_jwt_to_admin(token, "none")
        elif action == "tamper_hs256":
            token = tamper_jwt_to_admin(token, "HS256")

    result = verify_demo_jwt(token, mode)

    authenticated_user = result["payload"].get("sub") if result["payload"] else None
    authenticated_role = result["payload"].get("role") if result["payload"] else None

    return render_template(
        "owasp/a07_jwt.html",
        active_page="a07_jwt",
        token=token,
        mode=mode,
        result=result,
        authenticated_user=authenticated_user,
        authenticated_role=authenticated_role,
    )

def harmless_demo_trigger():
    return {
        "status": "executed",
        "message": "Harmless demo function triggered during deserialization."
    }


class DemoPayload:
    def __reduce__(self):
        return harmless_demo_trigger, ()


@app.route("/owasp/a08/deserialization")
def a08_pickle_demo():
    return render_template(
        "owasp/a08/deserialization.html",
        active_page="a08_pickle",
    )


@app.route("/owasp/a08/cdn-integrity")
def a08_cdn_demo():
    return render_template(
        "owasp/a08/cdn_integrity.html",
        active_page="a08_cdn",
    )

@app.route("/a08/pickle/generate", methods=["GET"])
def a08_generate_pickle_payload():
    payload = pickle.dumps(DemoPayload())
    encoded = base64.b64encode(payload).decode("utf-8")

    return jsonify({
        "payload": encoded,
        "explanation": "This payload calls a harmless server-side function when deserialized."
    })


@app.route("/a08/pickle/vulnerable", methods=["POST"])
def a08_vulnerable_pickle():
    data = request.get_json(silent=True) or {}
    encoded_payload = data.get("payload", "")

    try:
        raw_payload = base64.b64decode(encoded_payload)
        result = pickle.loads(raw_payload)

        return jsonify({
            "mode": "vulnerable",
            "result": result,
            "lesson": "The application trusted serialized data and executed behavior embedded in it."
        })

    except Exception as e:
        return jsonify({
            "mode": "vulnerable",
            "error": str(e)
        }), 400


@app.route("/a08/pickle/safe", methods=["POST"])
def a08_safe_deserialization():
    data = request.get_json(silent=True) or {}
    encoded_payload = data.get("payload", "")

    try:
        raw_payload = base64.b64decode(encoded_payload)
        parsed = json.loads(raw_payload.decode("utf-8"))

        return jsonify({
            "mode": "safe",
            "result": parsed,
            "lesson": "JSON data was parsed as plain data. No object behavior was restored."
        })

    except Exception:
        return jsonify({
            "mode": "safe",
            "error": "Rejected: expected JSON data, not native serialized objects."
        }), 400


@app.route("/a08/cdn/script")
def a08_cdn_script():
    compromised = request.args.get("compromised") == "true"
    filename = "compromised-lib.js" if compromised else "trusted-lib.js"
    return send_from_directory("static/a08", filename)

@app.route("/owasp/a09", methods=["GET", "POST"])
def logging_failures():
    mode = "unsafe"
    if request.method == "POST":
        mode = request.form.get("mode", "unsafe")

    events, logs, detection, detection_class = simulate_logging(mode)

    return render_template(
        "owasp/a09.html",
        active_page="a09",
        mode=mode,
        events=events,
        logs=logs,
        detection=detection,
        detection_class=detection_class,
    )

def simulate_fail_open_auth(auth_service_state, user_role, mode):
    decision_steps = []

    try:
        decision_steps.append("1. User requests admin resource ✅")
        decision_steps.append("2. Application calls authorization service ✅")

        if auth_service_state == "down":
            raise ConnectionError("Authorization service timeout")

        is_admin = user_role == "admin"
        decision_steps.append("3. Authorization service returned a decision ✅")

    except Exception as exc:
        decision_steps.append(f"3. Authorization service failed: {exc} ⚠️")

        if mode == "unsafe":
            is_admin = True
            decision_steps.append("4. Exception handler defaults to allow ❌")
        else:
            is_admin = False
            decision_steps.append("4. Exception handler defaults to deny ✅")

    if is_admin:
        admin_panel_visible = True

        if auth_service_state == "down":
            result = "⚠️ Access granted — failure path allowed the user into the admin panel!"
            result_class = "success"
        elif user_role == "admin":
            result = "✅ Access granted — authorization service confirmed admin role"
            result_class = "success"
        else:
            result = "⚠️ Access granted — unexpected authorization decision"
            result_class = "success"

    else:
        admin_panel_visible = False

        if auth_service_state == "down":
            result = "❌ Access denied — system failed closed"
            result_class = "fail"
        else:
            result = "❌ Access denied — user is not an admin"
            result_class = "fail"

    return {
        "result": result,
        "result_class": result_class,
        "decision_steps": decision_steps,
        "admin_panel_visible": admin_panel_visible,
        "auth_service_state": auth_service_state,
        "user_role": user_role,
        "mode": mode,
    }


@app.route("/owasp/a10/fail-open", methods=["GET", "POST"])
def a10_fail_open_demo():
    auth_service_state = "down"
    user_role = "user"
    mode = "unsafe"

    if request.method == "POST":
        auth_service_state = request.form.get("auth_service_state", "down")
        user_role = request.form.get("user_role", "user")
        mode = request.form.get("mode", "unsafe")

    result = simulate_fail_open_auth(auth_service_state, user_role, mode)

    return render_template(
        "owasp/a10_fail_open.html",
        active_page="a10_fail_open",
        auth_service_state=auth_service_state,
        user_role=user_role,
        mode=mode,
        result=result,
    )


def simulate_error_disclosure(error_type, mode):
    fake_request_id = "REQ-A10-8f4c2"

    internal_details = {
        "stack_trace": (
            "Traceback (most recent call last):\n"
            "  File \"/srv/app/shop/views.py\", line 88, in checkout\n"
            "    order = db.session.query(Order).filter_by(id=order_id).one()\n"
            "  File \"/srv/app/.venv/lib/python3.12/site-packages/sqlalchemy/orm/query.py\", line 2798, in one\n"
            "    raise NoResultFound(\"No row was found\")\n"
            "sqlalchemy.exc.NoResultFound: No row was found"
        ),
        "environment": (
            "FLASK_DEBUG=true\n"
            "DATABASE_URL=postgresql://shop_user:SuperSecretDemoPassword@db.internal:5432/shop\n"
            "JWT_SECRET=classroom-demo-secret\n"
            "APP_ENV=development"
        ),
        "file_paths": (
            "/srv/app/shop/views.py\n"
            "/srv/app/config.py\n"
            "/srv/app/.env\n"
            "/srv/app/.venv/lib/python3.12/site-packages/"
        ),
    }

    if error_type == "db":
        exception_name = "sqlalchemy.exc.NoResultFound"
        trigger = "/checkout?order_id=999999"
    elif error_type == "null":
        exception_name = "AttributeError: 'NoneType' object has no attribute 'role'"
        trigger = "/admin/profile?user_id=deleted-user"
    else:
        exception_name = "ValueError: invalid literal for int() with base 10"
        trigger = "/invoice?id=abc"

    if mode == "unsafe":
        result = "⚠️ Detailed error exposed to the browser"
        result_class = "success"
        user_message = (
            "Debug page visible. Stack trace, internal paths, framework details, "
            "and environment-like secrets are shown to the user."
        )
        exposed_details = internal_details
        decision_steps = [
            "1. Unexpected input triggers exception ✅",
            "2. Application catches nothing / debug handler activates ⚠️",
            "3. Framework renders detailed debug page ❌",
            "4. Attacker learns internals, paths, secrets, and dependencies ⚠️",
        ]
    else:
        result = "✅ Generic error shown — details kept server-side"
        result_class = "success"
        user_message = f"Something went wrong. Please contact support with request ID {fake_request_id}."
        exposed_details = None
        decision_steps = [
            "1. Unexpected input triggers exception ✅",
            "2. Application handles error centrally ✅",
            "3. User receives generic message ✅",
            "4. Detailed diagnostics are logged server-side only ✅",
        ]

    return {
        "result": result,
        "result_class": result_class,
        "user_message": user_message,
        "exposed_details": exposed_details,
        "decision_steps": decision_steps,
        "exception_name": exception_name,
        "trigger": trigger,
        "request_id": fake_request_id,
        "mode": mode,
        "error_type": error_type,
    }


@app.route("/owasp/a10/error-disclosure", methods=["GET", "POST"])
def a10_error_disclosure_demo():
    error_type = "db"
    mode = "unsafe"

    if request.method == "POST":
        error_type = request.form.get("error_type", "db")
        mode = request.form.get("mode", "unsafe")

    result = simulate_error_disclosure(error_type, mode)

    return render_template(
        "owasp/a10_error_disclosure.html",
        active_page="a10_error_disclosure",
        error_type=error_type,
        mode=mode,
        result=result,
    )


if __name__ == "__main__":
    app.run(debug=True)