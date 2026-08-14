"""Complete, code-level remediation for every vulnerability class Danger Mode reports.

A finding that says "use parameterized queries" is not actionable. Each entry
here gives the failing pattern, the corrected pattern in the languages teams
actually use, the configuration change where one applies, and how to verify the
fix held. Text is plain ASCII so it survives the PDF renderer unchanged.
"""

from __future__ import annotations

REMEDIATION: dict[str, str] = {
    # ── Injection ────────────────────────────────────────────────────────────
    "sql_injection": """ROOT CAUSE
User input is concatenated into a SQL statement, so the database parses attacker
text as code rather than treating it as a value.

THE FIX - parameterize every query. Never build SQL with string operations.

Python (psycopg / sqlite3 / MySQLdb):
    # VULNERABLE
    cur.execute("SELECT * FROM orders WHERE id = " + user_id)
    cur.execute(f"SELECT * FROM orders WHERE id = {user_id}")
    # FIXED
    cur.execute("SELECT * FROM orders WHERE id = %s", (user_id,))

Python (SQLAlchemy):
    # VULNERABLE
    session.execute(text(f"SELECT * FROM orders WHERE id = {user_id}"))
    # FIXED
    session.execute(text("SELECT * FROM orders WHERE id = :id"), {"id": user_id})
    session.query(Order).filter(Order.id == user_id)      # ORM is safe

PHP (PDO):
    // VULNERABLE
    $db->query("SELECT * FROM users WHERE email = '$email'");
    // FIXED
    $stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$email]);

Node.js (mysql2 / pg):
    // VULNERABLE
    db.query(`SELECT * FROM users WHERE id = ${id}`);
    // FIXED
    db.query("SELECT * FROM users WHERE id = ?", [id]);          // mysql2
    db.query("SELECT * FROM users WHERE id = $1", [id]);         // pg

Java (JDBC):
    // VULNERABLE
    stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    // FIXED
    PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
    ps.setInt(1, Integer.parseInt(id));

C# (ADO.NET):
    // FIXED
    cmd.CommandText = "SELECT * FROM users WHERE id = @id";
    cmd.Parameters.AddWithValue("@id", id);

IDENTIFIERS CANNOT BE PARAMETERIZED
Table names, column names, and ORDER BY direction must come from an allow-list:
    SORT_COLUMNS = {"created": "created_at", "name": "display_name"}
    column = SORT_COLUMNS.get(request.args.get("sort"), "created_at")
    direction = "DESC" if request.args.get("dir") == "desc" else "ASC"
    query = f"SELECT * FROM items ORDER BY {column} {direction}"   # both values are ours

DEFENCE IN DEPTH
1. Give the application database account only the rights it needs. It should not
   own DDL, and it should not read tables it never touches.
2. Turn off verbose database errors in production; return a generic message and
   log the detail server-side.
3. Add a query timeout so one request cannot pin a connection.
4. Deploy a WAF rule as a speed bump only - it is not the fix.

VERIFY
Re-run the boolean-differential probe from the evidence. The TRUE and FALSE
conditions must now return byte-identical responses. Confirm the arithmetic
probe (for example id=3-2) no longer renders the same record as id=1.""",

    "command_injection": """ROOT CAUSE
User input reaches a shell. The shell splits on metacharacters (; | & $ ` newline),
so any of them turn data into a second command.

THE FIX - do not invoke a shell. Pass an argument array to the OS directly.

Python:
    # VULNERABLE - shell=True parses the whole string
    subprocess.run(f"ping -c 1 {host}", shell=True)
    os.system("ping -c 1 " + host)
    # FIXED - no shell, host can never become a command
    subprocess.run(["ping", "-c", "1", host], shell=False, timeout=5, check=False)

Node.js:
    // VULNERABLE
    child_process.exec(`ping -c 1 ${host}`);
    // FIXED
    child_process.execFile("ping", ["-c", "1", host], {timeout: 5000});

PHP:
    // VULNERABLE
    shell_exec("ping -c 1 " . $host);
    // FIXED
    $safe = escapeshellarg($host);
    shell_exec("ping -c 1 " . $safe);
    // BETTER: avoid the shell entirely
    proc_open(["ping", "-c", "1", $host], $descriptors, $pipes);

Java:
    // VULNERABLE
    Runtime.getRuntime().exec("ping -c 1 " + host);
    // FIXED
    new ProcessBuilder("ping", "-c", "1", host).start();

Go:
    // FIXED - exec.Command does not use a shell
    exec.Command("ping", "-c", "1", host).Output()

VALIDATE THE VALUE TOO
Argument arrays stop command injection but not argument injection (a value
starting with "-" can become a flag). Validate against a strict pattern:
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
        raise ValueError("invalid host")

PREFER A LIBRARY OVER A PROCESS
Most shell calls have a native equivalent: use an HTTP client instead of curl, an
image library instead of ImageMagick's CLI, a DNS library instead of dig.

CONTAIN THE BLAST RADIUS
1. Run the worker as an unprivileged user with a read-only filesystem.
2. Apply egress filtering so the host cannot open arbitrary outbound connections -
   this is what stops a confirmed injection becoming an interactive shell.
3. Drop Linux capabilities and enable no-new-privileges on the container.

VERIFY
Re-send the arithmetic probe from the evidence. The response must no longer
contain the computed product, and the literal payload should be rejected or
treated as a single opaque argument.""",

    "xss": """ROOT CAUSE
User input is written into a page without encoding for the context it lands in,
so the browser parses it as markup or script.

THE FIX - encode on output, for the specific context.

Use a template engine that escapes by default and stop disabling it:
    Jinja2/Django : {{ value }}  is safe;  {{ value|safe }} and |striptags are not
    React         : {value}      is safe;  dangerouslySetInnerHTML is not
    Vue           : {{ value }}  is safe;  v-html is not
    Angular       : {{ value }}  is safe;  [innerHTML] and bypassSecurityTrust* are not

CONTEXT MATTERS - HTML escaping is wrong in three of these four places:
    HTML body      -> HTML-encode  < > & " '
    HTML attribute -> HTML-encode AND always quote the attribute
    JavaScript     -> JSON-encode; never interpolate into a script block
    URL            -> percent-encode; validate the scheme is http or https

Passing data into JavaScript - do not build script text:
    <!-- VULNERABLE -->
    <script>var user = "{{ username }}";</script>
    <!-- FIXED: serialize as data, read it as data -->
    <script id="app-data" type="application/json">{{ data|tojson }}</script>
    <script>const data = JSON.parse(document.getElementById("app-data").textContent);</script>

Server-side examples:
    Python  : from markupsafe import escape;  escape(value)
    PHP     : htmlspecialchars($v, ENT_QUOTES | ENT_HTML5, "UTF-8")
    Java    : org.owasp.encoder.Encode.forHtml(value)
    Node    : use the template engine's escaping; do not concatenate HTML

IF YOU MUST ACCEPT RICH TEXT
Sanitize with a vetted allow-list library, never a regex or a blocklist:
    Python : bleach.clean(html, tags=ALLOWED, attributes=ALLOWED_ATTRS, strip=True)
    Node   : DOMPurify.sanitize(html)
    Java   : OWASP Java HTML Sanitizer

CONTENT SECURITY POLICY - the safety net that turns an XSS into a blocked error
    Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-<random>';
      object-src 'none'; base-uri 'none'; require-trusted-types-for 'script'
Generate a fresh nonce per response. Do not use 'unsafe-inline' - it disables the
protection entirely.

COOKIES
Set HttpOnly so script cannot read the session, Secure so it is HTTPS-only, and
SameSite=Lax or Strict.

VERIFY
Re-send the payload from the evidence and view the raw response. The characters
listed as unescaped must now appear as &lt; &gt; &quot; &#x27;. Confirm the CSP
header is present and has no 'unsafe-inline'.""",

    "ssti": """ROOT CAUSE
User input is used as template *source* rather than as template *data*, so the
engine compiles and evaluates it.

THE FIX - never render user input as a template.

    # VULNERABLE - the input becomes template source
    Template("Hello " + user_name).render()
    render_template_string(f"<h1>Welcome {user_name}</h1>")
    # FIXED - a fixed template with the input passed as a variable
    render_template("welcome.html", name=user_name)
    Template("Hello {{ name }}").render(name=user_name)

Node (Handlebars / EJS / Pug):
    // VULNERABLE
    ejs.render(userSuppliedTemplate, data);
    // FIXED
    ejs.renderFile("views/welcome.ejs", {name: userName});

Java (Thymeleaf / Freemarker / Velocity):
    // VULNERABLE - expression is parsed from a request value
    templateEngine.process(userSuppliedFragment, context);
    // FIXED
    templateEngine.process("welcome", context);

IF USER-EDITABLE TEMPLATES ARE A PRODUCT REQUIREMENT
1. Use a sandboxed engine designed for it: Jinja2 SandboxedEnvironment,
   Twig SandboxExtension, Liquid, or Handlebars without helpers.
2. Deny access to attribute traversal, imports, and the object graph. In Jinja2
   that means blocking __class__, __globals__, __subclasses__, __mro__, and
   __builtins__.
3. Render in a separate, unprivileged process with a CPU and memory limit.
4. Prefer a data-only format such as Markdown or a fixed placeholder syntax.

VERIFY
Re-send the arithmetic probe from the evidence. The response must contain the
literal expression rather than the computed product.""",

    "path_traversal": """ROOT CAUSE
A user-controlled value is concatenated into a filesystem path, so ../ sequences
escape the intended directory.

THE FIX - resolve the final path and confirm it stays inside the base directory.
Checking for ".." before resolving is not sufficient because encoding, doubled
sequences, and symlinks all defeat it.

Python:
    from pathlib import Path
    BASE = Path("/srv/app/uploads").resolve()
    def safe_path(user_value: str) -> Path:
        candidate = (BASE / user_value).resolve()        # resolve FIRST
        if not candidate.is_relative_to(BASE):           # then contain
            raise ValueError("path escapes the base directory")
        return candidate

Node.js:
    const path = require("path");
    const BASE = path.resolve("/srv/app/uploads");
    function safePath(userValue) {
      const candidate = path.resolve(BASE, userValue);
      if (candidate !== BASE && !candidate.startsWith(BASE + path.sep)) {
        throw new Error("path escapes the base directory");
      }
      return candidate;
    }

Java:
    Path base = Paths.get("/srv/app/uploads").toRealPath();
    Path candidate = base.resolve(userValue).normalize().toRealPath();
    if (!candidate.startsWith(base)) throw new SecurityException("path escape");

PHP:
    $base = realpath("/srv/app/uploads");
    $candidate = realpath($base . DIRECTORY_SEPARATOR . $userValue);
    if ($candidate === false || strpos($candidate, $base . DIRECTORY_SEPARATOR) !== 0) {
        throw new RuntimeException("path escape");
    }

THE STRONGER PATTERN - do not accept paths at all
Store files under generated identifiers and look the path up server-side:
    file = db.files.find_one({"id": request.args["file_id"], "owner": current_user.id})
    return send_file(BASE / file["stored_name"])
This also fixes the authorization problem that usually accompanies traversal.

ALSO
1. Reject null bytes and decode only once; %00 and double-encoding are standard
   bypasses.
2. Serve downloads from a dedicated directory the app cannot write to.
3. Run the process as a user that cannot read /etc/shadow, keys, or config.

VERIFY
Re-send every encoding variant listed in the evidence. All must return a 400 or
404, and none may return content matching the file signature.""",

    "nosql_injection": """ROOT CAUSE
A request value is passed into a query object still typed as an object, so an
attacker can supply a query operator ({"$ne": null}) where a scalar was expected.

THE FIX - cast to the expected scalar type before the value reaches the query.

Node.js / Express + Mongoose:
    // VULNERABLE - req.body.email may be an object
    User.findOne({email: req.body.email, password: req.body.password});
    // FIXED - force a string
    User.findOne({email: String(req.body.email), password: String(req.body.password)});

Validate with a schema so the shape is enforced once, at the edge:
    const {z} = require("zod");
    const LoginSchema = z.object({email: z.string().email(), password: z.string().min(8)});
    const {email, password} = LoginSchema.parse(req.body);   // throws on an object

Express hardening:
    app.use(require("express-mongo-sanitize")());   // strips keys beginning with $ or .

Python / PyMongo:
    email = request.json.get("email")
    if not isinstance(email, str):
        abort(400)
    users.find_one({"email": email})

NEVER USE $where
It evaluates JavaScript server-side. Replace it with a normal query or an
aggregation stage, and disable it at the server with --noscripting.

AUTHENTICATION SPECIFICALLY
Never compare a password inside the database query. Fetch the user by identifier,
then verify with a constant-time password hash comparison (bcrypt/argon2).

VERIFY
Re-send the operator payload from the evidence. It must return 400, and it must
not authenticate or return more records than the scalar value did.""",

    # ── DOM and client side ──────────────────────────────────────────────────
    "dom_xss": """ROOT CAUSE
Client-side script reads an attacker-controlled source (location.hash,
location.search, document.referrer, window.name, postMessage) and writes it to a
sink that parses markup or executes code. The payload may never reach the server,
so server-side filtering and WAF rules cannot see it.

THE FIX - change the sink. This is nearly always a one-line change.

    // VULNERABLE                                  // FIXED
    el.innerHTML = value;                          el.textContent = value;
    el.outerHTML = value;                          el.replaceWith(newNode);
    el.insertAdjacentHTML("beforeend", value);     el.append(document.createTextNode(value));
    document.write(value);                         container.textContent = value;
    eval(value);                                   JSON.parse(value);
    new Function(value)();                         // use a lookup table of allowed actions
    setTimeout("doThing(" + value + ")", 100);     setTimeout(() => doThing(value), 100);
    $("#out").html(value);                         $("#out").text(value);
    location.href = value;                         // validate first, see below
    $(value);                                      $(document.getElementById(value));

Building markup safely:
    const link = document.createElement("a");
    link.textContent = userTitle;      // never innerHTML
    link.href = safeUrl(userHref);     // validated below
    container.append(link);

Validating a URL before navigation or href assignment:
    function safeUrl(value) {
      try {
        const url = new URL(value, location.origin);
        return ["http:", "https:"].includes(url.protocol) ? url.href : "#";
      } catch { return "#"; }
    }
This blocks javascript:, data:, and vbscript: URLs.

IF HTML IS GENUINELY REQUIRED
    el.innerHTML = DOMPurify.sanitize(value, {USE_PROFILES: {html: true}});

TRUSTED TYPES - enforce it browser-side so a regression cannot ship
    Content-Security-Policy: require-trusted-types-for 'script'; trusted-types default

    trustedTypes.createPolicy("default", {
      createHTML: (input) => DOMPurify.sanitize(input),
    });
With this header, assigning a raw string to innerHTML throws instead of executing.

FRAMEWORK NOTES
    React   : avoid dangerouslySetInnerHTML; sanitize if unavoidable
    Vue     : avoid v-html; use {{ }} or v-text
    Angular : avoid bypassSecurityTrustHtml; the default sanitizer is correct

VERIFY
Load the page with the payload in the fragment, for example
  https://target/page#<img src=x onerror=alert(1)>
Nothing should execute, and the value should appear as literal text in the DOM.""",

    "prototype_pollution": """ROOT CAUSE
A recursive merge, deep-assign, or dynamic property write copies attacker-supplied
keys onto an object without rejecting __proto__, constructor, or prototype. Writing
those keys modifies Object.prototype, and every object in the process inherits the
injected property.

THE FIX - reject the dangerous keys, and stop using raw objects as maps.

    const BLOCKED = new Set(["__proto__", "constructor", "prototype"]);
    function safeMerge(target, source) {
      for (const key of Object.keys(source)) {
        if (BLOCKED.has(key)) continue;                 // drop, do not merge
        const value = source[key];
        if (value && typeof value === "object" && !Array.isArray(value)) {
          target[key] = safeMerge(target[key] ?? Object.create(null), value);
        } else {
          target[key] = value;
        }
      }
      return target;
    }

Use a prototype-less object or a Map for anything keyed by user input:
    const store = Object.create(null);   // no prototype to pollute
    const store = new Map();             // better still

Freeze the prototype at process start - cheap and highly effective:
    Object.freeze(Object.prototype);
    Object.freeze(Object.getPrototypeOf({}));

Parsing JSON safely:
    const parsed = JSON.parse(body, (key, value) =>
      BLOCKED.has(key) ? undefined : value);

Query-string parsing: qs and similar libraries create nested objects from
a[b][c]=1. Set a depth limit and reject the blocked keys, or use URLSearchParams.

LIBRARIES
Update lodash (merge, mergeWith, defaultsDeep, set), jQuery ($.extend(true, ...)),
and minimist to versions with prototype-pollution fixes, and add a supply-chain
scanner to CI.

VERIFY
Send a request whose body or query pollutes a property, for example
  {"__proto__": {"polluted": "yes"}}
then confirm that ({}).polluted is still undefined.""",

    "dom_clobbering": """ROOT CAUSE
Named HTML elements become properties of window and document. An element with
id="config" shadows a global named config, so script that reads it receives an
HTMLElement instead of the intended object.

THE FIX
1. Declare globals with let or const in a module scope. Lexical bindings are not
   clobberable, unlike implicit globals and var on window.
       // VULNERABLE                 // FIXED
       var config = window.config;   const config = Object.freeze({...});
2. Check the type before trusting a global:
       if (typeof window.config !== "object" || config instanceof HTMLElement) {
         throw new Error("clobbered global");
       }
3. Sanitize user-influenced HTML with an allow-list that strips id and name:
       DOMPurify.sanitize(html, {FORBID_ATTR: ["id", "name"]});
4. Never resolve configuration or code paths through document.getElementById on
   a name that also exists as a variable.
5. Trusted Types plus a strict CSP prevents the injected markup from landing at all.

VERIFY
Inject <a id="config"> into the page and confirm the application still reads its
real configuration object and does not throw or misbehave.""",

    "postmessage": """ROOT CAUSE
A message event listener trusts data from any window. Any page holding a reference
to this window - an opener, an embedding frame, or a popup it created - can send it
arbitrary data.

THE FIX - validate the origin first, on every message.

    const ALLOWED = new Set(["https://app.example.com", "https://checkout.example.com"]);
    window.addEventListener("message", (event) => {
      if (!ALLOWED.has(event.origin)) return;        // origin check FIRST
      let payload;
      try { payload = JSON.parse(event.data); } catch { return; }
      if (typeof payload?.action !== "string") return;
      handleAction(payload);                          // never eval or innerHTML
    });

Common mistakes to avoid:
    event.origin.indexOf("example.com") > -1     // matches evil-example.com.attacker.tld
    event.origin.endsWith("example.com")          // matches notexample.com
    event.origin !== "null"                       // not a check at all
Compare the full origin for exact equality against an allow-list.

When sending, always name the target origin explicitly:
    // VULNERABLE - delivers to whatever origin now occupies that frame
    frame.postMessage(data, "*");
    // FIXED
    frame.postMessage(data, "https://app.example.com");

Also restrict who may frame you:
    Content-Security-Policy: frame-ancestors 'self' https://trusted.example.com

VERIFY
From an unrelated origin, open the page and post a message. The handler must
ignore it entirely.""",

    # ── Access control and business logic ────────────────────────────────────
    "idor": """ROOT CAUSE
The endpoint authenticates the caller but never checks that the caller owns the
object identified in the request, so changing the identifier returns someone
else's data.

THE FIX - authorize on every object access, scoped to the caller.

    # VULNERABLE - any authenticated user can read any invoice
    @app.get("/api/invoice/<invoice_id>")
    def get_invoice(invoice_id):
        return db.invoices.find_one({"_id": invoice_id})

    # FIXED - ownership is part of the query, so a foreign id returns nothing
    @app.get("/api/invoice/<invoice_id>")
    @login_required
    def get_invoice(invoice_id):
        invoice = db.invoices.find_one({"_id": invoice_id, "owner_id": current_user.id})
        if invoice is None:
            abort(404)          # 404, not 403 - do not confirm the id exists
        return invoice

Make it structural so it cannot be forgotten on the next endpoint:
    # A scoped accessor every handler must go through
    def owned(model, object_id, user):
        obj = model.query.filter_by(id=object_id, owner_id=user.id).first()
        if obj is None:
            abort(404)
        return obj

Framework support:
    Django          : queryset = Invoice.objects.filter(owner=request.user)
    Rails           : current_user.invoices.find(params[:id])
    Spring Security : @PreAuthorize("@ownership.check(#id, authentication)")
    Postgres        : enable row-level security so the database enforces it too

APPLY IT TO EVERY METHOD
Authorization must be identical for GET, POST, PUT, PATCH, and DELETE on the same
resource. Method-specific checks are how bypasses appear.

UNGUESSABLE IDS ARE DEFENCE IN DEPTH, NOT THE CONTROL
Replacing sequential integers with UUIDv4 raises the cost of enumeration but does
not authorize anything. Do both; never do only the UUID.

VERIFY
Authenticate as user A, request an object owned by user B, and confirm the
response is 404 with no body difference from a non-existent id.""",

    "business_logic": """ROOT CAUSE
The workflow's rules are enforced in the client or assumed from request order, so
a caller who sends requests directly can skip steps, reuse one-time values, or
supply quantities and prices the interface would never produce.

THE FIX - re-derive and re-validate every business fact on the server.

1. NEVER TRUST CLIENT-SUPPLIED PRICE, TOTAL, OR DISCOUNT
       # VULNERABLE - the client tells you what to charge
       total = request.json["total"]
       # FIXED - the server computes it from authoritative data
       items = [db.products.get(i["sku"]) for i in request.json["items"]]
       total = sum(p.price * validate_qty(i["qty"]) for p, i in zip(items, request.json["items"]))

2. VALIDATE NUMERIC DOMAIN, NOT JUST TYPE
       def validate_qty(value):
           qty = int(value)                       # rejects "1e5", "0x10", " 1 "
           if not 1 <= qty <= 100:                # negative and zero rejected
               raise ValidationError("quantity out of range")
           return qty
   Use Decimal for money, never float. Reject negative quantities explicitly -
   a negative line item is the classic route to a credit.

3. ENFORCE STATE TRANSITIONS SERVER-SIDE
       ALLOWED = {"cart": {"pending"}, "pending": {"paid", "cancelled"},
                  "paid": {"shipped"}, "shipped": set()}
       if new_state not in ALLOWED[order.state]:
           abort(409)
   Store the state on the server. Never accept the current step from the request.

4. MAKE ONE-TIME ACTIONS ATOMIC AND IDEMPOTENT
       # Single atomic claim - two concurrent requests cannot both succeed
       claimed = db.coupons.update_one(
           {"code": code, "redeemed_by": None},
           {"$set": {"redeemed_by": user.id, "redeemed_at": now}})
       if claimed.modified_count != 1:
           abort(409, "coupon already redeemed")
   Require an Idempotency-Key header on payment and order endpoints and store the
   first response against it.

5. CLOSE RACE WINDOWS
   Use a database transaction with SELECT ... FOR UPDATE, a unique constraint, or
   an atomic conditional update. Check-then-act across two statements is the bug.

6. RATE-LIMIT BY BUSINESS ACTION, NOT ONLY BY IP
   Limit coupon attempts per account, password resets per account, and checkout
   attempts per payment instrument.

7. RE-AUTHORIZE AT EVERY STEP
   A caller who owns step 1 does not automatically own step 3. Check ownership and
   state on each request.

VERIFY
Replay the exact request from the evidence. Negative and oversized quantities must
return 400, a tampered price must be ignored in favour of the server total, a
skipped step must return 409, and a replayed one-time action must fail on the
second attempt.""",

    "mass_assignment": """ROOT CAUSE
The handler binds the whole request body onto a model, so a caller can set fields
the interface never exposes - is_admin, role, balance, verified, owner_id.

THE FIX - bind an explicit allow-list. Never pass the raw body to a model.

    # VULNERABLE
    user = User(**request.json)
    Object.assign(user, req.body);
    User.objects.filter(id=uid).update(**request.data)

    # FIXED - name every field you accept
    ALLOWED = {"display_name", "bio", "avatar_url"}
    payload = {k: v for k, v in request.json.items() if k in ALLOWED}
    user = User(**payload)

Framework support:
    Django REST : serializer fields = [...] plus read_only_fields = ["role", "is_admin"]
    Rails       : params.require(:user).permit(:display_name, :bio)
    Spring      : @JsonIgnore on protected fields, or a dedicated request DTO
    Node        : validate with zod/joi and use the parsed result, not req.body
    Mongoose    : strict: true on the schema so unknown keys are dropped

Use a separate DTO for input and output. Reusing the persistence model for request
binding is what creates this class of bug.

VERIFY
Re-send the request with the privileged field from the evidence included. The
response must succeed while leaving that field unchanged in the database.""",

    "auth_weakness": """ROOT CAUSE
The authentication flow is missing a control that is observable from outside:
no CSRF token, no lockout, weak session cookie attributes, or credentials over
plaintext HTTP.

THE FIX

CSRF - use the framework's built-in protection and SameSite cookies:
    Django  : keep CsrfViewMiddleware; include {% csrf_token %} in every form
    Flask   : Flask-WTF CSRFProtect(app)
    Express : csurf middleware, or a double-submit cookie
    Set-Cookie: session=...; SameSite=Lax; Secure; HttpOnly; Path=/
SameSite=Lax alone is not sufficient for cross-site POST protection on older
browsers - keep the token.

CREDENTIAL STORAGE - a slow, salted KDF, never a general-purpose hash:
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    stored = ph.hash(password)
    ph.verify(stored, supplied)          # constant-time
bcrypt with cost >= 12 is acceptable. MD5, SHA-1, and unsalted SHA-256 are not.

PASSWORD POLICY - length and breach-checking beat composition rules:
    minimum 12 characters, no composition requirement, no forced rotation,
    reject anything present in a breach corpus (k-anonymity API).

LOCKOUT AND THROTTLING - per account and per source, with progressive delay:
    attempts 1-3 : no delay
    attempts 4-6 : 2s, 4s, 8s
    attempts 7+  : lock for 15 minutes and alert
Return an identical message and timing for "unknown user" and "wrong password".

SESSION HANDLING
    Rotate the session identifier on login and on privilege change.
    Invalidate server-side on logout; do not rely on cookie expiry.
    Set an absolute lifetime as well as an idle timeout.

MULTI-FACTOR
Offer TOTP or WebAuthn, and require it for administrative roles.

VERIFY
Confirm the login page issues a CSRF token and rejects a request without it,
that the session cookie carries HttpOnly, Secure, and SameSite, and that repeated
failures produce a throttling response.""",

    # ── Configuration and exposure ───────────────────────────────────────────
    "cors": """ROOT CAUSE
The Access-Control-Allow-Origin header reflects the requesting origin, or is a
wildcard alongside credentials, so any site can read authenticated responses on
behalf of a logged-in victim.

THE FIX - allow-list exact origins; never reflect the request origin.

    # VULNERABLE - reflects whatever the attacker sends
    response.headers["Access-Control-Allow-Origin"] = request.headers["Origin"]
    response.headers["Access-Control-Allow-Credentials"] = "true"

    # FIXED
    ALLOWED_ORIGINS = {"https://app.example.com", "https://admin.example.com"}
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"      # required, or caches will cross-serve

Rules that matter:
1. "Access-Control-Allow-Origin: *" with credentials is rejected by browsers, but
   reflecting the origin achieves the same unsafe result - do not do it.
2. Always send "Vary: Origin" when the value depends on the request.
3. Never allow the literal "null" origin; sandboxed frames and local files send it.
4. Match the full origin string. Suffix or substring matching allows
   example.com.attacker.tld.
5. Keep Access-Control-Allow-Methods and -Headers to what the client needs.

Framework config:
    Flask-CORS : CORS(app, origins=["https://app.example.com"], supports_credentials=True)
    Express    : cors({origin: ALLOWED, credentials: true})
    Spring     : @CrossOrigin(origins = "https://app.example.com")

VERIFY
Re-send the request with Origin: https://evil.example. The response must not
contain an Access-Control-Allow-Origin header naming that origin.""",

    "open_redirect": """ROOT CAUSE
A redirect target is taken from the request without validation, so the application
lends its domain to a phishing page and can leak tokens through the referrer.

THE FIX - never redirect to a user-supplied absolute URL.

    # BEST - map an opaque key to a known destination
    DESTINATIONS = {"dashboard": "/app", "billing": "/billing", "help": "/support"}
    return redirect(DESTINATIONS.get(request.args.get("next"), "/app"))

    # ACCEPTABLE - allow relative paths only
    def safe_next(value: str) -> str:
        if not value.startswith("/") or value.startswith("//"):
            return "/app"                 # // is protocol-relative and leaves the site
        return value

    # IF ABSOLUTE URLS ARE REQUIRED - exact host allow-list
    ALLOWED_HOSTS = {"app.example.com", "docs.example.com"}
    parsed = urlparse(value)
    if parsed.scheme in ("http", "https") and parsed.netloc in ALLOWED_HOSTS:
        return redirect(value)
    return redirect("/app")

Bypasses to test against your validator: //evil.com, https:/\\evil.com,
https://example.com@evil.com, https://example.com.evil.com, and encoded variants.
Parse the URL properly - never use startswith on the raw string.

OAuth and SSO redirect_uri must be compared against pre-registered exact values,
including the path.

VERIFY
Request the endpoint with the external URL from the evidence. The response must
redirect to an internal path instead.""",

    "ssrf": """ROOT CAUSE
The server fetches a URL supplied by the caller, so it can be aimed at internal
services, cloud metadata endpoints, or the loopback interface.

THE FIX - resolve, validate, then pin. Validating the hostname alone loses to DNS
rebinding, because the name can resolve differently on the second lookup.

    import ipaddress, socket
    ALLOWED_SCHEMES = {"http", "https"}
    ALLOWED_HOSTS = {"api.partner.com"}          # allow-list beats blocklist

    def safe_fetch(url: str):
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMES or parsed.hostname not in ALLOWED_HOSTS:
            raise ValueError("destination not permitted")
        addresses = {info[4][0] for info in socket.getaddrinfo(parsed.hostname, None)}
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:                  # rejects private, loopback, link-local
                raise ValueError("destination resolves to a non-public address")
        # Connect to the validated IP while preserving Host and TLS SNI, so the
        # name cannot re-resolve between the check and the connection.
        return request_pinned(parsed, sorted(addresses)[0])

Also required:
1. Disable redirect following, or revalidate every hop the same way.
2. Block the cloud metadata addresses explicitly: 169.254.169.254, fd00:ec2::254,
   and metadata.google.internal. On AWS, require IMDSv2.
3. Set a short timeout and a response-size cap.
4. Restrict the schemes: no file://, gopher://, dict://, ftp://.
5. Put egress rules on the fetching service so it can only reach what it needs -
   this is the control that holds when the application check is bypassed.

VERIFY
Re-send the private-address canary from the evidence. The response must be an
error, and it must be indistinguishable in body and timing from a public URL that
does not exist.""",

    "sensitive_data_exposure": """ROOT CAUSE
An endpoint returns more data than the caller is entitled to, or returns
sensitive fields that the interface never displays.

THE FIX

1. SERIALIZE EXPLICITLY - return only the fields the caller needs
       # VULNERABLE - ships every column, including password_hash and internal notes
       return jsonify(user.__dict__)
       # FIXED
       return jsonify({"id": user.id, "display_name": user.display_name})
   Use a response schema (DRF serializer, Pydantic response_model, Rails
   jbuilder) and mark sensitive fields write-only or excluded.

2. AUTHORIZE THE COLLECTION, NOT ONLY THE RECORD
       # VULNERABLE
       return Order.objects.all()
       # FIXED
       return Order.objects.filter(owner=request.user)

3. CAP AND VALIDATE PAGINATION
       limit = min(int(request.args.get("limit", 50)), 100)   # hard ceiling
   Reject limit=0, negative values, and unbounded exports. Rate-limit and audit
   any bulk-export endpoint.

4. MINIMIZE AND MASK
   Return the last four digits of a card, not the number. Do not return full
   dates of birth, government identifiers, or full addresses unless the screen
   requires them.

5. PROTECT IN TRANSIT AND AT REST
   HTTPS with HSTS; encrypt sensitive columns at rest; keep secrets in a manager
   rather than in code, images, or client bundles.

6. NEVER LOG SECRETS
   Redact tokens, passwords, and card data before logging; keep them out of URLs,
   which are recorded by proxies, browsers, and analytics.

VERIFY
Re-request the endpoint and confirm the field names listed in the evidence are
absent, that an unauthenticated request returns 401, and that the pagination
ceiling is enforced.""",

    "misconfiguration": """ROOT CAUSE
A diagnostic, management, or version-control path is reachable without
authentication, disclosing configuration, dependencies, or source history.

THE FIX

1. BLOCK THE PATHS AT THE EDGE
   nginx:
       location ~ /\\.(git|svn|env|htaccess) { deny all; return 404; }
       location ~ ^/(actuator|server-status|debug|phpinfo) { deny all; return 404; }
   Apache:
       RedirectMatch 404 /\\.(git|svn|env)
2. STOP DEPLOYING THEM
   Build from a clean artifact. Add .git, .env, and .svn to .dockerignore and the
   deployment excludes. Serve only a build output directory.
3. DISABLE DEBUG IN PRODUCTION
       Django DEBUG = False;  Flask app.debug = False;  Rails config.consider_all_requests_local = false
       Spring: management.endpoints.web.exposure.include=health
   Return a generic error page and log detail server-side.
4. TURN OFF DIRECTORY INDEXING
       nginx: autoindex off;      Apache: Options -Indexes
5. AUTHENTICATE MANAGEMENT ENDPOINTS
   Bind actuator, metrics, and admin consoles to an internal interface and require
   authentication.
6. ROTATE ANYTHING THAT WAS EXPOSED
   Treat every credential in a reachable .env or repository as compromised.

VERIFY
Request each path from the evidence and confirm a 404 with no body difference from
a random non-existent path.""",

    "weak_tls": """ROOT CAUSE
The server negotiates a deprecated TLS version or serves content over plaintext
HTTP, so traffic can be downgraded or read in transit.

THE FIX

nginx:
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_session_tickets off;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

Apache:
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    SSLHonorCipherOrder off
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

Redirect all HTTP to HTTPS:
    server { listen 80; return 301 https://$host$request_uri; }

Also:
1. Disable TLS 1.0 and 1.1 everywhere, including on APIs and admin hosts.
2. Prefer forward-secret ECDHE suites; disable RC4, 3DES, and CBC-mode suites.
3. Enable OCSP stapling and automate certificate renewal.
4. Submit to the HSTS preload list once includeSubDomains is safe for you.

VERIFY
Re-run the handshake probe from the evidence. TLS 1.0 and 1.1 must fail, and a
plain HTTP request must return a 301 to HTTPS.""",

    "zone_transfer": """ROOT CAUSE
An authoritative name server answers AXFR from any client, handing over the
complete zone in one query.

THE FIX

BIND:
    acl "secondaries" { 203.0.113.10; 203.0.113.11; };
    options { allow-transfer { none; }; };
    zone "example.com" { type master; allow-transfer { secondaries; key transfer-key; }; };

    key "transfer-key" { algorithm hmac-sha256; secret "<generated>"; };

NSD / Knot: restrict provide-xfr / acl to the secondary addresses and require TSIG.

Managed DNS (Route 53, Cloudflare, Azure DNS): AXFR is not exposed; if you also
run a self-hosted secondary, restrict it there.

Also:
1. Prefer TSIG-authenticated transfers over address allow-lists alone.
2. Block TCP/53 from the internet at the firewall except for your secondaries.
3. Review the zone for internal hostnames that should not be in public DNS at all,
   and use split-horizon DNS for internal records.

VERIFY
Run: dig AXFR example.com @ns1.example.com
It must return "Transfer failed" from every address that is not an authorized
secondary.""",

    "missing_rate_limit": """ROOT CAUSE
An authentication or business endpoint accepts unlimited attempts, enabling
credential stuffing, password spraying, enumeration, and one-time-value abuse.

THE FIX - limit by account and by source, with progressive cost.

nginx (edge):
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    location /login { limit_req zone=login burst=3 nodelay; }

Application (per account, which is what stops spraying):
    key = f"login:{username}"
    attempts = redis.incr(key)
    if attempts == 1:
        redis.expire(key, 900)
    if attempts > 5:
        raise TooManyAttempts(retry_after=900)
    # clear on success
    redis.delete(key)

Also:
1. Add exponential backoff, then a lock with an out-of-band unlock.
2. Introduce a CAPTCHA or proof-of-work after a few failures rather than at first
   contact.
3. Keep responses and timing identical for valid and invalid usernames.
4. Alert on distributed low-rate failures across many accounts - that is spraying,
   and per-IP limits will not catch it.
5. Rate-limit password reset, MFA verification, coupon redemption, and checkout
   separately from general API traffic.

VERIFY
Replay the submission burst from the evidence. It must produce 429 with a
Retry-After header before the attempt count in your policy is exceeded.""",

    "monitoring": """ROOT CAUSE
Attack traffic produced no throttling, block, or challenge, and there is no
external signal that the activity was recorded.

THE FIX

1. LOG SECURITY EVENTS WITH ENOUGH CONTEXT TO INVESTIGATE
   Authentication success and failure, authorization denials, input-validation
   rejections, privilege changes, and administrative actions. Record timestamp,
   account, source address, request id, user agent, and outcome.
2. NEVER LOG SECRETS
   Redact passwords, tokens, card numbers, and personal data at the logger.
3. CENTRALIZE AND PROTECT
   Ship to a store the application cannot modify, with retention that matches your
   incident-response needs.
4. ALERT ON PATTERNS, NOT SINGLE EVENTS
   Failure spikes per account and per source, first-time administrative actions,
   authorization denials in bulk, and unusual export volume.
5. MAKE THE RESPONSE OBSERVABLE
   Rate limiting, challenges, and blocks give both the attacker and your telemetry
   a signal that controls exist.
6. TEST DETECTION
   Replay this scan and confirm it appears in your alerting. Detection that is
   never exercised does not work when it matters.

VERIFY
Re-run this assessment and confirm the traffic generated alerts, that the events
are queryable, and that no secret appears in the log records.""",

    "outdated_components": """ROOT CAUSE
A component in use is end-of-life or matches a version with published,
widely exploited weaknesses.

THE FIX

1. CONFIRM THE EXACT VERSION from the package manifest, not the banner. Banners
   are often stale or deliberately misleading.
2. UPGRADE to a supported release. Where a major upgrade is required, apply the
   vendor's backported patch in the interim.
3. AUTOMATE DETECTION - fail the build on known-vulnerable dependencies:
       pip-audit           (Python)
       npm audit --audit-level=high   (Node)
       mvn dependency-check:check     (Java)
       trivy image <image>            (containers)
   Add Dependabot or Renovate for automated upgrade pull requests.
4. GENERATE AN SBOM (CycloneDX or SPDX) per release so you can answer "are we
   affected" in minutes rather than days.
5. REMOVE WHAT YOU DO NOT USE. Unused dependencies carry the same risk.
6. SUPPRESS VERSION DISCLOSURE as defence in depth:
       nginx: server_tokens off;
       Express: app.disable("x-powered-by");

VERIFY
Re-run the fingerprint and the dependency scanner. The flagged version must no
longer be present, and CI must fail if it returns.""",

    "integrity": """ROOT CAUSE
Externally hosted script is loaded without an integrity check, so a compromise of
that host or its CDN executes attacker code with full privileges on your origin.

THE FIX

1. SUBRESOURCE INTEGRITY on every third-party script and stylesheet:
       <script src="https://cdn.example.com/lib.js"
               integrity="sha384-<base64-digest>"
               crossorigin="anonymous"></script>
   Generate the digest:
       openssl dgst -sha384 -binary lib.js | openssl base64 -A
2. PIN EXACT VERSIONS. Never load from a "latest" or floating path - the digest
   will break on every upstream change, which is the point.
3. SELF-HOST WHERE PRACTICAL. It removes the third party from your trust boundary
   and is usually faster than a cross-origin fetch.
4. ENFORCE WITH CSP so an unpinned script cannot be added later:
       Content-Security-Policy: script-src 'self' https://cdn.example.com;
         require-sri-for script style
5. LOCK THE BUILD. Commit the lockfile, enable npm ci, and verify signatures where
   the ecosystem supports them.
6. UNSAFE DESERIALIZATION: never deserialize untrusted input into objects. Use a
   data-only format, enforce a type allow-list, and sign any state that
   round-trips through the client.

VERIFY
Alter one byte of the referenced script in a staging copy and confirm the browser
refuses to execute it.""",

    "xxe": """ROOT CAUSE
The XML parser resolves external entities, so a document can read local files and
make server-side requests.

THE FIX - disable DTDs and external entities in every parser.

Python (defusedxml is the reliable answer):
    from defusedxml.ElementTree import fromstring      # safe by default
    # If you must use lxml:
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)

Java:
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);

PHP:
    libxml_set_external_entity_loader(null);
    $doc = new DOMDocument();
    $doc->loadXML($xml, LIBXML_NONET | LIBXML_DTDLOAD);

.NET:
    var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit,
                                           XmlResolver = null };

Node (libxmljs):
    libxmljs.parseXml(xml, {noent: false, nonet: true, dtdload: false});

ALSO
1. Prefer JSON. If XML is not a requirement, removing it removes the class.
2. Reject any document containing a DOCTYPE declaration at the edge.
3. Apply egress filtering so a parser that does resolve cannot reach internal
   services or the metadata endpoint.
4. Cap document size and nesting depth to prevent entity-expansion denial of
   service.

VERIFY
Re-send the entity probe from the evidence. The parser must reject the DOCTYPE or
leave the entity unexpanded.""",

    "directory_listing": """ROOT CAUSE
The server generates an index page when no default document exists, disclosing
every filename stored under that path.

THE FIX
    nginx  : autoindex off;                       # default, so it was enabled deliberately
    Apache : Options -Indexes
    IIS     : set directoryBrowse enabled="false"
    S3      : block public list permissions; serve through CloudFront with OAC
    Express : express.static(root, {index: false}) and do not use serve-index

Also:
1. Store uploads and backups outside the web root entirely.
2. Serve user files through an authorizing handler rather than as static content.
3. Return an identical 404 for both missing and forbidden paths.

VERIFY
Request the directory from the evidence and confirm it returns 403 or 404 with no
file names in the body.""",

    "verbose_error": """ROOT CAUSE
An unhandled exception is rendered to the client, disclosing stack frames, file
paths, framework versions, and sometimes credentials in a connection string.

THE FIX

    Django  : DEBUG = False; ALLOWED_HOSTS = ["example.com"]
    Flask    : app.debug = False; register an error handler returning a generic page
    Rails    : config.consider_all_requests_local = false
    Express  : add an error middleware that logs and returns a generic 500
    PHP      : display_errors = Off; log_errors = On; error_reporting = E_ALL

    # Example: log the detail, return nothing useful to the caller
    @app.errorhandler(Exception)
    def handle(exc):
        logger.exception("request %s failed", g.request_id)
        return {"error": "Internal server error", "request_id": g.request_id}, 500

Return a request id so support can correlate without exposing internals.

Also:
1. Use identical error responses for "not found" and "not authorized" so errors do
   not confirm which records exist.
2. Strip stack traces from API responses at the gateway as a second layer.

VERIFY
Trigger the same error and confirm the response contains only a generic message
and a request id, while the full trace appears in the server log.""",

    "generic": """GENERAL REMEDIATION
1. Reproduce the observation using the exact request recorded in the evidence.
2. Identify the code path that handles the input and the trust boundary it crosses.
3. Validate input against an allow-list at the boundary, and encode or parameterize
   at the point of use - both, not either.
4. Apply the least-privilege principle to the process, the database account, and
   the network path.
5. Add a regression test that sends this payload and asserts the safe behaviour.
6. Retest from an equivalent network position and confirm the finding is closed.""",
}

#: Finding category -> remediation key.
CATEGORY_MAP: dict[str, str] = {
    "danger_injection_sql": "sql_injection",
    "danger_injection_command": "command_injection",
    "danger_injection_html": "xss",
    "danger_injection_xss": "xss",
    "danger_dom_xss": "dom_xss",
    "danger_injection_ssti": "ssti",
    "danger_injection_xxe": "xxe",
    "danger_injection_nosql": "nosql_injection",
    "danger_path_traversal": "path_traversal",
    "danger_idor": "idor",
    "danger_missing_auth": "idor",
    "danger_business_logic": "business_logic",
    "danger_mass_assignment": "mass_assignment",
    "danger_prototype_pollution": "prototype_pollution",
    "danger_dom_clobbering": "dom_clobbering",
    "danger_postmessage": "postmessage",
    "danger_cors": "cors",
    "danger_open_redirect": "open_redirect",
    "danger_ssrf": "ssrf",
    "danger_data_exposure": "sensitive_data_exposure",
    "danger_misconfiguration": "misconfiguration",
    "danger_sensitive_path": "misconfiguration",
    "danger_directory_listing": "directory_listing",
    "danger_verbose_error": "verbose_error",
    "danger_weak_tls": "weak_tls",
    "danger_plaintext_http": "weak_tls",
    "danger_zone_transfer": "zone_transfer",
    "danger_missing_rate_limit": "missing_rate_limit",
    "danger_monitoring": "monitoring",
    "danger_outdated_components": "outdated_components",
    "danger_integrity": "integrity",
    "danger_deserialization": "integrity",
    "danger_auth_weakness": "auth_weakness",
    "danger_session_cookie": "auth_weakness",
    "danger_insecure_design": "business_logic",
}


def remediation_for(key: str) -> str:
    """Return the full remediation text for a remediation key or finding category."""
    if key in REMEDIATION:
        return REMEDIATION[key]
    mapped = CATEGORY_MAP.get(key)
    if mapped:
        return REMEDIATION[mapped]
    return REMEDIATION["generic"]
