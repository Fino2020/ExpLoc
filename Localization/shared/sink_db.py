"""
Sink database and vulnerability type detection.
Reused from Explainable_Localization/graph_explainer.py.
"""
from typing import Dict, List, Set

SINK_DB: Dict[str, Dict[str, List[str]]] = {
    "xss": {
        "php": ["echo", "print", "printf", "sprintf", "vprintf", "die", "exit",
                 "var_dump", "print_r", "var_export", "header", "setcookie",
                 "setrawcookie", "json_encode", "json_decode"],
        "javascript": ["innerhtml", "outerhtml", "document.write", "document.writeln",
                        "insertAdjacentHTML", "eval", "setTimeout", "setInterval",
                        "html", "append", "prepend", "after", "before", "replaceWith"],
        "python": ["render", "render_template", "write", "send", "json.dumps",
                    "json.loads", "mark_safe", "SafeString", "html", "escape"],
        "ruby": ["html_safe", "raw", "render", "to_s", "concat", "send_data", "send_file"],
        "java": ["println", "printf", "write", "getWriter", "setHeader", "addHeader"],
        "go": ["fmt.Fprint", "fmt.Sprintf", "template.Execute", "http.ResponseWriter",
                "w.Write", "io.WriteString", "json.Marshal", "json.NewEncoder"],
        "rust": ["write!", "println!", "format!", "print!", "respond", "render", "to_string"],
        "perl": ["print", "say", "printf", "sprintf", "cgi->header", "cgi->start_html"],
        "cpp": ["cout", "cerr", "printf", "fprintf", "puts", "send", "write_response"],
        "c": ["printf", "fprintf", "sprintf", "puts", "send", "write_response"],
    },
    "sql_injection": {
        "php": ["mysql_query", "mysqli_query", "pg_query", "sqlite_query",
                 "exec", "query", "execute", "prepare"],
        "javascript": ["query", "execute", "raw", "sequelize.query"],
        "python": ["execute", "executemany", "raw", "cursor.execute", "raw_query"],
        "ruby": ["execute", "find_by_sql", "where", "select_all"],
        "java": ["executeQuery", "executeUpdate", "createStatement", "prepareStatement"],
        "go": ["db.Query", "db.Exec", "db.QueryRow", "db.Prepare"],
        "rust": ["query", "execute", "sql_query"],
        "perl": ["do", "prepare", "execute", "selectall_arrayref"],
        "cpp": ["mysql_query", "sqlite3_exec", "PQexec", "exec"],
        "c": ["mysql_query", "sqlite3_exec", "PQexec"],
    },
    "command_injection": {
        "php": ["exec", "system", "passthru", "shell_exec", "popen", "proc_open",
                 "pcntl_exec", "eval", "assert", "create_function", "preg_replace"],
        "javascript": ["exec", "execSync", "spawn", "child_process.exec", "eval"],
        "python": ["os.system", "os.popen", "subprocess.call", "subprocess.Popen",
                    "subprocess.run", "eval", "exec", "os.exec", "compile"],
        "ruby": ["system", "exec", "spawn", "`", "%x", "eval", "syscall"],
        "java": ["Runtime.exec", "ProcessBuilder", "ScriptEngine.eval"],
        "go": ["exec.Command", "os.StartProcess", "syscall.Exec"],
        "rust": ["Command::new", "std::process::Command", "std::process::output"],
        "perl": ["system", "exec", "qx", "`", "open", "eval"],
        "cpp": ["system", "popen", "exec", "CreateProcess", "ShellExecute"],
        "c": ["system", "popen", "exec", "execve", "execvp", "CreateProcess"],
    },
    "path_traversal": {
        "php": ["include", "require", "include_once", "require_once",
                 "file_get_contents", "fopen", "readfile", "file", "opendir"],
        "javascript": ["fs.readFile", "fs.readFileSync", "fs.createReadStream",
                        "require", "import", "fetch"],
        "python": ["open", "os.path.join", "pathlib.Path", "shutil.copy",
                    "tarfile.extractall", "zipfile.extractall"],
        "ruby": ["File.open", "File.read", "Dir.glob", "IO.read", "open"],
        "java": ["FileInputStream", "FileReader", "File", "Path", "Paths.get"],
        "go": ["os.Open", "ioutil.ReadFile", "os.ReadFile", "filepath.Join"],
        "rust": ["File::open", "std::fs::read", "std::fs::read_to_string"],
        "perl": ["open", "read", "opendir", "readdir"],
        "cpp": ["fopen", "ifstream", "std::ifstream", "open", "read"],
        "c": ["fopen", "open", "read", "opendir", "realpath"],
    },
    "buffer_overflow": {
        "c": ["strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
               "fscanf", "memcpy", "memmove", "memset", "read", "recv", "fread",
               "wcscpy", "wcscat", "lstrcpy", "lstrcat", "CopyMemory"],
        "cpp": ["strcpy", "strcat", "sprintf", "memcpy", "memmove", "std::copy",
                 "std::copy_n", "std::memcpy", "std::strcpy", "std::strcat",
                 "gets", "scanf", "cin.read", "istream::read"],
        "rust": ["copy_from_slice", "ptr::copy", "ptr::copy_nonoverlapping",
                  "std::ptr::copy", "std::ptr::write", "unsafe"],
    },
    "use_after_free": {
        "c": ["free", "realloc", "HeapFree", "delete"],
        "cpp": ["delete", "delete[]", "free", "realloc", "unique_ptr::reset",
                 "shared_ptr::reset", "weak_ptr::lock"],
        "rust": ["drop", "ManuallyDrop", "unsafe", "ptr::drop_in_place"],
    },
    "integer_overflow": {
        "c": ["malloc", "calloc", "realloc", "alloca", "memcpy", "memmove",
               "array", "sizeof", "strlen"],
        "cpp": ["new", "new[]", "malloc", "calloc", "realloc", "std::vector::resize",
                 "std::vector::reserve", "std::string::resize"],
        "rust": ["Vec::with_capacity", "vec!", "Box::new", "unsafe"],
    },
    "null_deref": {
        "c": ["malloc", "calloc", "realloc", "free", "fopen", "opendir"],
        "cpp": ["new", "new[]", "malloc", "dynamic_cast", "static_cast",
                 "reinterpret_cast", "std::shared_ptr::get", "std::unique_ptr::get"],
        "rust": ["unwrap", "expect", "Option::unwrap", "unsafe"],
        "go": ["interface.(type)", "type assertion", "nil deref"],
    },
    "denial_of_service": {
        "c": ["malloc", "calloc", "realloc", "recv", "read", "accept",
               "select", "poll", "epoll_wait", "sleep", "usleep"],
        "cpp": ["new", "new[]", "std::this_thread::sleep_for", "std::thread::join"],
        "python": ["time.sleep", "asyncio.sleep", "socket.recv", "socket.accept"],
        "go": ["time.Sleep", "http.ListenAndServe", "net.Listen", "channel receive"],
        "java": ["Thread.sleep", "Object.wait", "ServerSocket.accept"],
    },
    "deserialization": {
        "php": ["unserialize", "json_decode", "simplexml_load_string",
                 "unserialize_callback_func", "wddx_deserialize"],
        "python": ["pickle.load", "pickle.loads", "yaml.load", "marshal.loads",
                    "json.loads", "cPickle.loads", "dill.loads"],
        "javascript": ["JSON.parse", "eval", "serialize-javascript", "node-serialize"],
        "ruby": ["Marshal.load", "YAML.load", "JSON.parse", "Psych.load"],
        "java": ["ObjectInputStream.readObject", "ObjectInputStream.readUnshared",
                  "XMLDecoder.readObject", "Yaml.load", "Gson.fromJson"],
        "go": ["json.Unmarshal", "gob.NewDecoder", "xml.Unmarshal", "yaml.Unmarshal"],
    },
    "auth_bypass": {
        "php": ["check", "verify", "authenticate", "authorize", "login", "session_start"],
        "python": ["authenticate", "login", "check_password", "verify_token",
                    "check_credentials", "is_authenticated"],
        "javascript": ["authenticate", "verify", "login", "checkPassword", "verifyToken"],
        "go": ["authenticate", "verify", "login", "checkPassword"],
        "java": ["authenticate", "isAuthenticated", "checkPassword", "verify", "login"],
    },
    "information_leak": {
        "php": ["print_r", "var_dump", "debug_backtrace", "phpinfo", "echo", "error_log"],
        "python": ["print", "logging", "debug", "traceback.print_exc", "repr", "str"],
        "javascript": ["console.log", "console.error", "debug", "response.send"],
        "go": ["fmt.Println", "log.Print", "log.Printf", "debug.PrintStack"],
        "java": ["printStackTrace", "System.out.println", "logger.debug", "logger.info"],
    },
    "race_condition": {
        "c": ["pthread_mutex_lock", "pthread_mutex_unlock", "sem_wait", "sem_post",
               "atomic_fetch_add", "atomic_compare_exchange"],
        "cpp": ["std::mutex::lock", "std::mutex::unlock", "std::atomic",
                 "std::lock_guard", "std::unique_lock", "std::shared_lock"],
        "rust": ["Mutex::lock", "RwLock::read", "RwLock::write", "AtomicBool::load",
                  "AtomicBool::store", "unsafe"],
        "go": ["sync.Mutex.Lock", "sync.Mutex.Unlock", "sync.RWMutex.RLock",
                "sync.WaitGroup.Wait", "channel send/receive"],
        "java": ["synchronized", "ReentrantLock.lock", "AtomicInteger", "volatile"],
    },
}

VULN_TYPE_KEYWORDS: Dict[str, List[str]] = {
    "xss": ["xss", "cross-site", "cross site", "scripting", "html injection",
            "html entity", "escape", "sanitize", "sanitise", "output encoding"],
    "sql_injection": ["sql injection", "sqli", "sql query", "database",
                       "prepared statement", "parameterized query"],
    "command_injection": ["command injection", "code injection", "os command",
                           "shell injection", "exec", "remote code execution",
                           "arbitrary code", "rce"],
    "path_traversal": ["path traversal", "directory traversal", "file inclusion",
                        "lfi", "rfi", "../", "local file", "remote file"],
    "buffer_overflow": ["buffer overflow", "buffer overrun", "overflow",
                         "out of bounds", "stack overflow", "heap overflow"],
    "use_after_free": ["use after free", "use-after-free", "uaf",
                        "dangling pointer", "double free"],
    "integer_overflow": ["integer overflow", "integer underflow", "int overflow",
                          "numeric overflow", "wrap around"],
    "null_deref": ["null pointer", "null deref", "nil pointer", "null dereference",
                    "segfault", "segmentation fault"],
    "denial_of_service": ["denial of service", "dos", "ddos", "hang",
                           "resource exhaustion", "infinite loop"],
    "deserialization": ["deserializ", "unserializ", "marshal", "pickle",
                         "yaml load", "object injection"],
    "auth_bypass": ["authentication bypass", "auth bypass", "login bypass",
                     "improper authentication"],
    "information_leak": ["information leak", "information disclosure", "info leak",
                          "exposure", "sensitive data"],
    "csrf": ["csrf", "xsrf", "cross-site request forgery", "request forgery"],
    "race_condition": ["race condition", "race", "toctou", "time of check",
                        "concurrent", "deadlock"],
    "ssrf": ["ssrf", "server-side request forgery"],
    "prototype_pollution": ["prototype pollution", "proto pollution", "__proto__"],
    "xxe": ["xxe", "xml external entity", "xml injection", "xml parsing"],
}

UNIVERSAL_SINKS: Dict[str, List[str]] = {
    "c": ["printf", "fprintf", "sprintf", "malloc", "free", "memcpy"],
    "cpp": ["cout", "printf", "new", "delete", "malloc", "free"],
    "php": ["echo", "exec", "eval", "query", "unserialize"],
    "javascript": ["eval", "exec", "html", "query"],
    "python": ["eval", "exec", "open", "execute"],
    "ruby": ["eval", "exec", "system", "render"],
    "go": ["fmt.Println", "exec.Command", "db.Query"],
    "rust": ["unwrap", "expect", "unsafe", "println!"],
    "java": ["println", "executeQuery", "exec"],
    "perl": ["print", "eval", "system", "open"],
}


def detect_vuln_types(issue_text: str) -> List[str]:
    text_lower = issue_text.lower()
    scores: Dict[str, int] = {}
    for vtype, kws in VULN_TYPE_KEYWORDS.items():
        score = sum(1 for kw in kws if kw.lower() in text_lower)
        if score > 0:
            scores[vtype] = score
    if not scores:
        return ["xss", "command_injection", "path_traversal"]
    return [k for k, _ in sorted(scores.items(), key=lambda x: -x[1])]


def get_sinks_for_vuln_types(vuln_types: List[str], language: str) -> Set[str]:
    sinks: Set[str] = set()
    for vtype in vuln_types:
        type_sinks = SINK_DB.get(vtype, {})
        lang_sinks = type_sinks.get(language, [])
        if not lang_sinks:
            if language == "c" and "cpp" in type_sinks:
                lang_sinks = type_sinks["cpp"]
            elif language == "cpp" and "c" in type_sinks:
                lang_sinks = type_sinks["c"]
        sinks.update(s.lower() for s in lang_sinks)
    if not sinks:
        sinks.update(s.lower() for s in UNIVERSAL_SINKS.get(language, []))
    return sinks
