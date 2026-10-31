"""nginx config files: the main file, every file its include lines match, and the directives that matter.

Applies to: Debian/Ubuntu nginx layout.
Assumes: config at /etc/nginx/nginx.conf.
Cannot see: includes nested deeper than one level.
"""

CONF = "/etc/nginx/nginx.conf"
DIRECTIVES = ["listen", "server_name", "ssl_certificate", "ssl_certificate_key", "user", "worker_processes"]

def config_files(conf: str) -> list[str]:
    files = {conf: None}  # a dict keeps order and drops duplicates
    for line in read(conf).splitlines():
        m = re_match(r"^\s*include\s+([^;]+);", line)
        if m:
            pat = m[1] if m[1].startswith("/") else path_join(path_dirname(conf), m[1])
            for f in glob(pat):  # no match: [] (sh gives the pattern back)
                files[f] = None
    return list(files)

def directives(f: str) -> None:
    for n, line in enumerate(read(f).splitlines()):
        m = re_match(r"^\s*([a-z_]+)\s+([^;#]*[^;#\s])\s*;", line)
        if m and m[1] in DIRECTIVES:
            emit("file:" + f, m[1], m[2], "%s:%d" % (f, n + 1))

def main() -> None:
    s = stat(CONF)
    expect(s != None and s.readable, "nginx config %s not readable" % CONF)
    files = config_files(CONF)
    for f in files:
        s = stat(f)
        emit("unit:nginx.service", "loads", "file:" + f, CONF)
        emit("file:" + f, "mtime", iso_utc(s.mtime), "stat")
        emit("file:" + f, "sha256", pipe(["sha256sum", f]).stdout[:16], "sha256sum")
    each(files, directives)
