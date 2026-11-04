//! A process's environment as a question may see it (docs/security.md): every name, the values of a short list of names
//! known not to be secrets, and for the rest something hosts can be compared by that does not reveal the value.
//!
//! A hash has to be keyed, as values are short and guessable: a plain digest of `DB_PASSWORD=hunter2` can be guessed
//! offline. The sensor has no key to do that with: its own key is per host (nothing would compare across hosts) and
//! hidden from questions, and an org's sensors share nothing secret. The collector has one, the org's estate key, and
//! gate 2 already replaces what gate 1 marks `action: hash` with an HMAC under it. So:
//!
//! - The question gets an opaque token for a value (`«env:hash:3»`), never the value, so a probe cannot leak it in some
//!   other form. A token means nothing outside this run.
//! - At gate 1 a token in a record's value becomes `beat-env-value:<sha256 of the value>`, marked for gate 2. The answer
//!   is sealed to the collector, which replaces it before anything stores or indexes the answer. What leaves the host
//!   is the digest, not the value; only the collector sees the digest, and it does not keep it.
//!
//! An allowed value is still not trusted: option variables carry `-Dspring.datasource.password=...`, and any of them a
//! URL with a password in it. Those are masked here, before the question sees them, and gate 1 scans what it emits.

use std::sync::OnceLock;

use regex::Regex;

use crate::builtins::RunState;

/// Names whose values are shown. LC_* too. These are paths, locale and who: no secret belongs in them, and the checks
/// below cover the URL or option that gets put there anyway.
const ALLOWED: [&str; 11] = ["PATH", "PYTHONPATH", "CLASSPATH", "LD_LIBRARY_PATH", "JAVA_HOME", "LANG", "TZ", "HOME", "USER",
                             "PWD", "SHELL"];
/// JVM option variables, shown too, whose values are option lists.
const JVM: [&str; 5] = ["JAVA_OPTS", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CATALINA_OPTS"];
/// What stands where a password was. No digest: this value does not need comparing, and a plain digest could be guessed.
const MASK: &str = "«secret:beat-env-option:masked»";
const SECRET_NAME: &str = "password|passwd|pwd|secret|token|credential|key";

pub fn allowed(name: &str) -> bool {
    ALLOWED.contains(&name) || JVM.contains(&name) || name.starts_with("LC_")
}

/// (name, value) of each `NAME=value` in /proc/<pid>/environ. A name is what precedes the first `=`.
pub fn parse(bytes: &[u8]) -> Vec<(String, String)> {
    bytes.split(|b| *b == 0)
        .filter_map(|e| {
            let e = String::from_utf8_lossy(e);
            let (n, v) = e.split_once('=')?;
            Some((n.to_string(), v.to_string()))
        })
        .collect()
}

fn regexes() -> &'static [Regex; 5] {
    static R: OnceLock<[Regex; 5]> = OnceLock::new();
    R.get_or_init(|| {
        let rx = |s: String| Regex::new(&s).expect("valid");
        [
            // -Da.b.password=x  --db-token=x  -Dx="two words"
            rx(format!(r#"(?i)((?:^|[\s"'])-{{1,2}}[\w.\-:]*(?:{SECRET_NAME})[\w.\-]*=)("(?:[^"\\]|\\.)*"|'[^']*'|[^\s"']*)"#)),
            // --db-password hunter2
            rx(format!(r"(?i)((?:^|\s)-{{1,2}}[\w.\-]*(?:{SECRET_NAME})[\w.\-]*\s+)([^-\s]\S*)")),
            // inside a value: ...?user=a&password=x  -javaagent:/a.jar=token=x,key=y
            rx(format!(r#"(?i)([?&;,=][\w.\-]*(?:{SECRET_NAME})[\w.\-]*=)([^&;,\s"']*)"#)),
            // scheme://user:password@host, the last @ before the path
            Regex::new(r#"(?i)([a-z][a-z0-9+.\-]*://[^/\s:@'"]*:)([^/\s'"]+)(@)"#).expect("valid"),
            // scheme://token@host
            Regex::new(r#"(?i)([a-z][a-z0-9+.\-]*://)([^/\s:@'"]+)(@)"#).expect("valid"),
        ]
    })
}

fn mask_urls(value: &str) -> String {
    let r = regexes();
    let v = r[3].replace_all(value, |c: &regex::Captures| format!("{}{MASK}{}", &c[1], &c[3]));
    r[4].replace_all(&v, |c: &regex::Captures| format!("{}{MASK}{}", &c[1], &c[3])).into_owned()
}

fn mask_options(value: &str) -> String {
    let r = regexes();
    let mut v = value.to_string();
    for rx in &r[..3] {
        v = rx.replace_all(&v, |c: &regex::Captures| format!("{}{MASK}", &c[1])).into_owned();
    }
    v
}

/// The value a question may see for this name, with passwords in it masked; None for a name not known to be safe.
pub fn shown(name: &str, value: &str) -> Option<String> {
    if !allowed(name) {
        return None;
    }
    // URLs first: the option patterns stop at characters a URL's password may hold.
    let v = mask_urls(value);
    Some(if JVM.contains(&name) { mask_options(&v) } else { v })
}

/// The token for a value: the same for equal values in a run.
pub fn token(tokens: &mut Vec<(String, String)>, value: &str) -> String {
    use sha2::Digest;
    let digest: String = sha2::Sha256::digest(value.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    let text = format!("beat-env-value:{digest}");
    if let Some((t, _)) = tokens.iter().find(|(_, d)| *d == text) {
        return t.clone();
    }
    let t = format!("«env:hash:{}»", tokens.len());
    tokens.push((t.clone(), text));
    t
}

/// Tokens in record values become what gate 2 hashes. Only there: a subject, a key or a print() keeps the token, which
/// says nothing. A probe writing a token by hand gets a digest of a value it asked for anyway.
pub fn resolve_tokens(st: &mut RunState) {
    if st.env_tokens.is_empty() {
        return;
    }
    let tokens = std::mem::take(&mut st.env_tokens);
    for r in &mut st.records {
        if r.value.contains("«env:hash:") {
            for (t, d) in &tokens {
                r.value = r.value.replace(t.as_str(), d);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(v: &str) -> String {
        shown("JAVA_OPTS", v).unwrap()
    }

    #[test]
    fn parse_takes_the_first_equals() {
        assert_eq!(parse(b"A=1\0B=x=y\0NOEQUALS\0C=\0"), [("A".into(), "1".into()), ("B".into(), "x=y".into()), ("C".to_string(), String::new())]);
    }

    #[test]
    fn only_known_names_are_shown() {
        for n in ["PATH", "JAVA_OPTS", "PYTHONPATH", "CLASSPATH", "LD_LIBRARY_PATH", "JAVA_HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "HOME",
                  "USER", "PWD", "SHELL", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CATALINA_OPTS"] {
            assert!(shown(n, "/x").is_some(), "{n}");
        }
        for n in ["DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "path", "PATHS", "LCX", "OLDPWD", "MY_JAVA_OPTS", "SOMETHING"] {
            assert_eq!(shown(n, "/x"), None, "{n}");
        }
    }

    /// Each with its password, which must be gone.
    pub const JVM_EXAMPLES: [(&str, &str); 14] = [
        ("-Xmx2g -Dspring.datasource.password=Sup3rS3cret! -Dserver.port=8080", "Sup3rS3cret!"),
        ("-Djavax.net.ssl.keyStorePassword=changeit -Dfile.encoding=UTF-8", "changeit"),
        ("-Djavax.net.ssl.trustStorePassword=hunter2", "hunter2"),
        ("-Dapi.token=abc123def", "abc123def"),
        ("-Daws.secretKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"),
        ("-Dapp.credentials=alice:pa55", "alice:pa55"),
        ("-Dmail.smtp.passwd=letmein", "letmein"),
        ("-Ddb.pwd=tiger", "tiger"),
        ("-Dfoo.password=\"two words\" -Dbar=1", "two words"),
        ("-Dfoo.password='single quoted' -Dbar=1", "single quoted"),
        ("--db-password hunter3 --other", "hunter3"),
        ("--api-key=k3y", "k3y"),
        ("-Djdbc.url=jdbc:postgresql://db/app?user=app&password=s3cr3t&ssl=true", "s3cr3t"),
        ("-javaagent:/opt/dd.jar=api_key=abcd1234,service=x", "abcd1234"),
    ];

    #[test]
    fn jvm_options_lose_their_passwords_and_keep_the_rest() {
        for (v, secret) in JVM_EXAMPLES {
            let out = opts(v);
            assert!(!out.contains(secret), "{v} -> {out}");
            assert!(out.contains(MASK), "{v} -> {out}");
        }
        let out = opts(JVM_EXAMPLES[0].0);
        assert!(out.contains("-Xmx2g") && out.contains("-Dserver.port=8080") && out.contains("-Dspring.datasource.password="), "{out}");
        for keep in ["-Xmx2g -XX:+UseG1GC -Dfile.encoding=UTF-8 -Dserver.port=8080", "-cp /a:/b -Dlog.dir=/var/log"] {
            assert_eq!(opts(keep), keep);
        }
    }

    #[test]
    fn urls_lose_their_credentials_in_any_allowed_value() {
        for (name, v, secret) in [("CLASSPATH", "https://user:pa55w0rd@repo.example.com/lib.jar", "pa55w0rd"),
                                  ("PYTHONPATH", "git+https://ghp_token123@github.com/org/repo", "ghp_token123"),
                                  ("JAVA_OPTS", "-Ddb.url=jdbc:mysql://root:p@ss@db:3306/app", "p@ss"),
                                  ("PATH", "/bin:ftp://me:mine@host/x", "mine")] {
            let out = shown(name, v).unwrap();
            assert!(!out.contains(secret), "{v} -> {out}");
        }
        assert_eq!(shown("PATH", "/usr/bin:/bin").unwrap(), "/usr/bin:/bin");
        assert_eq!(shown("CLASSPATH", "https://repo.example.com:8443/lib.jar").unwrap(), "https://repo.example.com:8443/lib.jar");
    }

    #[test]
    fn a_plain_path_is_left_alone_outside_option_variables() {
        assert_eq!(shown("HOME", "/home/key=1").unwrap(), "/home/key=1");
    }

    #[test]
    fn tokens_hide_the_value_and_resolve_only_in_values() {
        let mut st = RunState::default();
        let a = token(&mut st.env_tokens, "hunter2");
        assert_eq!(a, token(&mut st.env_tokens, "hunter2"), "equal values, one token");
        assert_ne!(a, token(&mut st.env_tokens, "other"));
        assert!(!a.contains("hunter2"));
        st.records.push(crate::builtins::Record { subject: a.clone(), key: "k".into(), value: format!("x {a}"), source: "s".into(), span: "".into(), kind: None });
        resolve_tokens(&mut st);
        assert!(st.records[0].value.starts_with("x beat-env-value:") && st.records[0].value.len() == 2 + 15 + 64, "{}", st.records[0].value);
        assert_eq!(st.records[0].subject, a);
        assert!(!st.records[0].value.contains("hunter2"));
    }

    /// For the report: what the rules alone (gate 1) would have done with these. Run with --nocapture.
    #[test]
    fn what_gate_1_alone_catches() {
        let rules = crate::secrets::rules();
        for (v, secret) in JVM_EXAMPLES {
            let f = rules.scan(v);
            let hit: Vec<String> = f.iter().filter(|f| v[f.start..f.end].contains(secret) || secret.contains(&v[f.start..f.end]))
                .map(|f| format!("{}:{}", rules.id(f.rule), rules.action(f.rule))).collect();
            println!("GATE1 {v:?} -> {hit:?}");
        }
    }

    #[test]
    fn the_digest_is_only_marked_for_gate_2() {
        let rules = crate::secrets::rules();
        let text = "beat-env-value:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let found = rules.scan(text);
        assert!(found.iter().any(|f| rules.id(f.rule) == "beat-env-value" && rules.action(f.rule) == "hash"));
        assert!(found.iter().all(|f| rules.action(f.rule) != "mask"), "no plain-digest mask of it");
    }
}
