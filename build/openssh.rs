use std::path::{Path, PathBuf};

use crate::define_parser::parse_defines;

const OPENSSH_TAG: &str = "V_10_0_P2";

/// Default algorithms for ssh.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MyPrefs {
    pub ca_signature_algorithms: Vec<String>,
    pub ciphers: Vec<String>,
    pub host_key_algorithms: Vec<String>,
    pub kex_algorithms: Vec<String>,
    pub mac: Vec<String>,
    pub pubkey_accepted_algorithms: Vec<String>,
}

pub fn get_my_prefs() -> anyhow::Result<MyPrefs> {
    let out_dir = std::env::var_os("OUT_DIR")
        .map(|s| PathBuf::from(s).join("openssh"))
        .ok_or_else(|| anyhow::anyhow!("OUT_DIR not set"))?;
    let build_dir = out_dir.join("build");
    let inner_dir = build_dir.join("src");

    std::fs::remove_dir_all(&build_dir).ok();
    std::fs::create_dir_all(&inner_dir).ok();

    clone_openssh(&inner_dir)?;

    let my_proposal_path = inner_dir.join("myproposal.h");

    let reader = std::io::BufReader::new(std::fs::File::open(my_proposal_path)?);
    let defines = parse_defines(reader)?;

    let ca_signature_algorithms = defines
        .get("SSH_ALLOWED_CA_SIGALGS")
        .map(|s| s.split_whitespace().map(|s| format!(r#""{s}""#)).collect())
        .unwrap_or_default();

    let ciphers = defines
        .get("KEX_CLIENT_ENCRYPT")
        .map(|s| s.split_whitespace().map(|s| format!(r#""{s}""#)).collect())
        .unwrap_or_default();

    let host_key_algorithms = defines
        .get("KEX_DEFAULT_PK_ALG")
        .map(|s| s.split_whitespace().map(|s| format!(r#""{s}""#)).collect())
        .unwrap_or_default();

    let kex_algorithms = defines
        .get("KEX_CLIENT")
        .map(|s| s.split_whitespace().map(|s| format!(r#""{s}""#)).collect())
        .unwrap_or_default();

    let mac = defines
        .get("KEX_CLIENT_MAC")
        .map(|s| s.split_whitespace().map(|s| format!(r#""{s}""#)).collect())
        .unwrap_or_default();

    let pubkey_accepted_algorithms = defines
        .get("KEX_DEFAULT_PK_ALG")
        .map(|s| s.split_whitespace().map(|s| format!(r#""{s}""#)).collect())
        .unwrap_or_default();

    Ok(MyPrefs {
        ca_signature_algorithms,
        ciphers,
        host_key_algorithms,
        kex_algorithms,
        mac,
        pubkey_accepted_algorithms,
    })
}

fn clone_openssh(path: &Path) -> anyhow::Result<()> {
    let repo_url = "https://github.com/openssh/openssh-portable.git";
    let tag_ref_name = format!("refs/tags/{OPENSSH_TAG}");

    let mut fetch =
        gix::prepare_clone(repo_url, path)?.with_ref_name(Some(tag_ref_name.as_str()))?;

    let (mut checkout, _) =
        fetch.fetch_then_checkout(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)?;
    let (mut repo, _) =
        checkout.main_worktree(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)?;

    repo.committer_or_set_generic_fallback()?;

    let tag_commit_id = {
        let mut tag_ref = repo.find_reference(tag_ref_name.as_str())?;
        tag_ref.peel_to_id_in_place()?.detach()
    };

    use gix::refs::Target;
    use gix::refs::transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog};

    let head: gix::refs::FullName = "HEAD".try_into()?;
    repo.edit_reference(RefEdit {
        change: Change::Update {
            log: LogChange {
                mode: RefLog::AndReference,
                force_create_reflog: false,
                message: format!("checkout: {OPENSSH_TAG}").into(),
            },
            expected: PreviousValue::Any,
            new: Target::Object(tag_commit_id),
        },
        name: head,
        deref: false,
    })?;

    Ok(())
}
