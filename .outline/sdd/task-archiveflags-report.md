`git archive` now serves `--prefix`, `-o`, paths, `ssh://`/`git://` (3adf2e4, c1c6953, a722a93).
Whole-tree servers stay untouched; the verb rewrites the tar client-side (prefix with pax tracking, path filter keeping parents, `g` verbatim).
`--format=zip` refused naming its missing writer; no zip crate in deps.
SSH/git arms via new `net::{open_archive_stream,fetch_archive_stream}` on `Service::UploadArchive`; local/smart-http byte-identical un-narrowed.
13 CLI + 4 rewrap-unit + 1 ssh-duplex tests green; `cargo check --tests` clean.
Product defect, out of scope: `FileMode::from_octal` refuses `040000`, so no commit with a subdir builds end-to-end; dirs covered by synthetic-tar unit tests only.
