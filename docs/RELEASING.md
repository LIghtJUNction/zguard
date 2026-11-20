# Publishing and recovering releases

A release uses an immutable version tag. Its `vMAJOR.MINOR.PATCH` value must
match Cargo.toml, and the checked-out commit must match that exact tag. The
source tree must have no tracked modifications. The workflow resolves the
commit once, validates it on Linux, Windows and macOS, then publishes that
same commit.

## Package and registry

The release script explicitly runs `cargo package --locked` and reads Cargo's
`metadata.target_directory` to locate the resulting archive. It does not depend
on a publish command retaining a temporary archive or on a fixed build path.

`python3 scripts/release.py publish` computes the archive's SHA-256 and checks
the exact crates.io version before uploading. An already published matching
checksum completes this step without another upload. A different checksum
stops the release. Only an HTTP 404 is treated as an absent registry version;
network failures, permission errors and malformed metadata remain errors.

After a new upload, the registry checksum must match before publication is
accepted. If another publisher completed the same archive concurrently, the
same checksum check allows recovery. An upload error with no matching published
archive remains a failure.

## GitHub artifact

`python3 scripts/release.py github` rebuilds the archive and requires its checksum
to match the published crate. It then creates the GitHub release or replaces
the same named asset on an existing release with those verified bytes. Failed
GitHub metadata reads do not start an upload.

Both commands use `ZGUARD_RELEASE_TAG` for the exact selected tag. The workflow
provides registry credentials only to the publication step and GitHub write
credentials only where release creation or asset upload is needed.

## Existing tags

Tags preserve their original scripts as well as the Rust source. Updating main
does not update scripts inside an older tag, and manually selecting an old tag
from a newer workflow can still run that tag's older code. Keep published tags
fixed. Recover an older GitHub artifact from the original source and published
registry bytes with explicit checksum and source verification; do not attach a
newly modified package under an already published version.

The script regression suite runs without network access or remote mutations:

```sh
python3 -B -m unittest discover -s tests -p test_release.py -v
```

It covers configured target directories, absent artifacts, registry conflicts,
transient visibility, concurrent publication, existing GitHub releases,
metadata failures and immutable-tag checks.
