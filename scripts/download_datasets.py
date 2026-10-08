"""Download the public evaluation datasets into samples/. Run by hand, never by tests.

    uv run python scripts/download_datasets.py

Fills the samples folder (ignored by git, as the raw emails hold real
people's addresses) with one subfolder per label:

    samples/phish/phishing_pot/            from github.com/rf-peixoto/phishing_pot
    samples/ham/spamassassin_easy_ham/     from the SpamAssassin public corpus
    samples/ham/spamassassin_hard_ham/     (hard ham looks like marketing: a good
                                            test of false positives)

Then run the offline evaluation over it:

    uv run phishing-triage-evaluate

phishing_pot is about 1 GB to download, so this takes a while. Each dataset's
folder is emptied and refilled, so rerunning it fetches the latest emails.

The archives are only read, never unpacked with their own paths or run: each
email is copied out under its plain file name, so a crafted archive can't
write outside its folder.
"""

import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from phishing_triage.providers.transport import USER_AGENT

SAMPLES = Path(__file__).parent.parent / "samples"


@dataclass(frozen=True)
class Dataset:
    label: str  # "phish" or "ham": the samples subfolder it goes in
    name: str  # Its own folder inside that
    url: str


DATASETS = [
    Dataset("phish", "phishing_pot", "https://codeload.github.com/rf-peixoto/phishing_pot/zip/refs/heads/main"),
    Dataset(
        "ham",
        "spamassassin_easy_ham",
        "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    ),
    Dataset(
        "ham",
        "spamassassin_hard_ham",
        "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
    ),
]


def main() -> int:
    for dataset in DATASETS:
        folder = SAMPLES / dataset.label / dataset.name
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "archive"
            print(f"Downloading {dataset.name} from {dataset.url} ...", flush=True)
            _download(dataset.url, archive)
            if folder.exists():
                shutil.rmtree(folder)
            folder.mkdir(parents=True)
            count = 0
            for file_name, content in _emails_in(archive):
                (folder / file_name).write_bytes(content)
                count += 1
        print(f"  saved {count} emails to {folder}")
    print(f"Done. Run: uv run phishing-triage-evaluate {SAMPLES}")
    return 0


def _download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as out:
        shutil.copyfileobj(response, out)


def _emails_in(archive: Path) -> Iterator[tuple[str, bytes]]:
    """Each email in a downloaded archive, as (plain file name, bytes).

    phishing_pot is a zip of the repository, whose emails are in email/*.eml.
    The SpamAssassin corpora are .tar.bz2 files with one email per file, plus
    an index file called "cmds" that isn't an email.
    """
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zipped:
            for info in zipped.infolist():
                path = PurePosixPath(info.filename)
                if not info.is_dir() and path.parent.name == "email" and path.suffix == ".eml":
                    yield path.name, zipped.read(info)
        return

    with tarfile.open(archive, "r:*") as tarred:
        for member in tarred:
            name = PurePosixPath(member.name).name
            if not member.isfile() or name == "cmds" or name.startswith("."):
                continue
            extracted = tarred.extractfile(member)
            if extracted is not None:
                yield name, extracted.read()


if __name__ == "__main__":
    sys.exit(main())
