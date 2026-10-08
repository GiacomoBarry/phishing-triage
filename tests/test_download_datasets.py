"""Tests for scripts/download_datasets.py's archive handling, with no network.

The script copies each email out of a downloaded archive under its plain file
name. These tests build tiny archives on disk, including members whose names
try to climb out of the folder ("../../"), and check where the emails land.
"""

import importlib.util
import io
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType

SCRIPT = Path(__file__).parent.parent / "scripts" / "download_datasets.py"


def load_script() -> ModuleType:
    """The script as a module: scripts/ is a folder of scripts, not a package."""
    spec = importlib.util.spec_from_file_location("download_datasets", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def save_emails(archive: Path, folder: Path) -> int:
    count = load_script()._save_emails(archive, folder)
    assert isinstance(count, int)
    return count


def files_under(folder: Path) -> list[str]:
    return sorted(str(path.relative_to(folder)) for path in folder.rglob("*") if path.is_file())


def make_zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zipped:
        for name, content in members.items():
            zipped.writestr(name, content)
    return path


def make_tar(path: Path, members: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w:bz2") as tarred:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tarred.addfile(info, io.BytesIO(content))
    return path


def test_a_zip_member_climbing_out_of_the_folder_lands_inside_it_under_its_plain_name(tmp_path: Path) -> None:
    archive = make_zip(
        tmp_path / "archive",
        {
            "phishing_pot-main/email/sample-1.eml": b"Subject: one\n\nfirst",
            "phishing_pot-main/email/../../../../email/escaped.eml": b"Subject: two\n\nsecond",
        },
    )
    folder = tmp_path / "samples" / "phish" / "phishing_pot"
    folder.mkdir(parents=True)

    count = save_emails(archive, folder)

    assert count == 2
    assert files_under(tmp_path / "samples") == [
        "phish/phishing_pot/escaped.eml",
        "phish/phishing_pot/sample-1.eml",
    ]
    assert (folder / "escaped.eml").read_bytes() == b"Subject: two\n\nsecond"
    assert not (tmp_path / "email").exists()


def test_only_eml_files_in_a_zips_email_folder_are_saved(tmp_path: Path) -> None:
    # phishing_pot's zip also holds its README and other files: they aren't samples.
    archive = make_zip(
        tmp_path / "archive",
        {
            "phishing_pot-main/README.md": b"# phishing_pot",
            "phishing_pot-main/email/notes.txt": b"not an email",
            "phishing_pot-main/email/sample-1.eml": b"Subject: one\n\nfirst",
        },
    )
    folder = tmp_path / "out"
    folder.mkdir()

    assert save_emails(archive, folder) == 1
    assert files_under(folder) == ["sample-1.eml"]


def test_a_tar_member_climbing_out_of_the_folder_lands_inside_it_under_its_plain_name(tmp_path: Path) -> None:
    archive = make_tar(
        tmp_path / "archive",
        {
            "easy_ham/0001.ea7e79d3153e7469e7a9c3e0af6a357e": b"Subject: one\n\nfirst",
            "../../../escaped": b"Subject: two\n\nsecond",
            "/etc/absolute": b"Subject: three\n\nthird",
        },
    )
    folder = tmp_path / "samples" / "ham" / "spamassassin_easy_ham"
    folder.mkdir(parents=True)

    count = save_emails(archive, folder)

    assert count == 3
    assert files_under(tmp_path / "samples") == [
        "ham/spamassassin_easy_ham/0001.ea7e79d3153e7469e7a9c3e0af6a357e",
        "ham/spamassassin_easy_ham/absolute",
        "ham/spamassassin_easy_ham/escaped",
    ]
    assert not (tmp_path.parent / "escaped").exists()


def test_a_tars_cmds_index_and_hidden_files_are_not_saved(tmp_path: Path) -> None:
    archive = make_tar(
        tmp_path / "archive",
        {
            "easy_ham/cmds": b"mv 00001 ...",
            "easy_ham/.DS_Store": b"\x00\x00\x00\x01Bud1",
            "easy_ham/0001.abc": b"Subject: one\n\nfirst",
        },
    )
    folder = tmp_path / "out"
    folder.mkdir()

    assert save_emails(archive, folder) == 1
    assert files_under(folder) == ["0001.abc"]
