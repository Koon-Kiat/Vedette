"""Project decisions about the repository's own files: names, pins and wording."""

import re
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

import conventions

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
PROSE = [
    ROOT / "README.md",
    ROOT / "CHANGELOG.md",
    ROOT / "SECURITY.md",
    *sorted((ROOT / "docs").glob("*.md")),
    *sorted((ROOT / "docs" / "ux").glob("*.md")),
    *sorted((ROOT / ".github").glob("*.md")),
]
ROOT_FILES = (
    ".dockerignore",
    ".env.example",
    ".gitattributes",
    ".gitignore",
    ".pre-commit-config.yaml",
    "Dockerfile",
    "README.md",
    "SECURITY.md",
    "config.example.yaml",
    "docker-compose.yml",
    "pyproject.toml",
)
SOURCE_DIRS = ("src", "tests", "tools", ".github", ".githooks")
TEXT_SUFFIXES = {"", ".css", ".html", ".js", ".md", ".py", ".toml", ".txt", ".yaml", ".yml"}
OLD_NAME = re.compile(r"(?<![a-z0-9])sentinel(?![a-z0-9])", re.IGNORECASE)
RENAME_RECORDS = {
    ROOT / "CHANGELOG.md",
    Path(__file__).resolve(),
}
ARCHITECTURE = ROOT / "docs" / "ARCHITECTURE.md"
REPO_PATH = re.compile(r"`((?:src|tests|tools|docs|[.]github|[.]githooks|[.]impeccable)/[^`]+)`")
TEST_NAME = re.compile(r"`(test_[a-z0-9_]+)`")
MARKUP = {".html", ".js", ".css"}
MILESTONE_EXAMPLES = {ROOT / "tests" / "unit" / "test_conventions.py"}
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
REGISTRY_IMAGE = re.compile(
    r"\b(?:ghcr\.io|docker\.io|quay\.io)/[\w./-]+:[\w.-]+(?:@sha256:[0-9a-f]{64})?"
)
COMMIT = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
GITLEAKS = re.compile(r"ghcr\.io/gitleaks/gitleaks:(v[\d.]+)@sha256:[0-9a-f]{64}")


def _text_files() -> Iterator[Path]:
    for name in ROOT_FILES:
        yield ROOT / name
    yield from PROSE
    for directory in SOURCE_DIRS:
        for path in sorted((ROOT / directory).rglob("*")):
            if path.is_file() and path.suffix in TEXT_SUFFIXES and "__pycache__" not in path.parts:
                yield path


def _pyproject() -> dict[str, Any]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def _dependencies() -> dict[str, str]:
    found: dict[str, str] = {}
    for requirement in _pyproject()["project"]["dependencies"]:
        name = re.match(r"[A-Za-z0-9_.-]+", requirement)
        assert name is not None
        found[name.group(0).lower()] = requirement[name.end() :]
    return found


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", PROSE, ids=lambda path: path.relative_to(ROOT).as_posix())
def test_prose_names_the_work_not_the_milestone(path: Path) -> None:
    codes = conventions.MILESTONE_CODE.findall(path.read_text(encoding="utf-8"))
    assert codes == [], (
        f"{path.name} uses milestone codes {sorted(set(codes))}; name the work instead "
        "(scaffold, collector, enrichment and rules, dashboard, ...)."
    )


def test_code_and_configuration_name_the_work_not_the_milestone() -> None:
    found = [
        f"{path.relative_to(ROOT).as_posix()}:{number}"
        for path in _text_files()
        if path.suffix not in MARKUP and path not in MILESTONE_EXAMPLES
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if conventions.MILESTONE_CODE.search(line)
    ]
    assert found == [], (
        f"Milestone codes at {found}; name the work instead "
        "(scaffold, collector, enrichment and rules, dashboard, ...)."
    )


def test_the_old_project_name_is_only_in_the_rename_records() -> None:
    found: list[str] = []
    for path in _text_files():
        if path in RENAME_RECORDS:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if OLD_NAME.search(line):
                found.append(f"{path.relative_to(ROOT).as_posix()}:{number}")
    assert found == [], (
        "The project is Vedette; 'Sentinel' was its old name and appears only in the "
        f"CHANGELOG. Rename it at {found}. A placeholder value in code "
        "can be called _MISSING."
    )


def test_web_facing_dependencies_are_pinned_exactly() -> None:
    dependencies = _dependencies()
    loose = {
        name: dependencies[name]
        for name in ("fastapi", "jinja2", "python-multipart", "uvicorn")
        if not dependencies[name].startswith("==")
    }
    assert loose == {}, f"Pin {sorted(loose)} with '==' to a release at least two weeks old."


def test_time_zone_data_and_yaml_are_direct_dependencies() -> None:
    assert {"tzdata", "pyyaml"} <= set(_dependencies()), (
        "python:3.14-slim has no time zone database and the config loader parses YAML "
        "itself, so tzdata and pyyaml stay direct dependencies."
    )


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_actions_are_pinned_to_a_commit(path: Path) -> None:
    workflow = _load_yaml(path)
    used: list[str | None] = []
    for job in workflow["jobs"].values():
        used.append(job.get("uses"))
        used += [step.get("uses") for step in job.get("steps", [])]
    loose = [ref for ref in used if ref and not ref.startswith("./") and not COMMIT.match(ref)]
    assert loose == [], (
        f"Pin {loose} to the release's full commit, with the release in a comment, as in "
        "'actions/checkout@<40-hex commit> # v7.0.1'."
    )


def test_every_image_is_pinned_to_a_digest() -> None:
    images: list[str] = []
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    stages = set(re.findall(r"^FROM \S+ AS (\S+)$", dockerfile, re.MULTILINE))
    images += re.findall(r"^# syntax=(\S+)$", dockerfile, re.MULTILINE)
    images += re.findall(r"^FROM (\S+)", dockerfile, re.MULTILINE)
    images += re.findall(r"^COPY --from=(\S+)", dockerfile, re.MULTILINE)
    compose = _load_yaml(ROOT / "docker-compose.yml")
    images += [s["image"] for s in compose["services"].values() if "build" not in s]
    for path in [*WORKFLOWS, ROOT / ".githooks" / "pre-commit"]:
        images += REGISTRY_IMAGE.findall(path.read_text(encoding="utf-8"))
    loose = [image for image in images if image not in stages and not DIGEST.search(image)]
    assert loose == [], f"Name the tag and the @sha256 digest of {loose}."


def test_every_copy_of_the_gitleaks_image_is_the_same() -> None:
    copies = {
        path.relative_to(ROOT).as_posix(): GITLEAKS.search(path.read_text(encoding="utf-8"))
        for path in (ROOT / ".github" / "workflows" / "ci.yml", ROOT / ".githooks" / "pre-commit")
    }
    assert all(copies.values()), f"No pinned gitleaks image found in {copies}."
    images = {name: match.group(0) for name, match in copies.items() if match}
    hook_rev = _load_yaml(ROOT / ".pre-commit-config.yaml")["repos"][0]["rev"]
    tags = {match.group(1) for match in copies.values() if match}
    assert len(set(images.values())) == 1 and tags == {hook_rev}, (
        "Dependabot does not read these, so bump the gitleaks image in ci.yml and "
        ".githooks/pre-commit, and the rev in .pre-commit-config.yaml, together: "
        f"{images}, rev {hook_rev}."
    )


def test_dependabot_waits_two_weeks_for_every_ecosystem() -> None:
    updates = _load_yaml(ROOT / ".github" / "dependabot.yml")["updates"]
    short = {
        update["package-ecosystem"]: update.get("cooldown", {}).get("default-days")
        for update in updates
        if update.get("cooldown", {}).get("default-days", 0) < 14
    }
    assert short == {}, f"Give {short} a cooldown of at least 14 days."


def test_design_and_agent_working_files_stay_local() -> None:
    ignored = set((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
    missing = {"/PRODUCT.md", "/DESIGN.md", "/docs/superpowers/"} - ignored
    assert missing == set(), f"Keep {sorted(missing)} in .gitignore."


def _compose() -> dict[str, Any]:
    compose: dict[str, Any] = _load_yaml(ROOT / "docker-compose.yml")
    return compose


def test_ollama_has_no_route_to_the_internet() -> None:
    compose = _compose()
    internal = {name for name, net in compose["networks"].items() if (net or {}).get("internal")}
    ollama = compose["services"]["ollama"]
    assert set(ollama["networks"]) <= internal and "ports" not in ollama, (
        "Ollama joins only internal networks and publishes no port."
    )
    assert ollama["environment"]["OLLAMA_NO_CLOUD"] == "1", "Keep OLLAMA_NO_CLOUD set."
    assert compose["services"]["ollama-volume-owner"]["network_mode"] == "none"


def test_the_dev_container_can_reach_the_model() -> None:
    compose = _compose()
    assert "llm" in compose["services"]["dev"]["networks"], (
        "The dev container joins the llm network so pytest --live reaches Ollama."
    )


def test_every_published_port_is_on_loopback() -> None:
    published = [
        (name, str(port))
        for name, service in _compose()["services"].items()
        for port in service.get("ports", [])
    ]
    exposed = [(name, port) for name, port in published if not port.startswith("127.0.0.1:")]
    assert published and exposed == [], (
        f"Publish {exposed} on 127.0.0.1 only; the dashboard listens on every interface "
        "inside the container."
    )


def test_ollama_runs_unprivileged_with_a_read_only_root() -> None:
    services = _compose()["services"]
    for name in ("ollama", "ollama-pull"):
        assert services[name]["user"] == "10002:10002", name
        assert services[name]["read_only"] is True, name
        assert services[name]["cap_drop"] == ["ALL"], name
    owner = services["ollama-volume-owner"]
    assert sorted(owner["cap_add"]) == ["CHOWN", "DAC_READ_SEARCH"], (
        "Only the one-shot volume owner runs as root, with CHOWN and DAC_READ_SEARCH."
    )


def test_the_gpu_kernel_cache_lives_in_the_model_volume() -> None:
    ollama = _compose()["services"]["ollama"]
    mounts = [volume.split(":")[1] for volume in ollama["volumes"]]
    cache = ollama["environment"]["CUDA_CACHE_PATH"]
    assert any(cache.startswith(mount + "/") for mount in mounts), (
        f"CUDA_CACHE_PATH {cache} must sit in a mounted volume, or the read-only root "
        "makes the GPU kernels compile on every load."
    )


def test_ci_runs_weekly_and_builds_the_image() -> None:
    workflow = _load_yaml(ROOT / ".github" / "workflows" / "ci.yml")
    triggers = workflow.get("on", workflow.get(True))
    assert triggers.get("schedule"), "CI runs on a weekly schedule."
    steps = [step.get("uses", "") for step in workflow["jobs"]["image"]["steps"]]
    assert any(uses.startswith("docker/build-push-action@") for uses in steps), (
        "CI builds the image on every run."
    )


def test_the_architecture_names_only_files_and_tests_that_exist() -> None:
    text = ARCHITECTURE.read_text(encoding="utf-8")
    tests = {
        name
        for path in (ROOT / "tests").rglob("test_*.py")
        for name in re.findall(
            r"^(?:async )?def (test_[a-z0-9_]+)", path.read_text(encoding="utf-8"), re.MULTILINE
        )
    }
    ignored = {
        line.strip("/")
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.startswith("/")
    }
    missing_files = sorted(
        {
            path
            for path in REPO_PATH.findall(text)
            if not (ROOT / path).exists() and path.strip("/") not in ignored
        }
    )
    missing_tests = sorted(set(TEST_NAME.findall(text)) - tests)
    assert (missing_files, missing_tests) == ([], []), (
        f"docs/ARCHITECTURE.md names files {missing_files} and tests {missing_tests} that "
        "do not exist; point each at the check that holds it now."
    )


def test_every_commit_pushed_to_main_is_checked() -> None:
    workflow = _load_yaml(ROOT / ".github" / "workflows" / "conventions.yml")
    triggers = workflow.get("on", workflow.get(True))
    assert "main" in triggers["push"]["branches"]
    runs = [
        step.get("run", "")
        for job in workflow["jobs"].values()
        if job.get("if") == "github.event_name == 'push'"
        for step in job["steps"]
    ]
    assert any("tools/conventions.py commits" in run for run in runs), (
        "The Conventions workflow checks every commit pushed to main, squash merges included."
    )
