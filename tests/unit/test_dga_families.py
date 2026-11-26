"""The re-implemented malware families reproduce the names their analyses publish."""

from collections.abc import Callable, Iterator
from datetime import date
from itertools import islice

import pytest

from vedette.eval import dga_families as f
from vedette.eval.datasets import valid_dns_name

#: Each family on the seed or date of its published sample, and that sample's first names.
PUBLISHED: list[tuple[str, Callable[[], Iterator[str]], list[str]]] = [
    ("Banjori", f.banjori, ["earnestnessbiophysicalohax.com", "kwtoestnessbiophysicalohax.com"]),
    ("Simda", f.simda, ["gatyfus.com", "lyvyxor.com"]),
    ("Vawtrak", f.vawtrak, ["usahwutle.com", "folocnam.com"]),
    ("Fobber", f.fobber, ["vhkintjtksyxgjrzz.net", "btpnxlsfdqbhzazyx.net"]),
    ("Tinba", f.tinba, ["blackfreeqazyio.cc", "nvfowikhevmy.com"]),
    ("Shiotob", f.shiotob, ["wtipubctwiekhir.net", "rwmu35avqo12tqc.com"]),
    ("Chinad", lambda: f.chinad(date(2017, 1, 13)), ["8f6bacmw30xxv6sc.cn", "486txu3yjly0xcmz.ru"]),
    ("Necurs", lambda: f.necurs(date(2015, 8, 28)), ["nccojqvabqvkiwhj.mx", "hoedwwwywnmmbi.ac"]),
    (
        "Symmi",
        lambda: f.symmi(date(2015, 8, 16)),
        ["ogovugtuipawi.ddns.net", "afowkaupbabe.ddns.net"],
    ),
    ("Proslikefan", lambda: f.proslikefan(date(2016, 6, 17)), ["flarvcpk.eu", "stjneohiod.biz"]),
    (
        "PadCrypt",
        lambda: f.padcrypt(date(2016, 3, 6), ":", 24),
        ["elkfcfnacacmofdf.com", "mkmeeefncfnfdmbm.de"],
    ),
    (
        "New GameOver Zeus",
        lambda: f.newgoz(date(2015, 8, 31)),
        ["xzz3ug32bale1uo60y7xj6rge.com", "1hyzmw3l2phycet88hzr2do34.net"],
    ),
]


@pytest.mark.parametrize(
    ("make", "expected"), [pytest.param(make, names, id=name) for name, make, names in PUBLISHED]
)
def test_each_family_reproduces_its_published_sample(
    make: Callable[[], Iterator[str]], expected: list[str]
) -> None:
    assert list(islice(make(), len(expected))) == expected


def test_qadars_reproduces_the_published_labels() -> None:
    labels = [name.split(".")[0] for name in islice(f.qadars(date(2016, 3, 30)), 2)]

    assert labels == ["jk9enwhansl2", "sdqfodmf81m7"]


@pytest.mark.parametrize("family", f.FAMILIES, ids=lambda family: family.name)
def test_every_family_gives_forty_distinct_valid_names(family: f.Family) -> None:
    names = family.names(40)

    assert len(set(names)) == 40
    assert all(valid_dns_name(name) for name in names)


def test_a_family_that_runs_out_gives_what_it_has() -> None:
    chinad = next(family for family in f.FAMILIES if family.name == "Chinad")

    assert len(chinad.names(300)) == 256


def test_the_families_cover_every_style_of_name() -> None:
    styles = " ".join(family.style for family in f.FAMILIES)

    for style in ("pronounceable", "random letters", "letters and digits", "hash", "words"):
        assert style in styles
