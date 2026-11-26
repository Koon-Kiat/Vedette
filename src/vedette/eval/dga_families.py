"""Domain generation algorithms of real malware families, to test the name rules on.

Each generator follows a published reverse-engineering analysis of one family:
Johannes Bader's write-ups (johannesbader.ch) and the vendor reports they cite,
with the sample domains those analyses list. The generators were written for
this project from the analyses, and every one reproduces the listed sample
names for their seed or date. They only make names: nothing is looked up.

These names were not used to choose any threshold, so they are a held-out
test of the ``dga-like`` rule. Each family runs on a fixed date or seed, so
every evaluation sees the same names.
"""

import calendar
import hashlib
import string
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import date

#: The day the date-seeded families generate names for.
DAY = date(2026, 1, 15)
_MASK32 = 0xFFFFFFFF
_MASK64 = (1 << 64) - 1
_A = ord("a")


def _signed32(value: int) -> int:
    """``value`` wrapped to a signed 32-bit integer, as a C ``int`` holds it."""
    value &= _MASK32
    return value - (1 << 32) if value >= 1 << 31 else value


def banjori(seed: str = "earnestnessbiophysicalohax.com") -> Iterator[str]:
    """Banjori (2015): each name rewrites the first four letters of the one before."""

    def wrap(code: int) -> int:
        return _A + (code - _A) % 26

    name = seed
    while True:
        yield name
        c0, c1, c2, c3 = (ord(char) for char in name[:4])
        c0 = wrap(c0 + c3)
        c1 = wrap(c0 + 2 * c1)
        c2 = wrap(c0 + c2 - 1)
        c3 = wrap(c1 + c2 + c3)
        name = "".join(map(chr, (c0, c1, c2, c3))) + name[4:]


def simda() -> Iterator[str]:
    """Simda: seven letters, consonant and vowel in turn, under .com."""
    consonants, vowels = "qwrtpsdfghjklzxcvbnm", "eyuioa"
    step = sum(map(ord, "1676d5775e05c50b46baa5579d4fc7"))
    base = 0x45AE94B2
    while True:
        base += step
        label = "".join(
            (
                consonants[base // (3 + 2 * i) % 20]
                if i % 2 == 0
                else vowels[base // (3 + 2 * i) % 6]
            )
            for i in range(7)
        )
        yield f"{label}.com"


def fobber(state: int = 0xC87C8A78, step: int = -1719405398) -> Iterator[str]:
    """Fobber, first version: 17 letters under .net."""
    while True:
        letters = []
        for _ in range(17):
            mixed = (321167 * state + step) & _MASK32
            state = ((mixed >> 16) | (mixed << 16)) & _MASK32
            letters.append(chr((state & 0x17FF) % 26 + _A))
        yield "".join(letters) + ".net"


def vawtrak(seed: int = 0x5884C3C4) -> Iterator[str]:
    """Vawtrak, second version: 7 to 11 letters mixing consonants and vowels."""
    consonants, vowels = "cdfghlmnrstw", "aeiou"

    def step(value: int) -> int:
        return (1103515245 * value + 12345) % 2**31

    state = seed
    while True:
        state = step(state)
        length = state % 5 + 7
        state = step(state)
        consonants_due = state % 2
        label = ""
        for _ in range(length):
            state = step(_signed32(state + 2))
            drawn = state
            if consonants_due:
                pool = consonants
                consonants_due -= 1
            else:
                pool = vowels
                state = step(state)
                consonants_due = state % 2 + 1
            label += pool[drawn % len(pool)]
        yield f"{label}.com"


def chinad(day: date = DAY) -> Iterator[str]:
    """Chinad: 16 letters and digits from SHA-1 of the date, 256 names a day."""
    alphabet = string.ascii_lowercase + string.digits
    tlds = (".com", ".org", ".net", ".biz", ".info", ".ru", ".cn")
    for number in range(256):
        data = bytes([day.year % 100, day.month, day.day, number]) + bytes(12)
        digest = hashlib.sha1(data).digest()  # noqa: S324 - the malware's own choice
        words = b"".join(digest[i : i + 4][::-1] for i in range(0, 20, 4))
        yield "".join(alphabet[byte % 36] for byte in words[:16]) + tlds[words[16] % 7]


def necurs(day: date = DAY, magic: int = 9) -> Iterator[str]:
    """Necurs: 7 to 21 letters from a 64-bit mixing function, under 43 top-level domains."""
    tlds = [
        "tj",
        "in",
        "jp",
        "tw",
        "ac",
        "cm",
        "la",
        "mn",
        "so",
        "sh",
        "sc",
        "nu",
        "nf",
        "mu",
        "ms",
        "mx",
        "ki",
        "im",
        "cx",
        "cc",
        "tv",
        "bz",
        "me",
        "eu",
        "de",
        "ru",
        "co",
        "su",
        "pw",
        "kz",
        "sx",
        "us",
        "ug",
        "ir",
        "to",
        "ga",
        "com",
        "net",
        "org",
        "biz",
        "xxx",
        "pro",
        "bit",
    ]

    def mix(value: int) -> int:
        for index in range((value & 0x7F) + 21):
            value = (value + (((value * 7) ^ (value << 15)) + 8 * index - (value >> 5))) & _MASK64
        return value

    number = 0
    while True:
        value = mix(day.year)
        value = mix(value + day.month + 43690)
        value = mix(value + (day.day >> 2))
        value = mix(value + number)
        value = mix(value + magic)
        label = ""
        for i in range(value % 15 + 7):
            value = mix(value + i)
            label += chr(value % 25 + _A)
            value = mix(value + 0xABBEDF)
        yield f"{label}.{tlds[value % 43]}"
        number += 1


def symmi(day: date = DAY) -> Iterator[str]:
    """Symmi: 8 to 15 letters alternating vowels and consonants, on ddns.net."""
    groups = ("aeiouy", "bcdfghklmnpqrstvwxz")
    state = 10000 * (day.day // 16 * 100 + day.month) + day.year + 42

    def draw() -> int:
        nonlocal state
        state = (state * 214013 + 2531011) & _MASK32
        return (state >> 16) & 0x7FFF

    while True:
        length = 8 + draw() % 8
        label, shift = "", 0
        for i in range(length):
            if i % 2 == 0:
                shift = 0 if draw() & 0x100 == 0 else 1
            drawn = draw()
            pool = groups[(shift + i) % 2]
            label += pool[drawn % (len(pool) - 1)]
        yield f"{label}.ddns.net"


def qadars(day: date = DAY, seed: int = 0x89F5) -> Iterator[str]:
    """Qadars: 12 letters and digits, seeded by the week.

    The top-level domains follow the current analysis; an older one gave
    .com, .org and .net for every seed. The labels are the same in both.
    """
    charset = string.ascii_lowercase + string.digits
    tlds = (
        (".com", ".org", ".net") if seed in (0xE1F2, 0xE1F1, 0xE1F5) else (".net", ".org", ".top")
    )
    week, monday = 7 * 86400, 4 * 86400
    unix = calendar.timegm(day.timetuple())
    state = unix - (unix - monday) % week

    def draw() -> int:
        nonlocal state
        state = (seed - 1043968403 * state) & 0x7FFFFFFF
        return state

    while True:
        label = "".join(charset[draw() % 36] for _ in range(12))
        yield label + tlds[draw() % 3]


def _java_hash(text: str) -> int:
    """Java's ``String.hashCode``, as a signed 32-bit integer."""
    value = 0
    for char in text:
        value = _signed32((value << 5) - value + ord(char))
    return value


def proslikefan(day: date = DAY, magic: str = "prospect") -> Iterator[str]:
    """Proslikefan: 6 to 12 letters, one name per top-level domain per round."""
    tlds = ("eu", "biz", "se", "info", "com", "net", "org", "ru", "in", "name")
    for round_number in range(10):
        for tld in tlds:
            seed = ".".join(str(part) for part in (magic, day.month, day.day, day.year, tld))
            value = abs(_java_hash(seed)) + round_number
            label = ""
            while len(label) < value % 7 + 6:
                value = abs(_java_hash(label + str(value)))
                label += chr(value % 26 + _A)
            yield f"{label}.{tld}"


def tinba(
    seed: str = "jc74FlUna852Ji9o",
    first: str = "blackfreeqazyio.cc",
    tlds: tuple[str, ...] = ("com", "net", "in", "ru"),
) -> Iterator[str]:
    """Tinba: 12 letters derived from the previous name, under several top-level domains."""
    codes = [ord(char) for char in seed.ljust(17, "\0")]
    name = first
    yield name
    while True:
        previous = [ord(char) for char in name]
        total = sum(codes[:16])
        value = codes[15] & 0xFF
        letters = []
        for i in range(12):
            while True:
                value = (((value + previous[i]) ^ (total & 0xFF)) + previous[i + 1]) & 0xFF
                if 0x61 < value < 0x7A:
                    letters.append(chr(value))
                    break
                total += 1
        base = "".join(letters)
        for tld in tlds:
            name = f"{base}.{tld}"
            yield name


def shiotob(first: str = "wtipubctwiekhir.net") -> Iterator[str]:
    """Shiotob: 10 to 15 letters and digits derived from the previous name."""
    keyboard = "qwertyuiopasdfghjklzxcvbnm123945678"
    name = first
    while True:
        yield name
        total = sum(map(ord, name[:-3]))
        codes = [ord(char) for char in name] + [0] * 100
        old = len(name) - 4
        for i in range(66):
            for j in range(65 - i):
                codes[i + j] = (old * codes[j] ^ codes[i + j] ^ total) & 0xFF
        length = (((codes[2] * old) ^ codes[0]) & 0xFF) // 16
        length = old if length < 10 else length
        host = "".join(keyboard[codes[i] // 8] for i in range(length))
        name = host + (".com" if name.endswith(".net") else ".net")


def padcrypt(day: date = DAY, separator: str = "|", count: int = 72) -> Iterator[str]:
    """PadCrypt ransomware: 16 characters from SHA-256 of the date.

    Version 2.2.97.0 makes 72 names a day with ``|``; 2.2.86.1 made 24 with ``:``.
    """
    tlds = ("com", "co.uk", "de", "org", "net", "eu", "info", "online", "co", "cc", "website")
    digits = "abcdnfolmk"
    for number in range(count):
        seed = f"{day.day}-{day.month}-{day.year}{separator}{number}"
        digest = hashlib.sha256(seed.encode()).hexdigest()
        label = "".join(digits[int(char)] if char.isdigit() else char for char in digest[3:19])
        index = int(digest[-1], 16)
        yield f"{label}.{tlds[index if index < len(tlds) else 0]}"


def newgoz(day: date = DAY) -> Iterator[str]:
    """New GameOver Zeus: 25 to 28 letters and digits from MD5 of the date."""
    key = b"\x01\x05\x19\x35"

    def base36(value: int) -> str:
        digits: list[str] = []
        for _ in range(7):
            value, digit = divmod(value, 36)
            digits.append((string.digits + string.ascii_lowercase)[digit])
            if value == 0:
                break
        return "".join(reversed(digits))

    number = 0
    while True:
        packed = struct.pack("<I", number) + struct.pack("<H", day.year) + key
        packed += struct.pack("<H", day.month) + key + struct.pack("<H", day.day) + key
        digest = hashlib.md5(packed).digest()  # noqa: S324 - the malware's own choice
        label = "".join(
            base36(int.from_bytes(digest[i : i + 4], "little")) for i in range(0, 16, 4)
        )
        tld = (
            "com"
            if number % 4 == 0
            else "org"
            if number % 3 == 0
            else "biz"
            if number % 2 == 0
            else "net"
        )
        yield f"{label}.{tld}"
        number += 1


@dataclass(frozen=True, slots=True)
class Family:
    """One malware family's generator, and the kind of names it makes."""

    name: str
    style: str
    generate: Callable[[], Iterator[str]]

    def names(self, count: int) -> list[str]:
        """The family's first ``count`` names, without repeats (fewer if it runs out)."""
        seen: dict[str, None] = {}
        for name in self.generate():
            seen.setdefault(name)
            if len(seen) == count:
                break
        return list(seen)


FAMILIES: tuple[Family, ...] = (
    Family("Banjori", "words with the first four letters changed", banjori),
    Family("Simda", "pronounceable, 7 letters", simda),
    Family("Vawtrak", "pronounceable, 7 to 11 letters", vawtrak),
    Family("Symmi", "pronounceable, on ddns.net", symmi),
    Family("Proslikefan", "random letters, 6 to 12", proslikefan),
    Family("Necurs", "random letters, 7 to 21", necurs),
    Family("Tinba", "random letters, 12", tinba),
    Family("Fobber", "random letters, 17", fobber),
    Family("Qadars", "letters and digits, 12", qadars),
    Family("Shiotob", "letters and digits, 10 to 15", shiotob),
    Family("Chinad", "letters and digits, 16", chinad),
    Family("PadCrypt", "hash letters, 16", padcrypt),
    Family("New GameOver Zeus", "letters and digits, 25 to 28", newgoz),
)
