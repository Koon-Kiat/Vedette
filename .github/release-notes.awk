# Prints one version's section of CHANGELOG.md as the notes for its GitHub
# Release, with each paragraph and list item joined onto one line. GitHub shows
# every newline in a release body as a line break, so the changelog's wrapping
# at 80 columns would otherwise show as a narrow column.
#
#   awk -v heading="## 0.2.0" -f .github/release-notes.awk CHANGELOG.md

function flush() {
    if (buf != "") print buf
    buf = ""
}

index($0, heading) == 1 { found = 1; next }
!found { next }
/^## / { exit }

# Code blocks keep their lines.
/^[[:space:]]*```/ { flush(); print; fence = !fence; next }
fence { print; next }

/^[[:space:]]*$/ { flush(); print; next }

# Headings and table rows stand alone.
/^#/ || /^[[:space:]]*\|/ { flush(); print; next }

# A list item or quote starts a new line.
/^[[:space:]]*([-*+]|[0-9]+\.)[[:space:]]/ || /^[[:space:]]*>/ { flush(); buf = $0; next }

# Anything else continues the line before it.
{
    sub(/^[[:space:]]+/, "")
    buf = (buf == "") ? $0 : buf " " $0
}

END { flush() }
