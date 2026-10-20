from __future__ import annotations

from diffguard.diff import parse_diff

MULTI_HUNK = """\
diff --git a/app.py b/app.py
index 111..222 100644
--- a/app.py
+++ b/app.py
@@ -3,2 +3,3 @@ def handler():
 context = 1
-old = 2
+new = 2
+extra = 3
@@ -20 +21 @@
-x = 1
+x = 2
"""


def test_line_numbers_across_hunks():
    (fd,) = parse_diff(MULTI_HUNK)
    assert fd.path == "app.py"
    assert [(line.number, line.text) for line in fd.added] == [
        (4, "new = 2"),
        (5, "extra = 3"),
        (21, "x = 2"),
    ]
    assert [(line.number, line.anchor) for line in fd.removed] == [(4, 4), (20, 21)]


def test_unified_zero_hunk_without_counts():
    diff = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -7 +7 @@\n-a\n+b\n"
    (fd,) = parse_diff(diff)
    assert fd.added[0].number == 7 and fd.removed[0].number == 7


def test_new_deleted_renamed_binary():
    diff = (
        "diff --git a/new.py b/new.py\nnew file mode 100644\n--- /dev/null\n+++ b/new.py\n"
        "@@ -0,0 +1 @@\n+print('hi')\n"
        "diff --git a/gone.py b/gone.py\ndeleted file mode 100644\n--- a/gone.py\n+++ /dev/null\n"
        "@@ -1 +0,0 @@\n-print('bye')\n"
        "diff --git a/old.py b/moved.py\nsimilarity index 100%\nrename from old.py\nrename to moved.py\n"
        "diff --git a/logo.png b/logo.png\nBinary files a/logo.png and b/logo.png differ\n"
    )
    new, gone, moved, logo = parse_diff(diff)
    assert (new.status, new.added[0].number) == ("added", 1)
    assert (gone.status, gone.path) == ("deleted", "gone.py")
    assert (moved.status, moved.old_path, moved.path) == ("renamed", "old.py", "moved.py")
    assert logo.binary


def test_content_that_looks_like_headers():
    diff = (
        "diff --git a/s.sql b/s.sql\n--- a/s.sql\n+++ b/s.sql\n@@ -1,2 +1,2 @@\n"
        "--- a comment\n-+++ odd\n+++ new comment\n+--- also\n"
    )
    (fd,) = parse_diff(diff)
    assert [line.text for line in fd.removed] == ["-- a comment", "+++ odd"]
    assert [line.text for line in fd.added] == ["++ new comment", "--- also"]


def test_no_newline_marker_and_plain_diff():
    diff = "--- a.txt\t2024-01-01\n+++ b.txt\t2024-01-02\n@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+b\n"
    (fd,) = parse_diff(diff)
    assert fd.path == "b.txt"
    assert [line.text for line in fd.added] == ["b"]


def test_quoted_unicode_path():
    diff = (
        'diff --git "a/caf\\303\\251.py" "b/caf\\303\\251.py"\n'
        '--- "a/caf\\303\\251.py"\n+++ "b/caf\\303\\251.py"\n@@ -1 +1 @@\n-a\n+b\n'
    )
    (fd,) = parse_diff(diff)
    assert fd.path == "café.py"


def test_empty_diff():
    assert parse_diff("") == []
