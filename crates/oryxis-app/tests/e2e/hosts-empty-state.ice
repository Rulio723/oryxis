viewport: 1200x750
mode: Zen
-----
# First-run Hosts screen. With an empty vault there is no toolbar
# (nothing to search / sort / filter / re-layout), and the "+ Host ▾"
# menu's own entries render as buttons under an "or" divider instead
# of hiding behind a chevron. The keyboard reaches the block through
# the content zone: Tab rings the hostname field, Enter focuses it,
# and submitting opens the pre-filled host editor.
#
# The target MUST be a bare name. An explicit one (a username, a port
# or an IP literal, `SshTarget::is_explicit()`) quick-connects straight
# away instead of stopping at the editor (#97, 170654f0), which is a
# different assertion and would burn the 15 s connect timeout here.
settle 250
click "Skip"
click "Continue without password"
settle 250
expect "Create host"
expect "or"
# One Import entry since the hub landed (single standardized import,
# format detected from the picked file).
expect "Import"
screenshot hosts-empty-state
type tab
type enter
# Let the focus land before typing, or the first character is lost.
settle 250
type "myserver.example.com"
settle 250
type enter
settle 250
expect "New Host"
