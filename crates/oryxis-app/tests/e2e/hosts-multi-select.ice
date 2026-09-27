viewport: 1400x900
mode: Zen
-----
# Multi-select mode (issue #230): a toolbar toggle turns a card click
# into a selection, the bar over the grid carries the batch, a picked
# card's right-click menu collapses to what acts on the whole
# selection, and the batch delete asks first and names what goes.
#
# The mode toggle is an icon-only square, so there is no text for a
# selector to match and it is clicked by position. At 1400x900 the
# toolbar cluster is anchored to the right edge: the "+ HOST" split
# group (92 + 1 + 40 px) ends 25px in from that edge, and the toggle's
# 44px square sits one 8px gap and its own 6px leading gap to the left
# of it, which puts the square's centre at x 1212 on the cluster's own
# centre line (y 121). Every click below is followed by an assertion
# that only the intended control could satisfy, so a cluster that
# changes shape fails at the click rather than three steps later.
#
# What the mode does is asserted in text: the count, the bar's labels,
# and the menu's labels. A card's check box is a drawn glyph and a
# card's label is real text, which is why the count is the evidence
# for "this many are picked" rather than the boxes.
expect "Welcome to Oryxis"
click "Skip"
expect "Protect your vault"
click "Continue without password"
expect "Create host"

# Three hosts to have a batch out of. The first goes through the
# first-run empty state - Continue submits its empty field, which
# opens the editor (the same path hosts-move-to-group.ice uses); the
# other two through the toolbar's "+ HOST". Their addresses are
# TEST-NET-1 (RFC 5737), which routes nowhere, because the batch
# connect below really dials them. The editor's label field is
# reached by position for the toggle's reason: a text_input value is
# invisible to a selector, so there is nothing else to click.
click "Continue"
expect "New Host"
click "IP or Hostname"
type "192.0.2.1"
click (1190.00, 219.00)
type "web01"
click "Save"
settle 500
expect "web01"
click "HOST"
expect "New Host"
click "IP or Hostname"
type "192.0.2.2"
click (1190.00, 219.00)
type "db01"
click "Save"
settle 500
expect "db01"
click "HOST"
expect "New Host"
click "IP or Hostname"
type "192.0.2.3"
click (1190.00, 219.00)
type "cache01"
click "Save"
settle 500
# Sorted by label, so the grid reads cache01, db01, web01.
expect "cache01"

# The mode on with nothing picked yet: the bar is up with every verb
# that needs a selection present but disabled (a disabled row is still
# a row, so nothing reflows under the cursor), Select all being the
# one that can act on an empty selection.
click (1212.00, 121.00)
settle 400
expect "0 selected"
expect "Select all"
expect "Move to group…"
expect "Delete"

# While the mode is on, a card click selects it instead of dialling it.
click "web01"
settle 300
expect "1 selected"
click "db01"
settle 300
expect "2 selected"
click "Clear"
settle 300
expect "0 selected"

# Select all sweeps the whole visible list; Clear drops it again.
click "Select all"
settle 300
expect "3 selected"
click "Clear"
settle 300
expect "0 selected"

# Two picked, then a picked card's own menu: past one host it collapses
# to the selection's actions, so the single-host entries are gone and
# every verb carries the count.
click "web01"
settle 300
click "db01"
settle 300
expect "2 selected"
click right "web01"
settle 400
expect "Connect 2 hosts"
expect "Remove 2 hosts"
absent "Duplicate"
absent "Edit"

# Remove asks first and names the hosts. Cancel, so the batch survives
# this test the way it survives the gesture.
click "Remove 2 hosts"
settle 400
expect "Remove?"
click "Cancel"
settle 400
absent "Remove?"
expect "2 selected"

# Inside the mode a search narrows the grid but not the selection: a
# selection spanning the list is built one search at a time, and the
# bar says how many picked hosts the search is hiding, so a batch never
# acts on something off screen without the bar saying so.
click #search-dashboard
type "cache"
settle 300
expect "2 selected"
expect "2 hidden by the search"
click "cache01"
settle 300
expect "3 selected"
expect "2 hidden by the search"
click #search-dashboard
type ctrl+a
type backspace
settle 300
expect "3 selected"
absent "hidden by the search"

# Leaving the mode hands the cards back to click-connects, and the
# selection goes with it - a bar left over hosts that no longer read as
# chosen would be the mode lying about what a click does.
click (1212.00, 121.00)
settle 400
absent "3 selected"
absent "Select all"

# Batch connect dials ONE host at a time (the host-key, 2FA and
# command-proxy answers ride single staging slots). The first in view
# order is db01; web01 has no tab while db01's card is up, and a FAILED
# card holds the queue too (the next dial would take that card over),
# so the unroutable address makes the wait deterministic: web01 dials
# only once the user closes db01's card.
click (1212.00, 121.00)
settle 400
click "web01"
settle 300
click "db01"
settle 300
expect "2 selected"
click "Connect"
settle 800
expect "db01"
absent "web01"
click "Close"
settle 800
expect "web01"
absent "db01"
