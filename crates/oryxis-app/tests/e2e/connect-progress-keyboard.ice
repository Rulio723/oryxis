viewport: 1200x750
mode: Zen
-----
# The connect-progress card is on the keyboard ring like every other
# surface (issue #52 convention), with NO default row: it appears by
# itself, so a bare Enter must not retry, close or edit anything. Only
# a row the keyboard ringed acts.
#
# The target is an explicit quick-connect to a closed local port: no
# external network, and the card lands in its failed state (Edit Host,
# then Copy logs / Close / Start over). Some stacks answer a closed
# loopback port with silence rather than a reset (WSL does), so the
# failure can take the full 15 s connect timeout; `expect` waits for it.
settle 250
click "Skip"
click "Continue without password"
settle 250
type tab
type enter
# The focus lands a frame after the Enter that asked for it.
settle 250
type "root@127.0.0.1:1"
settle 250
type enter
settle 1500
expect "Connection failed with connection log:"
expect "Start over"
# Nothing ringed: Enter is inert and the card stays.
type enter
settle 250
expect "Start over"
# Esc with nothing ringed is inert too (it never closes the tab).
type escape
settle 250
expect "Start over"
# Walk: Edit Host, Copy logs, Close. Enter on the ringed Close closes.
type tab
type tab
type tab
settle 250
screenshot connect-progress-ringed-close
type enter
settle 250
absent "Start over"
expect "Create host"
