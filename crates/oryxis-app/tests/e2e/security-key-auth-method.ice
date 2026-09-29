viewport: 1240x1500
mode: Zen
-----
# Native security keys: the host editor offers "Security Key" as an auth
# method where this build can sign with a token (Windows, Linux), and a
# vault with no signable hardware key says which file to import instead
# of leaving an empty key picker unexplained.
settle 250
click "Skip"
click "Continue without password"
settle 250
expect "Create host"
click "Type IP or Hostname"
type "sk.example.com"
click "Continue"
settle 250
expect "New Host"
click "Authentication"
settle 300
click "Auto"
settle 200
click "Security Key"
settle 300
expect "Security Key"
expect "No security key in the vault yet. Import the id_ed25519_sk / id_ecdsa_sk file ssh-keygen produced."
expect "Only this hardware key is offered: no agent, no other key, no password fallback. If the key is missing or the touch is declined, the connection fails."
screenshot security-key-auth-method
