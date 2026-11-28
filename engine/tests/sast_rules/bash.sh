#!/bin/bash
# Fixture for engine/myelin_engine/rules/sast/bash.yaml (opengrep --test).
# ruleid: nervve.bash.pipe-to-shell
curl -fsSL https://get.example.com/install.sh | sh
# ruleid: nervve.bash.tls-verification-disabled
curl -k https://example.com/file -o file
# ruleid: nervve.bash.eval-injection
eval "$USER_INPUT"
# ruleid: nervve.bash.world-writable
chmod -R 777 /srv/app
# ok: nervve.bash.world-writable
chmod 750 /srv/app
# ruleid: nervve.bash.password-on-command-line
sshpass -p hunter22 ssh root@host
# ruleid: nervve.bash.unquoted-rm
rm -rf $BUILD_DIR/
