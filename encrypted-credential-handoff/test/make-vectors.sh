#!/bin/bash
# How the age test vectors in this folder were made. NOT run by run-test.sh or
# CI: the vectors are committed, and a re-run would change them (age's output
# is randomized). Kept so anyone can check how each one came about, and make
# new ones the same way.
#
# Tools used (2026-11-16, linux amd64, official release binaries, each in its
# own scratch directory; nothing installed system-wide):
#   age 1.3.2   age-v1.3.2-linux-amd64.tar.gz
#               sha256 cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10
#               https://github.com/FiloSottile/age/releases/tag/v1.3.2
#   rage 0.12.1 rage-v0.12.1-x86_64-linux.tar.gz
#               sha256 c5d7ab41fbf1213590e89721fd2b8eb122e84518c155ce35866f1c5759a3a29f
#               https://github.com/str4d/rage/releases/tag/v0.12.1
# Also ssh-keygen (OpenSSH) for the ssh-stanza vector, and python3.
#
# Usage: AGE_DIR=<dir with age, age-keygen> RAGE_DIR=<dir with rage> \
#        bash make-vectors.sh
#
# The identity is a published throwaway: it protects nothing. Every other key
# made here (second recipient, ssh, pq) lives in a scratch directory that is
# deleted at the end; only blobs are kept. The sha256 of each committed vector
# is at the end of this file.
set -Eeuo pipefail
cd "$(dirname "$0")"
: "${AGE_DIR:?set AGE_DIR to the directory holding age and age-keygen 1.3.2}"
: "${RAGE_DIR:?set RAGE_DIR to the directory holding rage}"
AGE=$AGE_DIR/age
AGE_KEYGEN=$AGE_DIR/age-keygen
RAGE=$RAGE_DIR/rage
"$AGE" --version | grep -qx 'v1.3.2' || { echo "need age v1.3.2" >&2; exit 1; }
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
mkdir -p vectors

# The dummy identity and its recipient (one line, as age-keygen -y prints it).
rm -f test-dummy-identity.txt
"$AGE_KEYGEN" -o test-dummy-identity.txt 2>/dev/null
"$AGE_KEYGEN" -y test-dummy-identity.txt > handoff-test.age
R=$(cat handoff-test.age)

# Known answers: expected.json encrypted by Go age and by rage, binary format
# (never -a), base64 on one line.
"$AGE" -r "$R" < expected.json | base64 -w0 > blob-age.txt; echo >> blob-age.txt
until "$RAGE" -r "$R" < expected.json | base64 -w0 > blob-age-rage.txt \
  && base64 -d blob-age-rage.txt | head -c 400 | grep -aq -- '-grease'; do :; done
echo >> blob-age-rage.txt
# blob-age-rage.txt's header carries a `-grease` stanza (rage adds one at
# random; the loop above repeats until it has).

# Refusal vectors. Real blobs where age can make one:
# scrypt (passphrase, through the batchpass plugin)
AGE_PASSPHRASE=throwaway-passphrase "$AGE" -e -j batchpass < expected.json \
  | base64 -w0 > vectors/scrypt.txt; echo >> vectors/scrypt.txt
# two X25519 recipients, ours among them
"$AGE_KEYGEN" -o "$W/second.txt" 2>/dev/null
R2=$("$AGE_KEYGEN" -y "$W/second.txt")
"$AGE" -r "$R" -r "$R2" < expected.json | base64 -w0 > vectors/two-x25519.txt; echo >> vectors/two-x25519.txt
# post-quantum recipient (age 1.3+)
"$AGE_KEYGEN" -pq -o "$W/pq.txt" 2>/dev/null
RPQ=$("$AGE_KEYGEN" -y "$W/pq.txt")
"$AGE" -r "$RPQ" < expected.json | base64 -w0 > vectors/pq-stanza.txt; echo >> vectors/pq-stanza.txt
# ssh-ed25519 recipient
ssh-keygen -q -t ed25519 -N '' -f "$W/ssh" >/dev/null
"$AGE" -R "$W/ssh.pub" < expected.json | base64 -w0 > vectors/ssh-stanza.txt; echo >> vectors/ssh-stanza.txt
# armored (age -a): the raw multi-line text, and its base64
"$AGE" -a -r "$R" < expected.json > vectors/armored-raw.txt
base64 -w0 vectors/armored-raw.txt > vectors/armored-b64.txt; echo >> vectors/armored-b64.txt

# Hand-built headers: take a real blob's header, replace its stanza lines, keep
# the rest. The MAC is no longer valid; the header check refuses these before
# age runs, so they need none.
"$AGE" -r "$R" < expected.json > "$W/real.age"
python3 -I - "$W/real.age" <<'PY'
import base64, sys

raw = open(sys.argv[1], "rb").read()
first = raw.index(b"\n") + 1                     # end of the version line
mac = raw.index(b"\n--- ") + 1                   # start of the MAC line
rest = raw[mac:]                                 # MAC line + payload
stanza = raw[first:mac]                          # the X25519 stanza lines
version = raw[:first]
body = base64.b64encode(bytes(range(32))).rstrip(b"=") + b"\n"   # one 32-byte body line

def write(name, stanzas):
    blob = version + stanzas + rest
    with open("vectors/" + name, "w") as f:
        f.write(base64.b64encode(blob).decode() + "\n")

# only a grease stanza, no X25519
write("grease-only.txt", b"-> a1b2-grease 7 xyz\n" + body)
# a plugin stanza type (an arbitrary string) and no X25519
write("plugin-stanza.txt", b"-> frobnicate AAAA\n" + body)
# an unknown type, beside our real X25519 stanza
write("unknown-stanza.txt", stanza + b"-> mystery-type AAAA\n" + body)
PY

sha256sum handoff-test.age test-dummy-identity.txt blob-age.txt blob-age-rage.txt vectors/*
echo done

# sha256 of each committed vector (made 2026-11-16 with the tools above):
# 8565b2368618c5683bd3126198258de52ae235550a59b5b15f88ac41b638e540  handoff-test.age
# 637f0f99e8e14cc8524a5ea0cc9fd4d34d016ca03c8476e764a3a944ef8ffc95  test-dummy-identity.txt
# 13468418a6bc8334336a13bc97d52ac8481b520a93e71aa9bc7903f136066a8c  blob-age.txt
# 051b174ea9016f2288ac2926beac5593f28f7f2faf13f94f7680f43ff8a2cc1e  blob-age-rage.txt
# 3e3b778cb9e36d8a67496ca66fd1f749a775b13ada426d3792ae1d892b938807  vectors/armored-b64.txt
# a4f730f82ab46b5ac6b2cbb879688b9ca4bda2d5b9788142c6e40af8e8a291ee  vectors/armored-raw.txt
# fd301294de8d04cd82937e82cf56e157315ca444ead5b8a247b547fb28160373  vectors/grease-only.txt
# 5be84bbfe4100d1d54680a7c2fec34c465cdf2b33f13a63d2687c368564e4eab  vectors/plugin-stanza.txt
# c60bd3a64b2c9f2ceb91ead544b402e13e5c4f3f8dc138d7caebdfb5f58d0517  vectors/pq-stanza.txt
# 377cc87f37cdb18aff3438d250c36bed65c538628f2cd3f070c61b9a6b131264  vectors/scrypt.txt
# 54b7f5fafaf8b7c32cbcd1f11a988a122a9a2da1b7ae51df825aa8510064b1ac  vectors/ssh-stanza.txt
# c6647b1ff99457210c0cacc1648e5fe9d0f3ebceb058b5aa17dc25c4ac4e027e  vectors/two-x25519.txt
# 824279933e6ce968262a4f32f13680cb42f951d04a052ebe5c3d74658d78637e  vectors/unknown-stanza.txt
