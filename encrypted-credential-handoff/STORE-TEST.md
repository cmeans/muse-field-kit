# Test a new store for the credential handoff

Use this prompt to test a remote store that the README's "Choosing a store" section has not tested yet. Give the whole prompt to your agent, and name the store you want tested where it says `[store]`.

---

Test whether `[store]` can hold the encrypted blobs for the credential
handoff in this folder (`encrypted-credential-handoff`). Work only from
this folder's files, the `age` tool, and the store's own connection.
At the end, give me the scorecard at the bottom of this prompt, filled in.

## Safety rails

- Use dummy data only. Every blob in this test is made with the test
  recipient in `test/handoff-test.age` and checked with the test identity
  in `test/test-dummy-identity.txt`. Never use a real credential, and
  never use my real recipient or identity.
- Put nothing from my real data in the store. Use a new scratch location
  named `store-test`, or the closest thing the store has to one.
- Stop and ask me before you create an account, change a sharing
  setting, or pay for anything.
- Never read the plaintext of a real handoff. This test has no real
  handoff in it. The check tool prints field names and lengths only.

## Make the dummy blobs

You need four blobs, one line each, of exactly 400, 2,700, 8,000, and
64,000 characters. Each holds the same dummy payload shape, with the
password field padded with the letter `x` to reach the size.

In bash (the files go in a new private folder from `mktemp -d`, never at a fixed name in `/tmp`, where another user of the machine could have put a link first):

```sh
cd encrypted-credential-handoff
T=$(mktemp -d)
R=$(cat test/handoff-test.age)
for t in 400 2700 8000 64000; do
  n=$(( t*3/4 - 200 ))
  pre='{"svc":"store-test","password":"'; post='"}'
  pl=$(( n - ${#pre} - ${#post} ))
  { printf '%s' "$pre"; head -c "$pl" /dev/zero | tr '\0' x; printf '%s' "$post"; } \
    | age -r "$R" | base64 | tr -d '\n' > "$T/blob-$t.txt"
  echo "$t: $(wc -c < "$T/blob-$t.txt")"
done
cp test/test-dummy-identity.txt "$T/store-test-id" && chmod 600 "$T/store-test-id"
echo "temp folder: $T"
```

In PowerShell (a new folder with a random name in the temp folder; the payload is dummy, so its temp file is safe to delete):

```powershell
cd encrypted-credential-handoff
$TempDir = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $TempDir | Out-Null
$R = (Get-Content .\test\handoff-test.age -Raw).Trim()
foreach ($t in 400, 2700, 8000, 64000) {
  $n = $t * 3 / 4 - 200
  $pre = '{"svc":"store-test","password":"'; $post = '"}'
  $payload = $pre + ('x' * ($n - $pre.Length - $post.Length)) + $post
  [IO.File]::WriteAllText((Join-Path $TempDir "payload-$t.json"), $payload, [Text.Encoding]::ASCII)
  & age -r $R -o (Join-Path $TempDir "blob-$t.age") (Join-Path $TempDir "payload-$t.json")
  $blob = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $TempDir "blob-$t.age")))
  [IO.File]::WriteAllText((Join-Path $TempDir "blob-$t.txt"), $blob)
  Remove-Item (Join-Path $TempDir "payload-$t.json"), (Join-Path $TempDir "blob-$t.age")
  "$t`: $($blob.Length)"
}
Copy-Item .\test\test-dummy-identity.txt (Join-Path $TempDir 'store-test-id')
"temp folder: $TempDir"
```

If a printed length is not the target size, stop and report that. Do not test with a blob of the wrong size.

The check runs where `consume.py` runs, on Linux or macOS. A Windows user copies the fetched blob and the temp identity there, or runs the check under WSL.

Check a blob like this, with `T` set to the temp folder the bash block printed (set it again in a new shell). The check must print that `svc` matches the label `store-test`, and a password length of 66, 1,791, 5,766, or 47,766 bytes, matching the rung:

```sh
HANDOFF_PRIVKEY="$T/store-test-id" python3 -I consume.py --label store-test --check --blob-file <fetched-file>
```

## What to check

Score each item pass, partial, or fail, and give the evidence for each score: the command or screen, the exact error text, or the setting you read. Do not score from the store's marketing pages.

1. **Private.** Who besides me can read an item in the store: the
   sharing defaults, whether a public link can exist, whether other
   people or agents on a shared account can read it, and whether the
   store's own staff tools or AI features can read or index it.
2. **Unattended fetch.** Fetch a stored blob in a fresh session, with
   me taking no action, the way a wrapper would at use time. The blob
   must reach the check tool without passing through your context or
   a tool output you read. Note every approval prompt: what it asks,
   and whether approving once is enough or a standing approval is
   offered. Report what each choice would mean; do not choose for me.
   If a fetch hangs or times out with no error, say whether a pending
   approval could be the cause.
3. **Write, replace, delete.** Store a blob under the label
   `store-test`, replace it with a second blob of the same size, and
   delete it. Say which of these you can do, which only I can do,
   and which nobody can do through the connection you have.
4. **Round trip, by size.** For each of the four sizes: store the
   blob as one item, fetch it, and run the check above. Added
   whitespace and line wrapping are fine. Truncation, re-encoding,
   or added text are not. If the store makes you split one blob
   across several items or fields to fit it, say so: that is a
   partial, not a pass. Record the largest size that passes, and
   the exact failure at the first size that fails. Fetch the item
   by a stable id or path, not by name or search alone: say if two
   items can share one name, if a new item takes time to appear in
   search, or if labels that differ only in letter case share a slot.
   Also record what a fetch of a missing label returns (an error,
   an empty value, or a fixed word), and whether you could tell
   "missing" from "damaged" from that result.
5. **History.** After a replace and after a delete, what survives:
   old versions, a revision history, a trash or recycle bin, a soft
   delete, or a backup. Say how long each survives, and whether it
   can be removed for good through the connection you have.
6. **The store's own credential.** What your connection to the store
   needs. Can it be limited to this one item, folder, or database,
   or does it open the whole account? Is it read-only, read-write,
   or both? Does any token, password, or key file have to sit on
   your machine for a fetch to work?
7. **Limits and cost.** The free tier, if any: the largest single
   item, any rate or total limits, anything that expires, is
   evicted, or is archived when idle, and whether the free tier is
   an account of its own or space shared with my other data. If
   there is no free tier, give the lowest paid price.

Also say where a fetched blob lands on your side (in memory, or in a file, and on which disk), and remove any file copy when you are done. A synced or cached local copy counts as a local copy.

## Clean up

Delete every item, file, and temp copy this test made, in the store and on your machine, including the temp folder with the identity copy in it (`rm -rf "$T"`, or in PowerShell `Remove-Item -Recurse -Force $TempDir`). Then check the scratch location once more and confirm in the scorecard that nothing is left.

## Scorecard

End with exactly this table, filled in, and the verdict line:

| Check | Score | Evidence in one line |
| --- | --- | --- |
| Private | | |
| Unattended fetch | | |
| Write, replace, delete | | |
| Round trip (largest passing size: ) | | |
| History after delete | | |
| Store credential scope | | |
| Limits and cost | | |

Store: / Date: / Agent and platform:
Cleaned up: yes or no
Verdict: one of "fits like a dedicated store",
"fits with caveats: ...", or "does not fit: ..."
