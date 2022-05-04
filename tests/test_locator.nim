import
  # Standard library
  json, strutils, os
export
  os, json

const ETH2_DIR = currentSourcePath.rsplit(DirSep, 1)[0] / "ef-bls12381-vectors-v0.1.1"

proc parseTest*(file: string): JsonNode =
  json.parseFile(file)

const SkippedTests = [
  # For genericity, requires successful deserialization of infinity G1 points,
  # but since they are pubkeys in Ethereum
  # and infinity pubkeys aren't allowed, we can't pass this test.
  # see also https://github.com/ethereum/consensus-specs/issues/2538#issuecomment-892051323
  "deserialization_succeeds_infinity_with_true_b_flag.json"
]

iterator walkTests*(category: string, skipped: var int): (string, string) =
  let testDir = ETH2_DIR / category

  for file in walkDirRec(testDir, relative = true):
    if file in SkippedTests:
      echo "[WARNING] Skipping - ", file
      inc skipped
      continue

    yield (testDir, file)
