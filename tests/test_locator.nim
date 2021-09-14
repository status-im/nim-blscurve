import
  # Standard library
  json, strutils, os,
  # Detect spec version
  ../blscurve

export
  os, json

const ETH2_DIR = currentSourcePath.rsplit(DirSep, 1)[0] / "ef-bls12381-vectors-v0.1.0"

proc parseTest*(file: string): JsonNode =
  result = json.parseFile(file)

const SkippedTests = [""]

iterator walkTests*(category: string, skipped: var int): (string, string) =
  let testDir = ETH2_DIR / category

  for file in walkDirRec(testDir, relative = true):
    if file in SkippedTests:
      echo "[WARNING] Skipping - ", file
      inc skipped
      continue

    yield (testDir, file)
