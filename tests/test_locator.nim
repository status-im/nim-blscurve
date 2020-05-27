import
  # Standard library
  json, strutils, os, streams,
  # Third party
  yaml,
  # Detect spec version
  ../blscurve

export
  os, json

when BLS_ETH2_SPEC == "v0.11.x":
  const ETH2_DIR = currentSourcePath.rsplit(DirSep, 1)[0] / "eth2.0_v0.10.1_vectors"
else:
  const ETH2_DIR = currentSourcePath.rsplit(DirSep, 1)[0] / "eth2.0_v0.12.0_vectors"

proc parseTest*(file: string): JsonNode =
  var yamlStream = openFileStream(file)
  defer: yamlStream.close()
  result = yamlStream.loadToJson()[0]

const SkippedTests = [""]

iterator walkTests*(category: string, skipped: var int): (string, string) =
  let testDir = ETH2_DIR / category

  for file in walkDirRec(testDir, relative = true):
    if file in SkippedTests:
      echo "[WARNING] Skipping - ", file
      inc skipped
      continue

    yield (testDir, file)
