import
  # Standard library
  json, strutils, os, streams,
  # Third party
  yaml

export
  os, json

const ETH2_DIR = currentSourcePath.rsplit(DirSep, 1)[0] / "eth2.0_v0.10.1_vectors"

proc parseTest*(file: string): JsonNode =
  var yamlStream = openFileStream(file)
  defer: yamlStream.close()
  result = yamlStream.loadToJson()[0]

const SkippedTests = [
  "small"/"fast_aggregate_verify_e6922a0d196d9869"/"data.yaml", # Buggy upstream vector: https://github.com/ethereum/eth2.0-specs/issues/1618
  "small"/"fast_aggregate_verify_62bca7cd61880e26"/"data.yaml",
  "small"/"fast_aggregate_verify_3b2b0141e95125f0"/"data.yaml",
]

iterator walkTests*(category: string, skipped: var int): (string, string) =
  let testDir = ETH2_DIR / category

  for file in walkDirRec(testDir, relative = true):
    if file in SkippedTests:
      echo "[WARNING] Skipping - ", file
      inc skipped
      continue

    yield (testDir, file)

