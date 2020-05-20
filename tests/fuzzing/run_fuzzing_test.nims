import strformat
import os except paramCount, paramStr, fileExists # these are also defined in the system module
import confutils, testutils/fuzzing_engines

cli do (testName {.argument.}: string,
        fuzzer = libFuzzer):
  let
    fuzzingDir = thisDir()
    fuzzingFile = fuzzingDir / "fuzz_" & addFileExt(testName, "nim")
    corpusDir = fuzzingDir / "corpus" / testName

  if not fileExists(fuzzingFile):
    echo testName, " is not a recognized fuzzing test"
    quit 1

  let
    collectCorpusNim = fuzzingDir / "collect_corpus.nim"
    fuzzNims = fuzzingDir / ".." / ".." / ".." / "nim-testutils" / "testutils" / "fuzzing" / "fuzz.nims"

  exec &"""nim c -r "{collectCorpusNim}""""
  exec &"""nim "{fuzzNims}" {fuzzer} "{fuzzingFile}" "{corpusDir}" """

