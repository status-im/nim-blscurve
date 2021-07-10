# Nim-BLST
# Copyright (c) 2020 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

template parallel_chunks*(
    numChunks: int,
    totalSize: int,
    chunkID: int,
    chunkOffset, chunkSize: untyped,
    body: untyped): untyped =
  ## Parallel balanced chunking algorithm
  ## This splits a range into balanced parallel regions

  # Rationale
  # The following simple chunking scheme can lead to severe load imbalance
  #
  # `chunk_offset`{.inject.} = chunk_size * thread_id
  # `chunk_size`{.inject.} =  if thread_id < nb_chunks - 1: chunk_size
  #                           else: omp_size - chunk_offset
  #
  # For example dividing 40 items on 12 threads will lead to
  # a base_chunk_size of 40/12 = 3 so work on the first 11 threads
  # will be 3 * 11 = 33, and the remainder 7 on the last thread.
  #
  # Instead of dividing 40 work items on 12 cores into:
  # 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 7 = 3*11 + 7 = 40
  # the following scheme will divide into
  # 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3 = 4*4 + 3*8 = 40
  #
  # This is compliant with OpenMP spec (page 60)
  # http://www.openmp.org/mp-documents/openmp-4.5.pdf
  # "When no chunk_size is specified, the iteration space is divided into chunks
  # that are approximately equal in size, and at most one chunk is distributed to
  # each thread. The size of the chunks is unspecified in this case."
  # ---> chunks are the same ±1

  let # Assign inputs to avoid evaluate side-effects twice.
    cID = chunkID
    nb_chunks = numChunks
    size = totalSize
    base_chunk_size = size.int div nb_chunks
    remainder = size.int mod nb_chunks

  var `chunkOffset`{.inject.}, `chunkSize`{.inject.}: int
  if cID < remainder:
    chunk_offset = (base_chunk_size + 1) * cID
    chunk_size = base_chunk_size + 1
  else:
    chunk_offset = base_chunk_size * cID + remainder
    chunk_size = base_chunk_size

  # If the number of threads is greater than the size to split
  # we have
  #   base_chunk_size = 0
  #   remainder = size
  # hence cID < size will receive one chunk each
  # and we need to skip processing for the extra threads

  block:
    if cID < size.int:
      body
