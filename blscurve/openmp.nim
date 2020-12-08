# Nim-BLST
# Copyright (c) 2020 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.
#
# Laser
# Copyright (c) 2018 Mamy André-Ratsimbazafy
# Distributed under the Apache v2 License (license terms are at http://www.apache.org/licenses/LICENSE-2.0).
# This file may not be copied, modified, or distributed except according to those terms.

when defined(openmp):
  {.passC: "-fopenmp".}
  {.passL: "-fopenmp".}

  {.pragma: omp, header:"omp.h".}

  proc omp_set_num_threads*(x: cint) {.omp.}
  proc omp_get_num_threads*(): cint {.omp.}
    ## Returns the number of threads assigned to this region
    ##
    ## Warning, this will always return 1 in a non-parallel region
    ## use `omp_get_max_threads` to get the number of threads
    ## available in a serial portion of the code.
  proc omp_get_max_threads*(): cint {.omp.} # This takes hyperthreading into account
  proc omp_get_thread_num*(): cint {.omp.}
  proc omp_set_nested*(x: cint) {.omp.}
  proc omp_get_nested*(): cint {.omp.}

else:
  template omp_set_num_threads*(x: cint) = discard
  template omp_get_num_threads*(): cint = 1
    ## Returns the number of threads assigned to this region
    ##
    ## Warning, this will always return 1 in a non-parallel region
    ## use `omp_get_max_threads` to get the number of threads
    ## available in a serial portion of the code.
  template omp_get_max_threads*(): cint = 1
  template omp_get_thread_num*(): cint = 0
  template omp_set_nested*(x: cint) = discard
  template omp_get_nested*(): cint = cint 0

# ################################################################

template attachGC*(): untyped =
  ## If you are allocating reference types, sequences or strings
  ## in a parallel section, you need to attach and detach
  ## a GC for each thread. Those should be thread-local temporaries.
  ##
  ## This attaches the GC.
  ##
  ## Note: this creates too strange error messages
  ## when --threads is not on: https://github.com/nim-lang/Nim/issues/9489
  if(omp_get_thread_num()!=0):
    setupForeignThreadGc()

template detachGC*(): untyped =
  ## If you are allocating reference types, sequences or strings
  ## in a parallel section, you need to attach and detach
  ## a GC for each thread. Those should be thread-local temporaries.
  ##
  ## This detaches the GC.
  ##
  ## Note: this creates too strange error messages
  ## when --threads is not on: https://github.com/nim-lang/Nim/issues/9489
  if(omp_get_thread_num()!=0):
    teardownForeignThreadGc()

template omp_parallel*(body: untyped): untyped =
  ## Starts an openMP parallel section
  ##
  ## Don't forget to use attachGC and detachGC if you are allocating
  ## sequences, strings, or reference types.
  ## Those should be thread-local temporaries.
  {.emit: "#pragma omp parallel".}
  block: body

template omp_parallel_if*(condition: bool, body: untyped) =
  let predicate = condition # Make symbol valid and ensure it's a lvalue
  {.emit: ["#pragma omp parallel if (",predicate,")"].}
  block: body

template omp_for*(
    index: untyped,
    length: Natural,
    annotation: static string,
    body: untyped
  ) =
  ## OpenMP for loop (not parallel)
  ##
  ## This must be used in an `omp_parallel` block
  ## for parallelization.
  ##
  ## Inputs:
  ##   - `index`, the iteration index, similar to
  ##     for `index` in 0 ..< length:
  ##       doSomething(`index`)
  ##   - `length`, the number of elements to iterate on
  ##
  ## Defaults to OpenMP defaults
  ## - nowait: off
  ## - simd: off
  ## - schedule: static
  ## Change "annotation" otherwise
  const omp_annotation = "for " & annotation
  for `index`{.inject.} in `||`(0, length-1, omp_annotation):
    block: body

template omp_chunks*(
    omp_size: Natural, #{lvalue} # TODO parameter constraint, pending https://github.com/nim-lang/Nim/issues/9620
    chunk_offset, chunk_size: untyped,
    body: untyped): untyped =
  ## Internal proc
  ## This is is the chunk part of omp_parallel_chunk
  ## omp_size should be a lvalue (assigned value) and not
  ## the result of a routine otherwise routine and its side-effect will be called multiple times
  ##
  ## If the omp_size to split in equal chunks of work
  ## is less than the number of threads, the extra threads
  ## will execute any code.
  ## In particular indexing with a thread ID
  ## into a sequence of size min(omp_size, omp_get_num_threads())
  ## is safe.

  # The following simple chunking scheme can lead to severe load imbalance
  #
  # `chunk_offset`{.inject.} = chunk_size * thread_id
  # `chunk_size`{.inject.} =  if thread_id < nb_chunks - 1: chunk_size
  #                           else: omp_size - chunk_offset
  #
  # For example dividing 40 items on 12 threads will lead to
  # a base_chunk_size of 40/12 = 3 so work on the first 11 threads
  # will be 3 * 11 = 33, and the remainder 7 on the last thread.
  let
    nb_chunks = omp_get_num_threads().uint32
    base_chunk_size = omp_size div nb_chunks
    remainder = omp_size mod nb_chunks
    thread_id = omp_get_thread_num().uint32

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

  var `chunk_offset`{.inject.}, `chunk_size`{.inject.}: Natural
  if thread_id < remainder:
    chunk_offset = (base_chunk_size + 1) * thread_id
    chunk_size = base_chunk_size + 1
  else:
    chunk_offset = base_chunk_size * thread_id + remainder
    chunk_size = base_chunk_size

  # If the number of threads is greater than the omp_size to split
  # we have
  #   base_chunk_size = 0
  #   remainder = omp_size
  # hence threadID < omp_size will receive one chunk each
  # and we need to skip processing for the extra threads

  block:
    if thread_id < omp_size:
      body

template omp_critical*(body: untyped): untyped =
  {.emit: "#pragma omp critical".}
  block: body

template omp_master*(body: untyped): untyped =
  {.emit: "#pragma omp master".}
  block: body

template omp_single*(body: untyped): untyped =
  {.emit: "#pragma omp single".}
  block: body

template omp_single_nowait*(body: untyped): untyped =
  {.emit: "#pragma omp single nowait".}
  block: body

template omp_barrier*(): untyped =
  {.emit: "#pragma omp barrier".}

template omp_task*(annotation: static string, body: untyped): untyped =
  {.emit: "#pragma omp task " & annotation.}
  block: body

template omp_taskwait*(): untyped =
  {.emit: "#pragma omp taskwait".}

template omp_taskloop*(
    index: untyped,
    length: Natural,
    annotation: static string,
    body: untyped
  ) =
  ## OpenMP taskloop
  const omp_annotation = "taskloop " & annotation
  for `index`{.inject.} in `||`(0, length-1, omp_annotation):
    block: body

import macros
macro omp_flush*(variables: varargs[untyped]): untyped =
  var listvars = "("
  for i, variable in variables:
    if i == 0:
      listvars.add "`" & $variable & "`"
    else:
      listvars.add ",`" & $variable & "`"
  listvars.add ')'
  result = quote do:
    {.emit: "#pragma omp flush " & `listvars`.}
