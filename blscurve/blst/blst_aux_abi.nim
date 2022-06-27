# blst_aux.h lists unstable interfaces that might be promoted to blst.h depending on their worthiness
# This assumes blst_abi is included

const auxHeaderPath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0] & "/../../vendor/blst/bindings/blst.h"

{.push cdecl, importc, header: headerPath.}

proc blst_derive_master_eip2333*[T: byte|char](
  out_SK: var blst_scalar,
  IKM: openArray[T])

proc blst_derive_child_eip2333*(
  out_SK: var blst_scalar,
  SK: blst_scalar,
  child_index: uint32)

{.pop.}

