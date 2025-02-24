import std/[tables, httpcore, times]
from types import ScanTarget

proc addHeader*(target: var ScanTarget, key, value: string) =
  if key != "":
    target.headers.add(key, value)
  else:
    echo "Error: Header key cannot be empty"

proc addParam*(target: var ScanTarget, key, value: string) =
  if target.params == nil:
    target.params = newTable[string, string]()
  target.params[key] = value

proc setData*(target: var ScanTarget, data: string) =
  target.data = data

proc setDelay*(target: var ScanTarget, milliseconds: int) =
  target.delay = initDuration(milliseconds = milliseconds)

proc setTimeout*(target: var ScanTarget, milliseconds: int) =
  target.timeout = initDuration(milliseconds = milliseconds) 