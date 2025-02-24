import std/[options, tables, httpcore, times]

type
  InjectionType* = enum
    Union = "Union",
    Error = "Error",
    Blind = "Blind",
    TimeBased = "TimeBased"
    
  ScanTarget* = ref object
    url*: string
    httpMethod*: HttpMethod
    headers*: HttpHeaders
    params*: TableRef[string, string]
    data*: string
    delay*: Duration  # Duration type for delay
    timeout*: Duration  # Duration type for timeout
    
  ScanResult* = ref object
    vulnerable*: bool
    injectionType*: Option[InjectionType]
    payload*: string
    parameter*: string
    details*: string

proc newScanTarget*(url: string, httpMethod: HttpMethod): ScanTarget =
  new(result)
  result.url = url
  result.httpMethod = httpMethod
  result.headers = newHttpHeaders()  # Initialize with newHttpHeaders from httpcore
  result.params = newTable[string, string]()
  result.data = ""
  result.delay = initDuration(milliseconds = 0)  # No delay by default
  result.timeout = initDuration(milliseconds = 10000)  # Default 10 second timeout

proc setDelay*(target: var ScanTarget, milliseconds: int) =
  target.delay = initDuration(milliseconds = milliseconds)

proc setTimeout*(target: var ScanTarget, milliseconds: int) =
  target.timeout = initDuration(milliseconds = milliseconds)

proc setData*(target: var ScanTarget, data: string) =
  target.data = data

proc addHeader*(target: var ScanTarget, key, value: string) =
  target.headers.add(key, value)

proc addParam*(target: ScanTarget, key, value: string) =
  if target.params == nil:
    target.params = newTable[string, string]()
  target.params[key] = value

# Export field accessors
proc `url=`*(target: var ScanTarget, value: string) = target.url = value
proc `httpMethod=`*(target: var ScanTarget, value: HttpMethod) = target.httpMethod = value
proc `data=`*(target: var ScanTarget, value: string) = target.data = value
proc `delay=`*(target: var ScanTarget, value: Duration) = target.delay = value
proc `timeout=`*(target: var ScanTarget, value: Duration) = target.timeout = value

# Export field getters
proc url*(target: ScanTarget): string = target.url
proc httpMethod*(target: ScanTarget): HttpMethod = target.httpMethod
proc headers*(target: ScanTarget): HttpHeaders = target.headers
proc params*(target: ScanTarget): TableRef[string, string] = target.params
proc data*(target: ScanTarget): string = target.data
proc delay*(target: ScanTarget): Duration = target.delay
proc timeout*(target: ScanTarget): Duration = target.timeout 