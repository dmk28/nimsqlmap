import std/[options, tables, httpcore, times]
import std/strutils
type
  InjectionType* = enum
    Union = "Union",
    Error = "Error",
    Blind = "Blind",
    TimeBased = "TimeBased"
    
  ParamRelation* = object
    name*: string
    value*: string
    parent*: Option[string]  # Track parent parameter if nested
    
  ScanTarget* = ref object
    url*: string
    httpMethod*: HttpMethod
    headers*: HttpHeaders
    params*: TableRef[string, string]
    paramRelations*: seq[ParamRelation]  # Add this field
    data*: string
    delay*: Duration  # Duration type for delay
    timeout*: Duration  # Duration type for timeout
    
  ScanResult* = ref object
    vulnerable*: bool
    injectionType*: Option[InjectionType]
    payload*: string
    parameter*: string
    details*: string

proc parseUrlParams*(url: string): TableRef[string, string] =
  result = newTable[string, string]()
  let parts = url.split('?')
  if parts.len > 1:
    let paramString = parts[1]
    for param in paramString.split('&'):
      let keyVal = param.split('=')
      if keyVal.len == 2:
        # Store both the parameter and its value
        result[keyVal[0]] = keyVal[1]
        # If parameter contains nested values (like mprod=0), store them too
        if keyVal[1].contains({'/', '&'}):
          for nestedParam in keyVal[1].split({'/', '&'}):
            let nestedKeyVal = nestedParam.split('=')
            if nestedKeyVal.len == 2:
              result[nestedKeyVal[0]] = nestedKeyVal[1]

proc newScanTarget*(url: string, httpMethod: HttpMethod): ScanTarget =
  new(result)
  result.url = url.split('?')[0]  # Store base URL without params
  result.httpMethod = httpMethod
  result.headers = newHttpHeaders()
  result.params = parseUrlParams(url)  # Parse URL params automatically
  result.paramRelations = @[]
  result.data = ""
  result.delay = initDuration(milliseconds = 0)
  result.timeout = initDuration(milliseconds = 10000)

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