import std/[asyncdispatch, httpclient, uri, strutils, options, parseopt, httpcore, tables]
from ./types import ScanTarget, ScanResult, InjectionType, newScanTarget
from ./scanner import scanParameter
from ./utils import addHeader, setDelay

proc showHelp() =
  echo """
NimSQLi - SQL Injection Scanner
Usage: nimsqli [options] <url>

Options:
  -h, --help              Show this help message
  -m, --method=METHOD     HTTP method (GET, POST, PUT, DELETE)
  -p, --param=PARAM       Parameter to test for SQL injection
  -d, --delay=MSEC        Delay between requests in milliseconds (default: 0)
  -t, --timeout=MSEC      Request timeout in milliseconds (default: 10000)
  --data=DATA            POST data
  --header=HEADER        Add custom header (format: "Name: Value")

Examples:
  nimsqli --method=GET --param=id -d 10 "http://example.com/page.php?id=1"
  nimsqli -p=id --method=GET "http://example.com/page.php?id=1"
"""

proc matchesWildcard(str, pattern: string): bool =
  if pattern == "*":
    return true
  if pattern.endsWith("*"):
    return str.startsWith(pattern[0..^2])
  if pattern.startsWith("*"):
    return str.endsWith(pattern[1..^1])
  return str == pattern

proc main() {.async.} =
  var
    url = ""
    httpMethod = HttpGet
    param = ""
    requestDelay = 0
    headers: seq[(string, string)] = @[]
    data = ""
    
  echo "Starting command line parsing..."  # Debug
  var p = initOptParser()
  while true:
    p.next()
    echo "Current token: kind=", p.kind, " key=", p.key, " val=", p.val  # Debug
    case p.kind
    of cmdEnd: 
      echo "Reached end of command line args"  # Debug
      break
    of cmdShortOption, cmdLongOption:
      case p.key.toLowerAscii()
      of "h", "help":
        showHelp()
        quit(0)
      of "m", "method":
        let methodStr = p.val.toUpperAscii()  # Use p.val instead of getting next token
        echo "Method string: '", methodStr, "'"  # Debug
        case methodStr
        of "GET": 
          echo "Setting method to GET"  # Debug
          httpMethod = HttpGet
        of "POST": 
          echo "Setting method to POST"  # Debug
          httpMethod = HttpPost
        of "PUT": 
          echo "Setting method to PUT"  # Debug
          httpMethod = HttpPut
        of "DELETE": 
          echo "Setting method to DELETE"  # Debug
          httpMethod = HttpDelete
        else:
          echo "Error: Invalid HTTP method '", methodStr, "'. Supported methods are: GET, POST, PUT, DELETE"
          quit(1)
      of "p", "param":
        if p.val.len > 0:  # If value is provided with --param=value
          param = p.val
        else:  # If value is provided as next argument
          p.next()
          if p.kind == cmdArgument:
            param = p.key
          else:
            echo "Error: -p/--param requires a value (e.g., -p id or --param=id)"
            quit(1)
        echo "Set param to: ", param  # Debug
      of "d", "delay":
        p.next()  # Get the value after -d
        if p.kind == cmdArgument:
          try:
            requestDelay = parseInt(p.key)
            echo "Set request delay to: ", requestDelay, "ms"  # Debug
          except ValueError:
            echo "Error: Invalid delay value. Must be a number in milliseconds."
            quit(1)
      of "data":
        p.next()  # Get the value after --data
        if p.kind == cmdArgument:
          data = p.key
          echo "Set data to: ", data  # Debug
      of "header":
        p.next()  # Get the value after --header
        if p.kind == cmdArgument:
          let parts = p.key.split(":", 1)
          if parts.len == 2:
            headers.add((parts[0].strip(), parts[1].strip()))
            echo "Added header: ", parts[0].strip(), " = ", parts[1].strip()  # Debug
    of cmdArgument:
      url = p.key
      echo "Set URL to: ", url  # Debug
      
  if url.len == 0:
    showHelp()
    quit(1)
    
  if param.len == 0:
    echo "Error: Parameter to test must be specified with -p"
    quit(1)
    
  var target = newScanTarget(url, httpMethod)
  for (name, value) in headers:
    target.addHeader(name, value)
  
  if data.len > 0:
    target.data = data
    
  target.setDelay(requestDelay)
  if param == "*":
    echo "Testing all parameters..."
    if target.params.len == 0:
      echo "No parameters found in URL. Try adding parameters like: ?param=value"
      quit(1)
    for paramName in target.params.keys():
      echo "Testing parameter: ", paramName
      let result = await scanParameter(target, paramName)
      if result.vulnerable:
        echo "VULNERABLE!"
        echo "Parameter: ", result.parameter
        echo "Payload: ", result.payload
        echo "Details: ", result.details
  elif param.contains('*'):
    echo "Testing parameters matching pattern: ", param
    if target.params.len == 0:
      echo "No parameters found in URL. Try adding parameters like: ?param=value"
      quit(1)
    var foundMatch = false
    for paramName in target.params.keys():
      if matchesWildcard(paramName, param):
        foundMatch = true
        echo "Testing parameter: ", paramName
        let result = await scanParameter(target, paramName)
        if result.vulnerable:
          echo "VULNERABLE!"
          echo "Parameter: ", result.parameter
          echo "Payload: ", result.payload
          echo "Details: ", result.details
    if not foundMatch:
      echo "No parameters found matching pattern: ", param
  
when isMainModule:
  try:
    waitFor main()
  except Exception as e:
    echo "Fatal error: ", e.msg, " (", e.name, ")"
    quit(1) 