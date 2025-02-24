import std/[asyncdispatch, httpclient, uri, strutils, options, parseopt, httpcore]
from ./types import ScanTarget, ScanResult, InjectionType, newScanTarget
from ./scanner import scanParameter
from ./utils import addHeader, setDelay

proc showHelp() =
  echo """
NimSQLi - SQL Injection Scanner
Usage: nimsqli [options] <url>

Options:
  -h, --help            Show this help message
  -m, --method=METHOD   HTTP method (GET, POST, PUT, DELETE)
  -p, --param=PARAM     Parameter to test
  -d, --delay=MSEC     Delay between requests in milliseconds (default: 0)
  -t, --timeout=MSEC   Request timeout in milliseconds (default: 10000)
  --data=DATA          POST data
  --header=HEADER      Add custom header (format: "Name: Value")
"""

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
        p.next()  # Get the value after -m
        if p.kind == cmdArgument:
          let methodStr = p.key.toUpperAscii()
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
        p.next()  # Get the value after -p
        if p.kind == cmdArgument:
          param = p.key
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
  let result = await scanParameter(target, param)
  
  if result.vulnerable:
    echo "VULNERABLE!"
    echo "Parameter: ", result.parameter
    echo "Payload: ", result.payload
    echo "Details: ", result.details
  else:
    echo "No SQL injection vulnerability detected."
  
when isMainModule:
  try:
    waitFor main()
  except Exception as e:
    echo "Fatal error: ", e.msg, " (", e.name, ")"
    quit(1) 