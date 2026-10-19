[CmdletBinding()]
param(
    [string]$BaseUrl = "http://localhost:8000",
    [int]$TimeoutSeconds = 240,
    [int]$PollIntervalSeconds = 2
)

$ErrorActionPreference = "Stop"
$script:CurrentStage = "startup"

function Invoke-Stage {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    $script:CurrentStage = $Name
    try {
        $result = & $Action
        Write-Host "[PASS] $Name"
        return $result
    }
    catch {
        Write-Host "[FAIL] $Name - $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

$loginResponse = $null
$accessToken = $null
$headers = $null
$scanId = $null

$openApiPythonCode = @'
import urllib.request
with urllib.request.urlopen("http://test-api:9000/openapi.json", timeout=15) as response:
    print(response.read().decode("utf-8"))
'@

try {
    $live = Invoke-Stage "API liveness" {
        $response = Invoke-RestMethod -Method Get -Uri "$BaseUrl/health/live" -TimeoutSec 15
        if ($response.status -ne "alive") {
            throw "Unexpected liveness response."
        }
        $response
    }

    $ready = Invoke-Stage "API readiness (PostgreSQL and Redis)" {
        $response = Invoke-RestMethod -Method Get -Uri "$BaseUrl/health/ready" -TimeoutSec 15
        if ($response.status -ne "ready") {
            throw "Unexpected readiness response."
        }
        $response
    }

    $loginResponse = Invoke-Stage "JSON login" {
        $email = $env:CODESENTINEL_EMAIL
        if ([string]::IsNullOrWhiteSpace($email)) {
            $email = Read-Host "CodeSentinel account email"
        }

        $plainPassword = $env:CODESENTINEL_PASSWORD
        $securePassword = $null
        $passwordPointer = [IntPtr]::Zero
        try {
            if ([string]::IsNullOrEmpty($plainPassword)) {
                $securePassword = Read-Host "CodeSentinel account password" -AsSecureString
                $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
                $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
            }
            if ([string]::IsNullOrEmpty($plainPassword)) {
                throw "A password is required."
            }

            $body = @{ email = $email; password = $plainPassword } | ConvertTo-Json -Compress
            $response = Invoke-RestMethod -Method Post -Uri "$BaseUrl/auth/login" `
                -ContentType "application/json" -Body $body -TimeoutSec 20
            if ([string]::IsNullOrWhiteSpace($response.access_token)) {
                throw "Login response did not contain an access token."
            }
            $response
        }
        finally {
            if ($passwordPointer -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
            }
            $plainPassword = $null
            $body = $null
            $email = $null
        }
    }

    $accessToken = [string]$loginResponse.access_token
    $headers = @{ Authorization = "Bearer $accessToken" }

    $null = Invoke-Stage "Authenticated GET /scans" {
        Invoke-RestMethod -Method Get -Uri "$BaseUrl/scans" -Headers $headers -TimeoutSec 20
    }

    $specification = Invoke-Stage "Fetch real synthetic API OpenAPI document over Compose network" {
        # test-api is intentionally not host-published. Run the HTTP request from the API
        # container, which shares the Compose network and resolves the test-api service name.
        $lines = $openApiPythonCode | & docker compose exec -T api python -
        $dockerExitCode = $LASTEXITCODE
        if ($dockerExitCode -ne 0) {
            throw "docker compose exec could not retrieve test-api OpenAPI (exit $dockerExitCode)."
        }
        $raw = ($lines -join "`n").Trim()
        if ([string]::IsNullOrWhiteSpace($raw)) {
            throw "The synthetic API returned an empty OpenAPI document."
        }
        $document = $raw | ConvertFrom-Json
        if ([string]::IsNullOrWhiteSpace($document.openapi) -or $null -eq $document.paths) {
            throw "The response is not an OpenAPI document."
        }
        $pathNames = @($document.paths.PSObject.Properties | ForEach-Object { $_.Name })
        if ($pathNames -notcontains "/cors" -or $pathNames -notcontains "/error") {
            throw "The document did not contain expected bundled synthetic API routes."
        }
        $raw
    }

    $scan = Invoke-Stage "Submit scan and enqueue RQ job" {
        $requestBody = @{
            target = "http://test-api:9000"
            # The API schema requires a string containing the OpenAPI document, not an object.
            specification = $specification
        } | ConvertTo-Json -Depth 10 -Compress

        $response = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$BaseUrl/scans" `
            -Headers $headers -ContentType "application/json" -Body $requestBody -TimeoutSec 30
        if ([int]$response.StatusCode -ne 202) {
            throw "Expected HTTP 202 from scan submission; received $($response.StatusCode)."
        }
        $result = $response.Content | ConvertFrom-Json
        if ([string]::IsNullOrWhiteSpace($result.id)) {
            throw "Scan response did not contain a scan ID."
        }
        if ($result.status -ne "Pending") {
            throw "Expected initial Pending status; received $($result.status)."
        }
        $result
    }
    $scanId = [string]$scan.id
    Write-Host "      Scan ID: $scanId"

    $completedScan = Invoke-Stage "Wait for RQ worker terminal status" {
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
        do {
            $current = Invoke-RestMethod -Method Get -Uri "$BaseUrl/scans/$scanId" `
                -Headers $headers -TimeoutSec 20
            if ($current.status -eq "Completed") {
                return $current
            }
            if ($current.status -eq "Failed" -or $current.status -eq "Cancelled") {
                throw "Scan ended as $($current.status); error=$($current.error_message)."
            }
            Start-Sleep -Seconds $PollIntervalSeconds
        } while ([DateTimeOffset]::UtcNow -lt $deadline)
        throw "Scan did not complete within $TimeoutSeconds seconds (last status: $($current.status))."
    }

    $findings = @(Invoke-Stage "Retrieve persisted findings and verify synthetic signals" {
        $rows = Invoke-RestMethod -Method Get -Uri "$BaseUrl/scans/$scanId/findings" `
            -Headers $headers -TimeoutSec 20
        $items = @($rows)
        if ($items.Count -eq 0) {
            throw "Completed scan returned no findings; expected synthetic CORS and diagnostic signals."
        }
        $checks = @($items | ForEach-Object { $_.check_name })
        if ($checks -notcontains "cors" -or $checks -notcontains "information_exposure") {
            throw "Expected CORS and information-exposure findings were not both present."
        }
        $items
    })

    Write-Host "[PASS] End-to-end demo completed: scan status $($completedScan.status), $($findings.Count) persisted findings."
    Write-Host "      Target was only the bundled synthetic service: http://test-api:9000"
    exit 0
}
catch {
    if ($script:CurrentStage -eq "startup") {
        Write-Host "[FAIL] Demo workflow - $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host "Demo stopped at stage: $script:CurrentStage" -ForegroundColor Red
    exit 1
}
finally {
    # Keep credentials and bearer token out of console output; release local references promptly.
    $accessToken = $null
    $headers = $null
    $loginResponse = $null
    $specification = $null
}
