#Requires -Version 5.1
# Run with: pwsh -NoProfile -File tests/PortnoxRADIUSclient.Tests.ps1
param([string] $SourcePath = (Join-Path (Split-Path $PSScriptRoot -Parent) "PortnoxRADIUSclient.ps1"))
$ErrorActionPreference = "Stop"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors.Message -join "`n") }

foreach ($name in @("Concat-Bytes", "Read-RadSecChunk", "Read-RadiusPacket", "Test-RadSecStreamFault",
    "Parse-EapPacket", "Parse-EapTlsTypeData", "New-EapIdentityResponse", "New-EapTlsResponse", "New-EapNakResponse")) {
    $definition = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (-not $definition) { throw "Missing function: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

Add-Type -Language CSharp @'
using System;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

public class RadiusLoopbackTls : IDisposable {
    readonly TcpClient client;
    readonly TcpClient server;
    public readonly SslStream Client;
    public readonly SslStream Server;
    public RadiusLoopbackTls(X509Certificate2 certificate) {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try {
            client = new TcpClient();
            client.Connect((IPEndPoint)listener.LocalEndpoint);
            server = listener.AcceptTcpClient();
            Server = new SslStream(server.GetStream(), false);
            Client = new SslStream(client.GetStream(), false, (s, c, chain, errors) => true);
            Task.WaitAll(
                Server.AuthenticateAsServerAsync(certificate, false, SslProtocols.Tls12, false),
                Client.AuthenticateAsClientAsync("localhost", new X509CertificateCollection(), SslProtocols.Tls12, false));
        } finally { listener.Stop(); }
    }
    public void Dispose() {
        Client.Dispose(); Server.Dispose(); client.Close(); server.Close();
    }
}

public class RadiusTestStream : Stream {
    readonly byte[] data;
    readonly int chunkSize;
    readonly int delayMs;
    readonly CancellationTokenSource closed = new CancellationTokenSource();
    int position;
    public bool Closed;
    public RadiusTestStream(byte[] bytes, int chunk, int delay) {
        data = bytes; chunkSize = chunk; delayMs = delay;
    }
    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) {
        await Task.Delay(delayMs, closed.Token).ConfigureAwait(false);
        int n = Math.Min(count, Math.Min(chunkSize, data.Length - position));
        Array.Copy(data, position, buffer, offset, n);
        position += n;
        return n;
    }
    public override void Close() { Closed = true; closed.Cancel(); base.Close(); }
    public override bool CanRead { get { return true; } }
    public override bool CanSeek { get { return false; } }
    public override bool CanWrite { get { return false; } }
    public override long Length { get { return data.Length; } }
    public override long Position { get { return position; } set { throw new NotSupportedException(); } }
    public override int Read(byte[] b, int o, int c) { throw new InvalidOperationException("Synchronous read is not bounded"); }
    public override void Flush() {}
    public override long Seek(long o, SeekOrigin s) { throw new NotSupportedException(); }
    public override void SetLength(long n) { throw new NotSupportedException(); }
    public override void Write(byte[] b, int o, int c) { throw new NotSupportedException(); }
}

public class RadiusHelloPipe {
    readonly Stopwatch timer = Stopwatch.StartNew();
    readonly int delayMs;
    public bool Closed;
    public RadiusHelloPipe(int delay) { delayMs = delay; }
    public byte[] TakeOutgoingWait(int timeoutMs) {
        int remaining = delayMs - (int)timer.ElapsedMilliseconds;
        if (remaining > 0) Thread.Sleep(Math.Min(timeoutMs, remaining));
        return timer.ElapsedMilliseconds >= delayMs ? new byte[] {22, 3, 3} : new byte[0];
    }
    public void Close() { Closed = true; }
}

public class RadiusCloseProbe : IDisposable {
    public bool Closed;
    public void Close() { Closed = true; }
    public void Dispose() { Closed = true; }
}
'@

$script:passed = 0
function Assert-True {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }
}
function Test-Case {
    param([string] $Name, [scriptblock] $Action)
    & $Action
    $script:passed++
    Write-Host "PASS: $Name"
}
function Assert-Throws {
    param([scriptblock] $Action, [string] $Pattern)
    $caught = $false
    try { & $Action | Out-Null } catch {
        $caught = $true
        Assert-True ($_.Exception.Message -like $Pattern) "Unexpected error: $($_.Exception.Message)"
    }
    Assert-True $caught "Expected an error matching $Pattern"
}

$packet = [byte[]]::new(20)
$packet[0] = 2
$packet[3] = 20

Test-Case "Partial RADSEC reads assemble an exact packet" {
    $stream = [RadiusTestStream]::new($packet, 2, 5)
    try {
        $actual = Read-RadiusPacket -SslStream $stream -TimeoutMs 1000
        Assert-True (($actual -join ",") -eq ($packet -join ",")) "Packet mismatch"
    } finally { $stream.Close() }
}
Test-Case "Header and body have independent timeout budgets" {
    $stream = [RadiusTestStream]::new($packet, 20, 250)
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $actual = Read-RadiusPacket -SslStream $stream -TimeoutMs 400
        Assert-True ($actual.Length -eq 20 -and $timer.ElapsedMilliseconds -ge 450) "Body did not get its own budget"
    } finally { $stream.Close() }
}
Test-Case "A stalled header times out without waiting for EOF" {
    $stream = [RadiusTestStream]::new($packet, 20, 5000)
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        Assert-Throws { Read-RadiusPacket -SslStream $stream -TimeoutMs 100 } "*Timeout reading RADIUS framing header*"
        Assert-True ($timer.ElapsedMilliseconds -lt 1000) "Header timeout exceeded its bounded window"
    } finally { $stream.Close() }
}
Test-Case "A trickling body cannot extend its total deadline" {
    $stream = [RadiusTestStream]::new($packet, 4, 80)
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        Assert-Throws { Read-RadiusPacket -SslStream $stream -TimeoutMs 150 } "*Timeout gathering multi-segment fragments*"
        Assert-True ($timer.ElapsedMilliseconds -lt 1000) "Body timeout exceeded its bounded window"
    } finally { $stream.Close() }
}
Test-Case "Header EOF and body truncation are retryable stream faults" {
    foreach ($bytes in @([byte[]]::new(0), [byte[]]@(2, 0, 0, 20, 0))) {
        $stream = [RadiusTestStream]::new($bytes, 20, 0)
        $caught = $false
        try { Read-RadiusPacket -SslStream $stream -TimeoutMs 100 | Out-Null } catch {
            $caught = $true
            Assert-True (Test-RadSecStreamFault $_.Exception) "EOF was not retryable"
        } finally { $stream.Close() }
        Assert-True $caught "Expected EOF"
    }
}
Test-Case "Malformed framing is not a transient network fault" {
    $stream = [RadiusTestStream]::new([byte[]]@(2, 0, 0, 10), 4, 0)
    $caught = $false
    try { Read-RadiusPacket -SslStream $stream -TimeoutMs 100 | Out-Null } catch {
        $caught = $true
        Assert-True (-not (Test-RadSecStreamFault $_.Exception)) "Malformed framing must not be retried"
    } finally { $stream.Close() }
    Assert-True $caught "Expected framing error"
}
Test-Case "Wrapped socket resets retry, certificate and configuration failures do not" {
    $reset = [System.Net.Sockets.SocketException]::new(10054)
    Assert-True (Test-RadSecStreamFault ([System.IO.IOException]::new("reset", $reset))) "Wrapped reset not recognized"
    Assert-True (-not (Test-RadSecStreamFault ([System.Security.Authentication.AuthenticationException]::new("certificate")))) "Certificate failure retry"
    Assert-True (-not (Test-RadSecStreamFault ([System.ArgumentException]::new("configuration")))) "Configuration failure retry"
    Assert-True (-not (Test-RadSecStreamFault ([System.Net.Sockets.SocketException]::new(10022)))) "Invalid socket argument retry"
}

if ("System.Security.Cryptography.X509Certificates.CertificateRequest" -as [type]) {
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=localhost", $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddMinutes(5))
    try {
        Test-Case "Real TLS peer stalled before the RADIUS header is bounded" {
            $tls = [RadiusLoopbackTls]::new($certificate)
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                Assert-Throws { Read-RadiusPacket -SslStream $tls.Client -TimeoutMs 150 } "*Timeout reading RADIUS framing header*"
                Assert-True ($timer.ElapsedMilliseconds -lt 1000) "Real TLS header read was not bounded"
            } finally { $tls.Dispose() }
        }
        Test-Case "Real TLS peer stalled after the RADIUS header is bounded" {
            $tls = [RadiusLoopbackTls]::new($certificate)
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $tls.Server.Write($packet, 0, 4)
                $tls.Server.Flush()
                Assert-Throws { Read-RadiusPacket -SslStream $tls.Client -TimeoutMs 150 } "*Timeout gathering multi-segment fragments*"
                Assert-True ($timer.ElapsedMilliseconds -lt 1000) "Real TLS body read was not bounded"
            } finally { $tls.Dispose() }
        }
    } finally { $certificate.Dispose(); $rsa.Dispose() }
} else {
    Write-Host "SKIP: real TLS stall tests require CertificateRequest (run with PowerShell 7)."
}

$retryLoop = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.WhileStatementAst] -and
        $node.Extent.Text -match '^while \(\$true\) \{\s*\$pendingRadSecRetry'
}, $true)
if (-not $retryLoop) { throw "Missing authentication retry loop" }
$mainUnderTest = [scriptblock]::Create(@'
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$maxTransientRadSecRetries = 1
$transientRadSecAttempt = 0
'@ + "`n" + $retryLoop.Extent.Text)

function New-TlsStream {
    $script:connections++
    if ($script:scenario -eq "certificate") { throw [System.Security.Authentication.AuthenticationException]::new("certificate") }
    $probe = [RadiusCloseProbe]::new()
    $script:transports.Add($probe)
    return @{ Ssl = $probe; Tcp = $null }
}
function New-RadiusUdpConnection { return New-TlsStream }
function Build-AccessRequest {
    param([byte[]] $State, [byte[]] $EapMessage)
    $script:requests.Add([pscustomobject]@{ State = $State; Eap = $EapMessage })
    return [byte[]]@(1)
}
function Send-AndReceiveRadiusPacket {
    $script:exchanges++
    if ($script:scenario -eq "always-fail" -or
        ($script:scenario -eq "retry" -and $script:exchanges -eq 2)) {
        Start-Sleep -Milliseconds 200
        throw [System.IO.IOException]::new("simulated stream interruption")
    }
    $script:lastCode = if ($AuthType -in @("PAP", "MAB") -or $script:scenario -eq "reject") {
        if ($script:scenario -eq "reject") { 3 } else { 2 }
    } elseif ($script:exchanges % 2 -eq 1) { 11 } else { 2 }
    return [byte[]]@(1)
}
function Parse-RadiusResponse {
    return [pscustomobject]@{
        Code = $script:lastCode
        CodeName = switch ($script:lastCode) { 2 { "Access-Accept" }; 3 { "Access-Reject" }; 11 { "Access-Challenge" } }
        Attributes = @()
    }
}
function Get-AttributeConcat {
    param($Attributes, [int] $Type)
    if ($Type -eq 24) { return [byte[]]@(99) }
    $typeId = switch ($AuthType) { "EAP-PEAP" { 25 }; "EAP-TTLS" { 21 }; default { 13 } }
    return [byte[]]@(1, 1, 0, 6, $typeId, 32)
}
function Get-EapTypeName { return "test-method" }
function Test-TruthyToken { return $false }
function New-EapTlsEngine {
    $pipe = [RadiusHelloPipe]::new($script:helloDelay)
    $ssl = [RadiusCloseProbe]::new()
    $script:pipes.Add($pipe)
    $script:innerStreams.Add($ssl)
    $taskSource = [System.Threading.Tasks.TaskCompletionSource[bool]]::new()
    if ($script:scenario -eq "startup-fault") {
        $taskSource.SetException([System.Exception]::new("simulated TLS startup fault"))
    }
    return [pscustomobject]@{ Pipe = $pipe; Ssl = $ssl; AuthTask = $taskSource.Task }
}
function Write-AuthenticationSummary {
    param([string] $FinalResponse, [long] $ElapsedMilliseconds)
    $script:OrionExitCode = if ($FinalResponse -eq "Access-Accept") { 0 } else { 3 }
    return [pscustomobject]@{ FinalResponse = $FinalResponse; ElapsedMilliseconds = $ElapsedMilliseconds }
}
function Stop-Transcript { $script:transcriptStops++ }
function Remove-Item { $script:transcriptDeletes++ }
function Move-Item { $script:transcriptMoves++ }
function Invoke-Conversation {
    param([string] $Method = "EAP-TTLS", [string] $Scenario = "accept", [int] $HelloDelay = 0,
        [int] $Timeout = 2000, [string] $Mode = "RADSEC", [int] $Rounds = 10, [switch] $CaptureTranscript)
    $script:scenario = $Scenario
    $script:helloDelay = $HelloDelay
    $script:connections = 0
    $script:exchanges = 0
    $script:requests = [System.Collections.Generic.List[object]]::new()
    $script:pipes = [System.Collections.Generic.List[RadiusHelloPipe]]::new()
    $script:innerStreams = [System.Collections.Generic.List[RadiusCloseProbe]]::new()
    $script:transports = [System.Collections.Generic.List[RadiusCloseProbe]]::new()
    $script:DebugTranscriptStarted = $CaptureTranscript.IsPresent
    $script:transcriptStops = 0
    $script:transcriptDeletes = 0
    $script:transcriptMoves = 0
    $script:IsOrionMode = $false
    $AuthType = $Method
    $Transport = $Mode
    $timeoutMs = $Timeout
    $MaxEapRounds = $Rounds
    $MaxEapTlsFragmentSize = 1000
    $Username = "test@example.invalid"
    $PeapOuterIdentity = $Username
    $PeapInnerIdentity = $Username
    $DebugOutput = [switch]$false
    $EmitResultObject = [switch]$true
    $Prtg = [switch]$false
    $PeapPhase2SetLengthBit = [switch]$false
    $PeapPhase2AckBeforeData = [switch]$false
    & $mainUnderTest
}

foreach ($method in @("EAP-TLS", "EAP-TTLS", "EAP-PEAP")) {
    Test-Case "$method waits for delayed ClientHello and never NAKs its own method" {
        $result = Invoke-Conversation -Method $method -HelloDelay 1200
        Assert-True ($result.FinalResponse -eq "Access-Accept") "Expected accept"
        Assert-True ($script:requests[1].Eap[4] -ne 3) "Supported method produced a NAK"
        Assert-True ($script:pipes[0].Closed -and $script:innerStreams[0].Closed) "Inner TLS was not cleaned up"
    }
}
Test-Case "Missing ClientHello fails explicitly and cleans up, without replay" {
    Assert-Throws { Invoke-Conversation -HelloDelay 5000 -Timeout 100 } "*did not produce a ClientHello within 100 ms*"
    Assert-True ($script:exchanges -eq 1 -and $script:connections -eq 1) "Unexpected NAK or replay"
    Assert-True ($script:pipes[0].Closed -and $script:innerStreams[0].Closed -and $script:transports[0].Closed) "Incomplete cleanup"
}
Test-Case "TLS startup faults surface explicitly without a contradictory NAK" {
    Assert-Throws { Invoke-Conversation -Scenario "startup-fault" } "*initialization failed completely: simulated TLS startup fault*"
    Assert-True ($script:exchanges -eq 1 -and $script:pipes[0].Closed) "Startup failure sent a NAK or leaked its pipe"
}
Test-Case "RADSEC reconnect resets identity and State and includes failed-attempt latency" {
    $result = Invoke-Conversation -Scenario "retry"
    Assert-True ($result.FinalResponse -eq "Access-Accept" -and $script:connections -eq 2) "Retry did not succeed"
    Assert-True ($script:requests[2].Eap[4] -eq 1 -and -not $script:requests[2].State) "Retry reused EAP state"
    Assert-True ($result.ElapsedMilliseconds -ge 200) "Failed attempt was excluded from elapsed time"
    Assert-True (($script:transports | Where-Object { -not $_.Closed }).Count -eq 0) "Transport leaked"
    Assert-True (($script:pipes | Where-Object { -not $_.Closed }).Count -eq 0) "Inner pipe leaked"
}
Test-Case "Persistent RADSEC failure stops after exactly one reconnect" {
    Assert-Throws { Invoke-Conversation -Scenario "always-fail" } "*simulated stream interruption*"
    Assert-True ($script:connections -eq 2) "Retry limit not enforced"
}
Test-Case "A retry finalizes the transcript only once, after the final result" {
    $result = Invoke-Conversation -Scenario "retry" -CaptureTranscript
    Assert-True ($result.FinalResponse -eq "Access-Accept") "Expected retry success"
    Assert-True ($script:transcriptStops -eq 1 -and $script:transcriptDeletes -eq 1 -and $script:transcriptMoves -eq 0) "Transcript finalized before retry or mislabeled as failure"
}
Test-Case "UDP errors do not trigger RADSEC conversation replay" {
    Assert-Throws { Invoke-Conversation -Scenario "always-fail" -Mode "RADIUS" } "*simulated stream interruption*"
    Assert-True ($script:connections -eq 1) "UDP conversation was replayed"
}
Test-Case "Explicit rejection and certificate failure do not replay" {
    $result = Invoke-Conversation -Scenario "reject"
    Assert-True ($result.FinalResponse -eq "Access-Reject" -and $script:connections -eq 1) "Reject replayed"
    Assert-Throws { Invoke-Conversation -Scenario "certificate" } "*certificate*"
    Assert-True ($script:connections -eq 1) "Certificate failure replayed"
}
Test-Case "EAP round exhaustion fails instead of silently returning" {
    Assert-Throws { Invoke-Conversation -Rounds 1 } "*Maximum EAP rounds*"
}
foreach ($method in @("PAP", "MAB")) {
    Test-Case "$method still completes in one exchange" {
        $result = Invoke-Conversation -Method $method
        Assert-True ($result.FinalResponse -eq "Access-Accept" -and $script:exchanges -eq 1) "Single-round behavior changed"
        Assert-True $script:transports[0].Closed "Transport not closed"
    }
}
Test-Case "TTLS debug output does not dump the plaintext credential payload" {
    $source = Get-Content -LiteralPath $sourcePath -Raw
    Assert-True ($source -notmatch 'Bytes-ToHex \$ttlsPayload') "TTLS password hex dump remains"
}
Write-Host "$script:passed tests passed."
