param(
    [string]$RepoName = "bitirme_anomali_tespit",
    [switch]$Private,
    [string]$Token
)

if (![string]::IsNullOrEmpty($Token)) {
    $env:GITHUB_TOKEN = $Token
}

Write-Host "Preparing local git repository..."
if (-not (Test-Path -Path .git)) {
    git init
    git add .
    git commit -m "Initial commit" -q
    git branch -M main
} else {
    Write-Host "Local git repo already initialized."
}

$isPrivate = $Private.IsPresent

if (Get-Command gh -ErrorAction SilentlyContinue) {
    Write-Host "Using GitHub CLI to create the repo..."
    if ($isPrivate) { gh repo create $RepoName --private --source=. --remote=origin --push } else { gh repo create $RepoName --public --source=. --remote=origin --push }
    exit $LASTEXITCODE
}

if (-not $env:GITHUB_TOKEN) {
    Write-Error "GITHUB_TOKEN environment variable not set and GitHub CLI not installed. Please install GitHub CLI or set env var GITHUB_TOKEN with a Personal Access Token (repo scope)."
    exit 1
}

$visibility = if ($isPrivate) { "true" } else { "false" }
$body = @{ name = $RepoName; description = "Thesis anomaly detection project"; private = $isPrivate } | ConvertTo-Json

Write-Host "Creating repo using GitHub API..."
$headers = @{ Authorization = "token $($env:GITHUB_TOKEN)"; "User-Agent" = "$RepoName" }
$response = Invoke-RestMethod -Uri "https://api.github.com/user/repos" -Headers $headers -Method Post -Body $body -ContentType "application/json"

if ($response -and $response.clone_url) {
    git remote add origin $response.clone_url -f
    git push -u origin main
    Write-Host "Repo created and pushed: $($response.html_url)"
} else {
    Write-Error "Failed to create repo. Response: $response"
    exit 1
}
