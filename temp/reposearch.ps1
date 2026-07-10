$ErrorActionPreference = "SilentlyContinue"

try {
  $Root = (git rev-parse --show-toplevel).Trim()
  Set-Location $Root
} catch {
  $Root = (Get-Location).Path
}

$Rows = New-Object System.Collections.Generic.List[object]

function Get-RepoPath {
  param([string]$Path)

  $full = [System.IO.Path]::GetFullPath($Path)
  $rel = $full.Substring($Root.Length).TrimStart('\','/')
  return "./" + ($rel -replace "\\", "/")
}

function Add-Dependency {
  param(
    [string]$File,
    [string]$Ecosystem,
    [string]$Dependency,
    [string]$Version = "",
    [string]$Kind = "",
    [string]$Section = ""
  )

  if ([string]::IsNullOrWhiteSpace($Dependency)) {
    return
  }

  $Rows.Add([pscustomobject]@{
    Ecosystem  = $Ecosystem
    Directory  = "/"
    Dependency = $Dependency.Trim()
    Version    = $Version.Trim()
    Kind       = $Kind
    File       = Get-RepoPath $File
    Section    = $Section
  }) | Out-Null
}

function Read-JsonSafe {
  param([string]$Path)

  try {
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
  } catch {
    return $null
  }
}

function Add-JsonDeps {
  param(
    [object]$Json,
    [string]$Path,
    [string]$Ecosystem,
    [string]$Section
  )

  if ($null -eq $Json) {
    return
  }

  $prop = $Json.PSObject.Properties[$Section]

  if ($null -eq $prop) {
    return
  }

  foreach ($p in $prop.Value.PSObject.Properties) {
    $version = ""

    if ($null -ne $p.Value) {
      if ($p.Value -is [string]) {
        $version = $p.Value
      } else {
        $version = $p.Value | ConvertTo-Json -Compress -Depth 20
      }
    }

    Add-Dependency $Path $Ecosystem $p.Name $version "manifest" $Section
  }
}

function Parse-RequirementsLine {
  param(
    [string]$Path,
    [string]$Line,
    [string]$Section
  )

  $line = $Line.Trim()

  if ([string]::IsNullOrWhiteSpace($line)) {
    return
  }

  if ($line.StartsWith("#")) {
    return
  }

  $line = ($line -replace "\s+#.*$", "").Trim()

  if ([string]::IsNullOrWhiteSpace($line)) {
    return
  }

  if ($line -match "^\s*(-r|--requirement)\s+(.+)$") {
    Add-Dependency $Path "pip" $Matches[2] "" "included-requirements-file" $Section
    return
  }

  if ($line -match "^\s*(-c|--constraint)\s+(.+)$") {
    Add-Dependency $Path "pip" $Matches[2] "" "constraints-file" $Section
    return
  }

  if ($line -match "#egg=([^&\s]+)") {
    Add-Dependency $Path "pip" $Matches[1] "" "vcs-or-url" $Section
    return
  }

  if ($line -match "^([A-Za-z0-9_.-]+(?:\[[^\]]+\])?)\s*@\s*(.+)$") {
    Add-Dependency $Path "pip" $Matches[1] $Matches[2] "direct-reference" $Section
    return
  }

  if ($line -match "^([A-Za-z0-9_.-]+(?:\[[^\]]+\])?)\s*([<>=!~]=?|===)\s*(.+)$") {
    Add-Dependency $Path "pip" $Matches[1] "$($Matches[2])$($Matches[3])" "manifest" $Section
    return
  }

  if ($line -match "^[A-Za-z0-9_.-]+(?:\[[^\]]+\])?$") {
    Add-Dependency $Path "pip" $line "" "manifest" $Section
    return
  }
}

$Files = Get-ChildItem -Path $Root -Recurse -File -Force |
  Where-Object {
    $_.FullName -notlike "*\.git\*" -and
    $_.Name -notin @("reposearch.ps1")
  }

foreach ($file in $Files) {
  $path = $file.FullName
  $name = $file.Name
  $ext = $file.Extension.ToLowerInvariant()

  try {
    $text = Get-Content -LiteralPath $path -Raw
  } catch {
    continue
  }

  # GitHub Actions, reusable workflows, local actions
  if ($ext -in @(".yml", ".yaml")) {
    foreach ($m in [regex]::Matches($text, '(?m)^\s*uses:\s*["'']?([^@\s"'']+)(?:@([^"''\s#]+))?')) {
      $dep = $m.Groups[1].Value
      $ver = $m.Groups[2].Value

      $kind = if ($dep -like "./*") {
        "local-action-or-workflow"
      } elseif ($dep -like "docker://*") {
        "docker-action"
      } else {
        "github-action-or-reusable-workflow"
      }

      Add-Dependency $path "github-actions" $dep $ver $kind "uses"
    }
  }

  # npm / Node
  if ($name -eq "package.json") {
    $json = Read-JsonSafe $path

    foreach ($section in @(
      "dependencies",
      "devDependencies",
      "peerDependencies",
      "optionalDependencies",
      "bundledDependencies",
      "bundleDependencies",
      "overrides",
      "resolutions"
    )) {
      Add-JsonDeps $json $path "npm" $section
    }
  }

  if ($name -in @("package-lock.json", "npm-shrinkwrap.json")) {
    $json = Read-JsonSafe $path

    if ($json -and $json.packages) {
      foreach ($p in $json.packages.PSObject.Properties) {
        if ([string]::IsNullOrWhiteSpace($p.Name)) {
          continue
        }

        $dep = $p.Value.name

        if ([string]::IsNullOrWhiteSpace($dep)) {
          $dep = $p.Name -replace "^.*node_modules/", ""
        }

        Add-Dependency $path "npm" $dep ([string]$p.Value.version) "lockfile-package" "packages"
      }
    }

    if ($json -and $json.dependencies) {
      foreach ($p in $json.dependencies.PSObject.Properties) {
        Add-Dependency $path "npm" $p.Name ([string]$p.Value.version) "lockfile-dependency" "dependencies"
      }
    }
  }

  if ($name -eq "yarn.lock") {
    $lines = $text -split "`r?`n"

    for ($i = 0; $i -lt $lines.Count; $i++) {
      if ($lines[$i] -match '^\s*("?[^#\s].*?"?)\s*:\s*$' -and $lines[$i] -notmatch '^\s{2,}') {
        $entry = $Matches[1].Trim('"')
        $version = ""

        for ($j = $i + 1; $j -lt [Math]::Min($i + 15, $lines.Count); $j++) {
          if ($lines[$j] -match '^\s+version\s+"?([^"\s]+)"?') {
            $version = $Matches[1]
            break
          }
        }

        foreach ($spec in ($entry -split ",\s*")) {
          $dep = $spec.Trim().Trim('"').Trim("'") -replace "^npm:", ""

          if ($dep -match "^(@[^/]+/[^@]+)@") {
            $dep = $Matches[1]
          } elseif ($dep -match "^([^@]+)@") {
            $dep = $Matches[1]
          }

          Add-Dependency $path "npm" $dep $version "lockfile-package" "yarn.lock"
        }
      }
    }
  }

  if ($name -eq "pnpm-lock.yaml") {
    foreach ($m in [regex]::Matches($text, '(?m)^\s{2,8}/?((?:@[^/\s:]+/)?[^@\s:]+)@([^:\s]+):\s*$')) {
      Add-Dependency $path "npm" $m.Groups[1].Value $m.Groups[2].Value "lockfile-package" "pnpm-lock.yaml"
    }
  }

  # Python requirements.txt
  if ($name -match "^requirements.*\.txt$") {
    foreach ($line in ($text -split "`r?`n")) {
      Parse-RequirementsLine $path $line $name
    }
  }

  # pyproject.toml
  if ($name -eq "pyproject.toml") {
    foreach ($m in [regex]::Matches($text, '["'']([^"'']+[<>=!~][^"'']*)["'']')) {
      Parse-RequirementsLine $path $m.Groups[1].Value "pyproject.toml"
    }

    $section = ""

    foreach ($line in ($text -split "`r?`n")) {
      $trim = $line.Trim()

      if ([string]::IsNullOrWhiteSpace($trim)) {
        continue
      }

      if ($trim.StartsWith("#")) {
        continue
      }

      if ($line -match "^\s*\[([^\]]+)\]\s*$") {
        $section = $Matches[1]
        continue
      }

      if ($section -match "^tool\.poetry.*dependencies$" -and $line -match "^\s*([A-Za-z0-9_.-]+)\s*=\s*(.+)$") {
        Add-Dependency $path "pip" $Matches[1] $Matches[2].Trim().Trim('"').Trim("'") "manifest" $section
      }
    }
  }

  # Pipfile / Pipfile.lock
  if ($name -in @("Pipfile", "Pipfile.lock")) {
    if ($name -eq "Pipfile.lock") {
      $json = Read-JsonSafe $path
      Add-JsonDeps $json $path "pip" "default"
      Add-JsonDeps $json $path "pip" "develop"
    } else {
      $section = ""

      foreach ($line in ($text -split "`r?`n")) {
        $trim = $line.Trim()

        if ($trim.StartsWith("#")) {
          continue
        }

        if ($line -match "^\s*\[([^\]]+)\]\s*$") {
          $section = $Matches[1]
          continue
        }

        if ($section -in @("packages", "dev-packages") -and $line -match "^\s*([A-Za-z0-9_.-]+)\s*=\s*(.+)$") {
          Add-Dependency $path "pip" $Matches[1] $Matches[2].Trim().Trim('"').Trim("'") "manifest" $section
        }
      }
    }
  }

  # Poetry / uv locks
  if ($name -in @("poetry.lock", "uv.lock")) {
    $currentName = ""
    $currentVersion = ""

    foreach ($line in ($text -split "`r?`n")) {
      if ($line -match '^\s*name\s*=\s*"([^"]+)"') {
        $currentName = $Matches[1]
      }

      if ($line -match '^\s*version\s*=\s*"([^"]+)"') {
        $currentVersion = $Matches[1]
      }

      if ($currentName -and $currentVersion) {
        Add-Dependency $path "pip" $currentName $currentVersion "lockfile-package" $name
        $currentName = ""
        $currentVersion = ""
      }
    }
  }

  # NuGet / .NET
  if ($name -match "\.(csproj|fsproj|vbproj|vcxproj|nuspec)$" -or $name -in @("packages.config", "Directory.Packages.props")) {
    try {
      [xml]$xml = $text

      Select-Xml -Xml $xml -XPath "//*[local-name()='PackageReference' or local-name()='PackageVersion' or local-name()='package' or local-name()='dependency']" |
        ForEach-Object {
          $n = $_.Node

          $dep = $n.GetAttribute("Include")
          if (-not $dep) { $dep = $n.GetAttribute("Update") }
          if (-not $dep) { $dep = $n.GetAttribute("id") }

          $ver = $n.GetAttribute("Version")
          if (-not $ver) { $ver = $n.GetAttribute("version") }

          Add-Dependency $path "nuget" $dep $ver "manifest" $n.Name
        }

      Select-Xml -Xml $xml -XPath "//*[local-name()='ProjectReference']" |
        ForEach-Object {
          Add-Dependency $path "nuget" $_.Node.GetAttribute("Include") "" "local-project-reference" "ProjectReference"
        }
    } catch {}
  }

  if ($name -eq "global.json") {
    $json = Read-JsonSafe $path

    if ($json.sdk.version) {
      Add-Dependency $path "dotnet-sdk" "dotnet-sdk" ([string]$json.sdk.version) "sdk-version" "global.json"
    }
  }

  # Go
  if ($name -eq "go.mod") {
    $inRequire = $false

    foreach ($line in ($text -split "`r?`n")) {
      $trim = $line.Trim()

      if ($trim -match "^require\s+\($") {
        $inRequire = $true
        continue
      }

      if ($inRequire -and $trim -eq ")") {
        $inRequire = $false
        continue
      }

      if ($trim -match "^require\s+(\S+)\s+(\S+)") {
        Add-Dependency $path "gomod" $Matches[1] $Matches[2] "manifest" "require"
      } elseif ($inRequire -and $trim -match "^(\S+)\s+(\S+)") {
        Add-Dependency $path "gomod" $Matches[1] $Matches[2] "manifest" "require-block"
      }
    }
  }

  if ($name -eq "go.sum") {
    foreach ($line in ($text -split "`r?`n")) {
      if ($line -match "^(\S+)\s+(\S+)\s+") {
        Add-Dependency $path "gomod" $Matches[1] $Matches[2] "checksum-lockfile" "go.sum"
      }
    }
  }

  # Docker / Compose
  if ($name -eq "Dockerfile" -or $name -match "\.Dockerfile$") {
    foreach ($line in ($text -split "`r?`n")) {
      if ($line -match '^\s*FROM\s+([^\s]+)') {
        Add-Dependency $path "docker" $Matches[1] "" "base-image" "FROM"
      }
    }
  }

  if ($name -match "^(docker-compose|compose).ya?ml$") {
    foreach ($line in ($text -split "`r?`n")) {
      if ($line -match '^\s*image:\s*["'']?([^"''\s]+)') {
        Add-Dependency $path "docker-compose" $Matches[1] "" "compose-image" "image"
      }
    }
  }

  # Maven
  if ($name -eq "pom.xml") {
    try {
      [xml]$xml = $text

      Select-Xml -Xml $xml -XPath "//*[local-name()='dependency']" |
        ForEach-Object {
          $n = $_.Node
          $groupId = ($n.ChildNodes | Where-Object { $_.LocalName -eq "groupId" }).InnerText
          $artifactId = ($n.ChildNodes | Where-Object { $_.LocalName -eq "artifactId" }).InnerText
          $version = ($n.ChildNodes | Where-Object { $_.LocalName -eq "version" }).InnerText

          if ($artifactId) {
            Add-Dependency $path "maven" "$groupId`:$artifactId" $version "manifest" "dependency"
          }
        }
    } catch {}
  }

  # Gradle
  if ($name -match "^build\.gradle(\.kts)?$" -or $name -match "^settings\.gradle(\.kts)?$" -or $name -eq "gradle.lockfile") {
    foreach ($m in [regex]::Matches($text, '["'']([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[^"'']+)["'']')) {
      $parts = $m.Groups[1].Value -split ":", 3

      if ($parts.Count -eq 3) {
        Add-Dependency $path "gradle" "$($parts[0]):$($parts[1])" $parts[2] "dependency-notation" "gradle"
      }
    }

    foreach ($m in [regex]::Matches($text, 'id\s*\(?\s*["'']([^"'']+)["'']\s*\)?\s*version\s*["'']([^"'']+)["'']')) {
      Add-Dependency $path "gradle" $m.Groups[1].Value $m.Groups[2].Value "plugin" "plugins"
    }
  }

  # Rust
  if ($name -eq "Cargo.toml") {
    $section = ""

    foreach ($line in ($text -split "`r?`n")) {
      if ($line -match "^\s*\[([^\]]+)\]\s*$") {
        $section = $Matches[1]
        continue
      }

      if ($section -match "(^dependencies$|^dev-dependencies$|^build-dependencies$|\.dependencies$|^workspace\.dependencies$)") {
        if ($line -match "^\s*([A-Za-z0-9_.-]+)\s*=\s*(.+)$") {
          Add-Dependency $path "cargo" $Matches[1] $Matches[2].Trim().Trim('"').Trim("'") "manifest" $section
        }
      }
    }
  }

  if ($name -eq "Cargo.lock") {
    $currentName = ""
    $currentVersion = ""

    foreach ($line in ($text -split "`r?`n")) {
      if ($line -match '^\s*name\s*=\s*"([^"]+)"') {
        $currentName = $Matches[1]
      }

      if ($line -match '^\s*version\s*=\s*"([^"]+)"') {
        $currentVersion = $Matches[1]
      }

      if ($currentName -and $currentVersion) {
        Add-Dependency $path "cargo" $currentName $currentVersion "lockfile-package" "Cargo.lock"
        $currentName = ""
        $currentVersion = ""
      }
    }
  }

  # Terraform / OpenTofu
  if ($ext -eq ".tf" -or $ext -eq ".tofu") {
    foreach ($line in ($text -split "`r?`n")) {
      if ($line -match 'source\s*=\s*["'']([^"'']+)["'']') {
        Add-Dependency $path "terraform" $Matches[1] "" "source-reference" "source"
      }

      if ($line -match 'version\s*=\s*["'']([^"'']+)["'']') {
        Add-Dependency $path "terraform" "version-constraint" $Matches[1] "version-constraint" "version"
      }
    }
  }

  if ($name -eq ".terraform.lock.hcl") {
    $provider = ""

    foreach ($line in ($text -split "`r?`n")) {
      if ($line -match 'provider\s+"([^"]+)"') {
        $provider = $Matches[1]
      }

      if ($provider -and $line -match 'version\s*=\s*"([^"]+)"') {
        Add-Dependency $path "terraform" $provider $Matches[1] "lockfile-provider" ".terraform.lock.hcl"
        $provider = ""
      }
    }
  }

  # Pre-commit
  if ($name -match "^\.pre-commit-config\.ya?ml$") {
    $repo = ""

    foreach ($line in ($text -split "`r?`n")) {
      if ($line -match '^\s*-\s*repo:\s*(.+)$') {
        $repo = $Matches[1].Trim().Trim('"').Trim("'")
      }

      if ($repo -and $line -match '^\s*rev:\s*(.+)$') {
        Add-Dependency $path "pre-commit" $repo $Matches[1].Trim().Trim('"').Trim("'") "hook-repo" "repo"
        $repo = ""
      }
    }
  }
}

$Final = $Rows |
  Sort-Object Ecosystem, File, Dependency, Version, Kind -Unique

Write-Host ""
Write-Host "Dependency list printed from repo:"
Write-Host $Root
Write-Host ""

if ($Final.Count -eq 0) {
  Write-Host "No dependencies found by this scan."
} else {
  $Final |
    Format-Table Ecosystem, Directory, Dependency, Version, Kind, File -AutoSize -Wrap |
    Out-String -Width 4096 |
    Write-Host
}

Write-Host ""
Write-Host "Summary by ecosystem:"
$Final |
  Group-Object Ecosystem |
  Sort-Object Name |
  Select-Object Name, Count |
  Format-Table -AutoSize |
  Out-String -Width 4096 |
  Write-Host