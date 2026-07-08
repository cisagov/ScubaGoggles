$ErrorActionPreference = "SilentlyContinue"

$Root = (Resolve-Path ".").Path.TrimEnd('\','/')
$AllDepsCsv = Join-Path $Root "all-dependencies.csv"
$GroupsCsv = Join-Path $Root "dependabot-update-groups.csv"

$Deps = New-Object System.Collections.Generic.List[object]
$Manifests = New-Object System.Collections.Generic.List[object]

function Get-RepoPath {
  param([string]$Path)
  $full = (Resolve-Path -LiteralPath $Path).Path
  if ($full.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
    return (("." + $full.Substring($Root.Length)) -replace "\\", "/")
  }
  return ($Path -replace "\\", "/")
}

function Get-DependabotDirectory {
  param([string]$Ecosystem, [string]$Path)

  if ($Ecosystem -eq "github-actions") {
    return "/"
  }

  $rel = (Get-RepoPath $Path) -replace "^\./", ""
  $dir = Split-Path -Parent $rel

  if ([string]::IsNullOrWhiteSpace($dir)) {
    return "/"
  }

  return "/" + ($dir -replace "\\", "/")
}

function Add-Manifest {
  param([string]$Ecosystem, [string]$Path)

  $Manifests.Add([pscustomobject]@{
    Ecosystem = $Ecosystem
    Directory = Get-DependabotDirectory $Ecosystem $Path
    File = Get-RepoPath $Path
  }) | Out-Null
}

function Add-Dep {
  param(
    [string]$Ecosystem,
    [string]$Path,
    [string]$Dependency,
    [string]$Version = "",
    [string]$Kind = "",
    [string]$Group = "",
    [string]$Raw = ""
  )

  if ([string]::IsNullOrWhiteSpace($Dependency)) {
    return
  }

  $Deps.Add([pscustomobject]@{
    Ecosystem = $Ecosystem
    Directory = Get-DependabotDirectory $Ecosystem $Path
    File = Get-RepoPath $Path
    Dependency = $Dependency.Trim()
    Version = $Version.Trim()
    Kind = $Kind
    Group = $Group
    Raw = $Raw.Trim()
  }) | Out-Null
}

function Read-JsonFile {
  param([string]$Path)
  try {
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
  } catch {
    return $null
  }
}

function Add-JsonDependencyMap {
  param(
    [object]$Json,
    [string]$Path,
    [string]$Ecosystem,
    [string]$Section
  )

  if ($null -eq $Json) {
    return
  }

  $obj = $Json.$Section
  if ($null -eq $obj) {
    return
  }

  if ($obj -is [System.Array]) {
    foreach ($item in $obj) {
      Add-Dep $Ecosystem $Path ([string]$item) "" "manifest" $Section ([string]$item)
    }
    return
  }

  foreach ($p in $obj.PSObject.Properties) {
    $v = ""
    if ($null -ne $p.Value) {
      if ($p.Value -is [string]) {
        $v = $p.Value
      } else {
        $v = ($p.Value | ConvertTo-Json -Compress -Depth 20)
      }
    }
    Add-Dep $Ecosystem $Path $p.Name $v "manifest" $Section "$($p.Name): $v"
  }
}

function Parse-PythonRequirement {
  param([string]$Path, [string]$Line, [string]$Group)

  $raw = $Line
  $line = ($Line -replace "\s+#.*$", "").Trim()

  if ([string]::IsNullOrWhiteSpace($line)) {
    return
  }

  if ($line -match "^\s*(-r|--requirement)\s+(.+)$") {
    Add-Dep "pip" $Path $Matches[2] "" "included-requirements-file" $Group $raw
    return
  }

  if ($line -match "^\s*(-c|--constraint)\s+(.+)$") {
    Add-Dep "pip" $Path $Matches[2] "" "constraints-file" $Group $raw
    return
  }

  if ($line -match "#egg=([^&\s]+)") {
    Add-Dep "pip" $Path $Matches[1] "" "vcs-or-url" $Group $raw
    return
  }

  if ($line -match "^\s*([A-Za-z0-9_.-]+)\s*(.*)$") {
    Add-Dep "pip" $Path $Matches[1] $Matches[2] "manifest" $Group $raw
    return
  }

  Add-Dep "pip" $Path $line "" "raw-requirement" $Group $raw
}

function Parse-TomlDependencyLines {
  param([string]$Path, [string]$Ecosystem)

  $section = ""
  $lines = Get-Content -LiteralPath $Path

  foreach ($raw in $lines) {
    $line = $raw.Trim()

    if ($line -match "^\s*\[(.+)\]\s*$") {
      $section = $Matches[1]
      continue
    }

    if ($line -match "^\s*([A-Za-z0-9_.-]+)\s*=\s*(.+)$") {
      $name = $Matches[1]
      $value = $Matches[2].Trim().Trim('"').Trim("'")

      if ($Path -match "pyproject\.toml$") {
        if ($section -match "^tool\.poetry(\.group\.[^.]+)?\.(dev-)?dependencies$" -or $section -eq "tool.poetry.dependencies") {
          Add-Dep "pip" $Path $name $value "manifest" $section $raw
        }
      }

      if ($Path -match "Cargo\.toml$") {
        if ($section -match "(^dependencies$|^dev-dependencies$|^build-dependencies$|\.dependencies$|^workspace\.dependencies$)") {
          Add-Dep "cargo" $Path $name $value "manifest" $section $raw
        }
      }

      if ($Path -match "Project\.toml$") {
        if ($section -match "deps") {
          Add-Dep "julia" $Path $name $value "manifest" $section $raw
        }
      }

      if ($Path -match "libs\.versions\.toml$") {
        if ($section -match "libraries|plugins|versions") {
          Add-Dep "gradle" $Path $name $value "version-catalog" $section $raw
        }
      }
    }

    if ($Path -match "pyproject\.toml$") {
      foreach ($m in [regex]::Matches($raw, '["'']([^"'']+[<>=!~][^"'']*)["'']')) {
        Parse-PythonRequirement $Path $m.Groups[1].Value "pyproject-inline"
      }
    }
  }
}

function Parse-NpmSpecName {
  param([string]$Spec)
  $s = $Spec.Trim().Trim('"').Trim("'")
  if ($s -match "^(@[^/]+/[^@]+)@") {
    return $Matches[1]
  }
  if ($s -match "^([^@]+)@") {
    return $Matches[1]
  }
  return $s
}

function Parse-NpmLockPackages {
  param([object]$Json, [string]$Path)

  if ($null -eq $Json) {
    return
  }

  if ($Json.packages) {
    foreach ($p in $Json.packages.PSObject.Properties) {
      if ([string]::IsNullOrWhiteSpace($p.Name)) {
        continue
      }

      $pkgName = $p.Value.name
      if ([string]::IsNullOrWhiteSpace($pkgName)) {
        $idx = $p.Name.LastIndexOf("node_modules/")
        if ($idx -ge 0) {
          $pkgName = $p.Name.Substring($idx + "node_modules/".Length)
        } else {
          $pkgName = $p.Name
        }
      }

      Add-Dep "npm" $Path $pkgName ([string]$p.Value.version) "lockfile-package" "packages" $p.Name
    }
  }

  if ($Json.dependencies) {
    foreach ($p in $Json.dependencies.PSObject.Properties) {
      Add-Dep "npm" $Path $p.Name ([string]$p.Value.version) "lockfile-dependency" "dependencies" $p.Name
    }
  }
}

$Files = Get-ChildItem -Path $Root -Recurse -File -Force -ErrorAction SilentlyContinue

foreach ($file in $Files) {
  $path = $file.FullName
  $name = $file.Name
  $rel = (Get-RepoPath $path) -replace "^\./", ""
  $relUnix = $rel -replace "\\", "/"
  $ext = $file.Extension.ToLowerInvariant()

  # GitHub Actions, local actions, reusable workflows, and docker actions.
  if ($ext -in @(".yml", ".yaml")) {
    $text = Get-Content -LiteralPath $path -Raw
    $actionRegex = '(?m)^\s*uses:\s*["'']?([^@\s"'']+)(?:@([^"''\s#]+))?'

    foreach ($m in [regex]::Matches($text, $actionRegex)) {
      $dep = $m.Groups[1].Value
      $ver = $m.Groups[2].Value
      $kind = "github-action-or-reusable-workflow"

      if ($dep -like "./*") {
        $kind = "local-action-or-reusable-workflow"
      } elseif ($dep -like "docker://*") {
        $kind = "docker-action"
      }

      Add-Manifest "github-actions" $path
      Add-Dep "github-actions" $path $dep $ver $kind "uses" $m.Value
    }
  }

  # npm, Yarn, pnpm, Bun.
  if ($name -eq "package.json") {
    Add-Manifest "npm" $path
    $json = Read-JsonFile $path
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
      Add-JsonDependencyMap $json $path "npm" $section
    }
  }

  if ($name -in @("package-lock.json", "npm-shrinkwrap.json")) {
    Add-Manifest "npm" $path
    Parse-NpmLockPackages (Read-JsonFile $path) $path
  }

  if ($name -eq "yarn.lock") {
    Add-Manifest "npm" $path
    $lines = Get-Content -LiteralPath $path
    for ($i = 0; $i -lt $lines.Count; $i++) {
      if ($lines[$i] -match '^\s*("?[^#\s].*?"?)\s*:\s*$') {
        $entry = $Matches[1].Trim('"')
        $version = ""
        for ($j = $i + 1; $j -lt [Math]::Min($i + 12, $lines.Count); $j++) {
          if ($lines[$j] -match '^\s+version\s+"?([^"\s]+)"?') {
            $version = $Matches[1]
            break
          }
        }
        foreach ($spec in ($entry -split ",\s*")) {
          Add-Dep "npm" $path (Parse-NpmSpecName $spec) $version "lockfile-package" "yarn.lock" $entry
        }
      }
    }
  }

  if ($name -eq "pnpm-lock.yaml") {
    Add-Manifest "npm" $path
    $text = Get-Content -LiteralPath $path -Raw
    foreach ($m in [regex]::Matches($text, '(?m)^\s{2,6}/?((?:@[^/\s:]+/)?[^@\s:]+)@([^:\s]+):\s*$')) {
      Add-Dep "npm" $path $m.Groups[1].Value $m.Groups[2].Value "lockfile-package" "pnpm-lock.yaml" $m.Value
    }
  }

  if ($name -in @("bun.lock", "bun.lockb")) {
    Add-Manifest "bun" $path
    Add-Dep "bun" $path $name "" "lockfile-present" "bun" "Use bun pm ls for full Bun dependency tree"
  }

  # Python.
  if ($name -match "^requirements.*\.txt$") {
    Add-Manifest "pip" $path
    Get-Content -LiteralPath $path | ForEach-Object {
      Parse-PythonRequirement $path $_ $name
    }
  }

  if ($name -in @("Pipfile", "Pipfile.lock")) {
    Add-Manifest "pip" $path
    if ($name -eq "Pipfile.lock") {
      $json = Read-JsonFile $path
      Add-JsonDependencyMap $json $path "pip" "default"
      Add-JsonDependencyMap $json $path "develop"
    } else {
      Parse-TomlDependencyLines $path "pip"
    }
  }

  if ($name -eq "pyproject.toml") {
    Add-Manifest "pip" $path
    Parse-TomlDependencyLines $path "pip"
  }

  if ($name -in @("poetry.lock", "uv.lock")) {
    Add-Manifest "pip" $path
    $currentName = ""
    $currentVersion = ""
    foreach ($line in Get-Content -LiteralPath $path) {
      if ($line -match '^\s*name\s*=\s*"([^"]+)"') {
        $currentName = $Matches[1]
      }
      if ($line -match '^\s*version\s*=\s*"([^"]+)"') {
        $currentVersion = $Matches[1]
      }
      if ($currentName -and $currentVersion) {
        Add-Dep "pip" $path $currentName $currentVersion "lockfile-package" $name "$currentName $currentVersion"
        $currentName = ""
        $currentVersion = ""
      }
    }
  }

  if ($name -eq "setup.py") {
    Add-Manifest "pip" $path
    Select-String -LiteralPath $path -Pattern "install_requires|setup_requires|tests_require|extras_require" |
      ForEach-Object {
        Add-Dep "pip" $path $_.Line.Trim() "" "setup.py-reference" "setup.py" $_.Line
      }
  }

  # .NET / NuGet.
  if ($name -match "\.(csproj|fsproj|vbproj|vcxproj|nuspec)$" -or $name -in @("packages.config", "Directory.Packages.props")) {
    Add-Manifest "nuget" $path
    try {
      [xml]$xml = Get-Content -LiteralPath $path -Raw

      Select-Xml -Xml $xml -XPath "//*[local-name()='PackageReference' or local-name()='PackageVersion' or local-name()='package' or local-name()='dependency']" |
        ForEach-Object {
          $n = $_.Node
          $depName = $n.Include
          if (-not $depName) { $depName = $n.Update }
          if (-not $depName) { $depName = $n.id }
          if (-not $depName) { $depName = $n.GetAttribute("id") }

          $ver = $n.Version
          if (-not $ver) { $ver = $n.version }
          if (-not $ver) { $ver = $n.GetAttribute("version") }

          Add-Dep "nuget" $path $depName $ver "manifest" $n.Name $n.OuterXml
        }

      Select-Xml -Xml $xml -XPath "//*[local-name()='ProjectReference']" |
        ForEach-Object {
          Add-Dep "nuget" $path $_.Node.Include "" "local-project-reference" "ProjectReference" $_.Node.OuterXml
        }
    } catch {}
  }

  if ($name -eq "global.json") {
    Add-Manifest "dotnet-sdk" $path
    $json = Read-JsonFile $path
    if ($json.sdk.version) {
      Add-Dep "dotnet-sdk" $path "dotnet-sdk" ([string]$json.sdk.version) "sdk-version" "global.json"
    }
  }

  # Maven.
  if ($name -eq "pom.xml") {
    Add-Manifest "maven" $path
    try {
      [xml]$xml = Get-Content -LiteralPath $path -Raw
      Select-Xml -Xml $xml -XPath "//*[local-name()='dependency']" |
        ForEach-Object {
          $n = $_.Node
          $groupId = ($n.ChildNodes | Where-Object { $_.LocalName -eq "groupId" }).InnerText
          $artifactId = ($n.ChildNodes | Where-Object { $_.LocalName -eq "artifactId" }).InnerText
          $version = ($n.ChildNodes | Where-Object { $_.LocalName -eq "version" }).InnerText
          if ($artifactId) {
            Add-Dep "maven" $path "$groupId`:$artifactId" $version "manifest" "dependency" $_.Node.OuterXml
          }
        }
    } catch {}
  }

  # Gradle.
  if ($name -match "^build\.gradle(\.kts)?$" -or $name -match "^settings\.gradle(\.kts)?$" -or $name -eq "gradle.lockfile") {
    Add-Manifest "gradle" $path
    $text = Get-Content -LiteralPath $path -Raw

    foreach ($m in [regex]::Matches($text, '["'']([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[^"'']+)["'']')) {
      $parts = $m.Groups[1].Value -split ":", 3
      Add-Dep "gradle" $path "$($parts[0]):$($parts[1])" $parts[2] "manifest" "dependency-notation" $m.Value
    }

    foreach ($m in [regex]::Matches($text, 'id\s*\(?\s*["'']([^"'']+)["'']\s*\)?\s*version\s*["'']([^"'']+)["'']')) {
      Add-Dep "gradle" $path $m.Groups[1].Value $m.Groups[2].Value "plugin" "plugins" $m.Value
    }
  }

  if ($name -eq "libs.versions.toml") {
    Add-Manifest "gradle" $path
    Parse-TomlDependencyLines $path "gradle"
  }

  # Go.
  if ($name -eq "go.mod") {
    Add-Manifest "gomod" $path
    $inRequire = $false
    foreach ($line in Get-Content -LiteralPath $path) {
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
        Add-Dep "gomod" $path $Matches[1] $Matches[2] "manifest" "require" $line
      } elseif ($inRequire -and $trim -match "^(\S+)\s+(\S+)") {
        Add-Dep "gomod" $path $Matches[1] $Matches[2] "manifest" "require-block" $line
      }
    }
  }

  if ($name -eq "go.sum") {
    Add-Manifest "gomod" $path
    Get-Content -LiteralPath $path | ForEach-Object {
      if ($_ -match "^(\S+)\s+(\S+)\s+") {
        Add-Dep "gomod" $path $Matches[1] $Matches[2] "checksum-lockfile" "go.sum" $_
      }
    }
  }

  # Rust.
  if ($name -eq "Cargo.toml") {
    Add-Manifest "cargo" $path
    Parse-TomlDependencyLines $path "cargo"
  }

  if ($name -eq "Cargo.lock") {
    Add-Manifest "cargo" $path
    $currentName = ""
    $currentVersion = ""
    foreach ($line in Get-Content -LiteralPath $path) {
      if ($line -match '^\s*name\s*=\s*"([^"]+)"') {
        $currentName = $Matches[1]
      }
      if ($line -match '^\s*version\s*=\s*"([^"]+)"') {
        $currentVersion = $Matches[1]
      }
      if ($currentName -and $currentVersion) {
        Add-Dep "cargo" $path $currentName $currentVersion "lockfile-package" "Cargo.lock"
        $currentName = ""
        $currentVersion = ""
      }
    }
  }

  # Composer / PHP.
  if ($name -in @("composer.json", "composer.lock")) {
    Add-Manifest "composer" $path
    $json = Read-JsonFile $path

    if ($name -eq "composer.json") {
      Add-JsonDependencyMap $json $path "composer" "require"
      Add-JsonDependencyMap $json $path "composer" "require-dev"
    }

    if ($name -eq "composer.lock") {
      foreach ($section in @("packages", "packages-dev")) {
        foreach ($pkg in $json.$section) {
          Add-Dep "composer" $path $pkg.name $pkg.version "lockfile-package" $section
        }
      }
    }
  }

  # Ruby.
  if ($name -eq "Gemfile") {
    Add-Manifest "bundler" $path
    Get-Content -LiteralPath $path | ForEach-Object {
      if ($_ -match '^\s*gem\s+["'']([^"'']+)["'']\s*,?\s*["'']?([^"'']*)?') {
        Add-Dep "bundler" $path $Matches[1] $Matches[2] "manifest" "Gemfile" $_
      }
    }
  }

  if ($name -eq "Gemfile.lock") {
    Add-Manifest "bundler" $path
    Get-Content -LiteralPath $path | ForEach-Object {
      if ($_ -match '^\s{4}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)') {
        Add-Dep "bundler" $path $Matches[1] $Matches[2] "lockfile-package" "Gemfile.lock" $_
      }
    }
  }

  # Docker and Compose.
  if ($name -eq "Dockerfile" -or $name -match "\.Dockerfile$") {
    Add-Manifest "docker" $path
    Get-Content -LiteralPath $path | ForEach-Object {
      if ($_ -match '^\s*FROM\s+([^\s]+)') {
        Add-Dep "docker" $path $Matches[1] "" "base-image" "FROM" $_
      }
    }
  }

  if ($name -match "^(docker-compose|compose).ya?ml$") {
    Add-Manifest "docker-compose" $path
    Get-Content -LiteralPath $path | ForEach-Object {
      if ($_ -match '^\s*image:\s*["'']?([^"''\s]+)') {
        Add-Dep "docker-compose" $path $Matches[1] "" "compose-image" "image" $_
      }
    }
  }

  # Terraform / OpenTofu.
  if ($ext -in @(".tf", ".tofu")) {
    Add-Manifest "terraform" $path
    Get-Content -LiteralPath $path | ForEach-Object {
      if ($_ -match 'source\s*=\s*["'']([^"'']+)["'']') {
        Add-Dep "terraform" $path $Matches[1] "" "source-reference" "source" $_
      }
      if ($_ -match 'version\s*=\s*["'']([^"'']+)["'']') {
        Add-Dep "terraform" $path "version-constraint" $Matches[1] "version-constraint" "version" $_
      }
    }
  }

  if ($name -eq ".terraform.lock.hcl") {
    Add-Manifest "terraform" $path
    $currentProvider = ""
    foreach ($line in Get-Content -LiteralPath $path) {
      if ($line -match 'provider\s+"([^"]+)"') {
        $currentProvider = $Matches[1]
      }
      if ($currentProvider -and $line -match 'version\s*=\s*"([^"]+)"') {
        Add-Dep "terraform" $path $currentProvider $Matches[1] "lockfile-provider" ".terraform.lock.hcl"
        $currentProvider = ""
      }
    }
  }

  # Helm.
  if ($name -eq "Chart.yaml") {
    Add-Manifest "helm" $path
    $currentName = ""
    $currentVersion = ""
    foreach ($line in Get-Content -LiteralPath $path) {
      if ($line -match '^\s*-\s*name:\s*["'']?([^"'']+)') {
        $currentName = $Matches[1]
      }
      if ($line -match '^\s*version:\s*["'']?([^"'']+)') {
        $currentVersion = $Matches[1]
      }
      if ($currentName -and $currentVersion) {
        Add-Dep "helm" $path $currentName $currentVersion "chart-dependency" "dependencies"
        $currentName = ""
        $currentVersion = ""
      }
    }
  }

  # Pre-commit.
  if ($name -match "^\.pre-commit-config\.ya?ml$") {
    Add-Manifest "pre-commit" $path
    $currentRepo = ""
    foreach ($line in Get-Content -LiteralPath $path) {
      if ($line -match '^\s*-\s*repo:\s*(.+)$') {
        $currentRepo = $Matches[1].Trim().Trim('"').Trim("'")
      }
      if ($currentRepo -and $line -match '^\s*rev:\s*(.+)$') {
        Add-Dep "pre-commit" $path $currentRepo $Matches[1].Trim().Trim('"').Trim("'") "hook-repo" "repo"
        $currentRepo = ""
      }
    }
  }

  # Git submodules.
  if ($name -eq ".gitmodules") {
    Add-Manifest "gitsubmodule" $path
    $currentPath = ""
    foreach ($line in Get-Content -LiteralPath $path) {
      if ($line -match 'path\s*=\s*(.+)$') {
        $currentPath = $Matches[1].Trim()
      }
      if ($line -match 'url\s*=\s*(.+)$') {
        Add-Dep "gitsubmodule" $path $Matches[1].Trim() "" "submodule" $currentPath $line
      }
    }
  }

  # Swift.
  if ($name -eq "Package.resolved") {
    Add-Manifest "swift" $path
    $json = Read-JsonFile $path
    foreach ($pin in $json.pins) {
      $depName = $pin.identity
      if (-not $depName) { $depName = $pin.package }
      $version = $pin.state.version
      if (-not $version) { $version = $pin.state.revision }
      Add-Dep "swift" $path $depName $version "lockfile-package" "Package.resolved"
    }
  }

  if ($name -eq "Package.swift") {
    Add-Manifest "swift" $path
    $text = Get-Content -LiteralPath $path -Raw
    foreach ($m in [regex]::Matches($text, '\.package\s*\(\s*url:\s*"([^"]+)"\s*,\s*([^)]*)\)')) {
      Add-Dep "swift" $path $m.Groups[1].Value $m.Groups[2].Value "manifest" "Package.swift" $m.Value
    }
  }

  # Dart / Flutter.
  if ($name -eq "pubspec.yaml") {
    Add-Manifest "pub" $path
    $section = ""
    foreach ($line in Get-Content -LiteralPath $path) {
      if ($line -match '^(dependencies|dev_dependencies|dependency_overrides):\s*$') {
        $section = $Matches[1]
        continue
      }
      if ($section -and $line -match '^\s{2}([A-Za-z0-9_.-]+):\s*(.*)$') {
        Add-Dep "pub" $path $Matches[1] $Matches[2].Trim() "manifest" $section $line
      }
    }
  }

  if ($name -eq "pubspec.lock") {
    Add-Manifest "pub" $path
    $currentName = ""
    foreach ($line in Get-Content -LiteralPath $path) {
      if ($line -match '^\s{2}([A-Za-z0-9_.-]+):\s*$') {
        $currentName = $Matches[1]
      }
      if ($currentName -and $line -match '^\s+version:\s*"([^"]+)"') {
        Add-Dep "pub" $path $currentName $Matches[1] "lockfile-package" "pubspec.lock"
        $currentName = ""
      }
    }
  }

  # Elixir.
  if ($name -eq "mix.exs") {
    Add-Manifest "mix" $path
    Get-Content -LiteralPath $path | ForEach-Object {
      if ($_ -match '\{:(\w+),\s*["'']([^"'']+)["'']') {
        Add-Dep "mix" $path $Matches[1] $Matches[2] "manifest" "mix.exs" $_
      }
    }
  }

  if ($name -eq "mix.lock") {
    Add-Manifest "mix" $path
    Get-Content -LiteralPath $path | ForEach-Object {
      if ($_ -match '"([^"]+)":\s*\{[^,]+,\s*"([^"]+)"') {
        Add-Dep "mix" $path $Matches[1] $Matches[2] "lockfile-package" "mix.lock" $_
      }
    }
  }

  # Dev containers.
  if ($name -eq "devcontainer.json") {
    Add-Manifest "devcontainers" $path
    $json = Read-JsonFile $path
    if ($json.image) {
      Add-Dep "devcontainers" $path $json.image "" "container-image" "image"
    }
    if ($json.features) {
      foreach ($p in $json.features.PSObject.Properties) {
        Add-Dep "devcontainers" $path $p.Name ($p.Value | ConvertTo-Json -Compress -Depth 20) "feature" "features"
      }
    }
  }
}

$Deps |
  Sort-Object Ecosystem, Directory, Dependency, Version, File |
  Export-Csv -NoTypeInformation -Encoding UTF8 $AllDepsCsv

$Manifests |
  Sort-Object Ecosystem, Directory, File -Unique |
  Export-Csv -NoTypeInformation -Encoding UTF8 $GroupsCsv

"`nDependency inventory written to:"
$AllDepsCsv

"`nDependabot candidate ecosystem/directory groups written to:"
$GroupsCsv

"`nSummary by ecosystem:"
$Deps |
  Group-Object Ecosystem |
  Sort-Object Name |
  Select-Object Name, Count |
  Format-Table -AutoSize

"`nFirst 100 dependencies:"
$Deps |
  Sort-Object Ecosystem, Directory, Dependency, Version, File |
  Select-Object -First 100 Ecosystem, Directory, Dependency, Version, Kind, File |
  Format-Table -AutoSize -Wrap