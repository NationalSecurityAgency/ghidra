function Find-App-Properties {
	[IO.FileInfo] $props = "$Env:GHIDRA_HOME\application.properties"
	if ($props.Exists) {
		return $props
	}
	throw "Cannot find application.properties"
}

function Get-Ghidra-Version {
	$props = Find-App-Properties
	$m = Get-Content $props | Select-String -Pattern "application\.version=([0-9]*\.[0-9]*)\.?.*"
	return $m.Matches.Groups[1].Value
}

function Ghidra-Module-PyPath {
	if ($args.Count -eq 0 -or $args[0] -eq "<SELF>") {
		$modhomename = 'MODULE_HOME'
	} else {
		$modhomename = "MODULE_$($args[0])_HOME" -replace '-', '_'
	}
	$modhomeitem = Get-ChildItem Env:$modhomename
	$modhome = $modhomeitem.Value
	[IO.DirectoryInfo] $installed = "$modhome\pypkg\src"
	if ($installed.Exists) {
		return "$installed"
	}
	[IO.DirectoryInfo] $dev = "$modhome\build\pypkg\src"
	if ($dev.Exists) {
		return "$dev"
	}
	throw "Cannot find Python source for $($args[0]). Try gradle assemblePyPackage?"
}

function Ghidra-Module-PyDist {
	if ($args.Count -eq 0 -or $args[0] -eq "<SELF>") {
		$modhomename = 'MODULE_HOME'
	} else {
		$modhomename = "MODULE_$($args[0])_HOME" -replace '-', '_'
	}
	$modhomeitem = Get-ChildItem Env:$modhomename
	$modhome = $modhomeitem.Value
	[IO.DirectoryInfo] $installed = "$modhome\pypkg\dist"
	if ($installed.Exists) {
		return "$installed"
	}
	[IO.DirectoryInfo] $dev = "$modhome\build\pypkg\dist"
	if ($dev.Exists) {
		return "$dev"
	}
	throw "Cannot find Python package for $($args[0]). Try gradle buildPyPackage?"
}

function Compute-Ssh-Args {
	$arglist = $args[0]
	$forward = $args[1]
	$cmdline = $arglist -join " " -replace "`"", "\`""

	$sshargs = @("`"$Env:OPT_SSH_PATH`"")
	$sshargs+=("-t")
	if ($forward) {
		$sshargs+=("-R$Env:OPT_REMOTE_PORT`:$Env:GHIDRA_TRACE_RMI_ADDR")
	}
	if ("$Env:OPT_EXTRA_SSH_ARGS" -ne "") {
		$sshargs+=("$Env:OPT_EXTRA_SSH_ARGS")
	}
	$sshargs+=("$Env:OPT_HOST", "TERM='$Env:TERM' $cmdline")

	return $sshargs
}

function Check-Result-And-Prompt-Mitigation {
	$proc = $args[0]
	$msg = $args[1]
	$prompt = $args[2]
	if ($proc.ExitCode -eq 253) {
		Write-Host @"
--------------------------------------------------------------------------------
!!!                       INCORRECT OR INCOMPLETE SETUP                      !!!
--------------------------------------------------------------------------------

"@
		Write-Host $msg
		Write-Host ""
		Write-Host "Select KEEP if you're seeing this in an error dialog."
		Write-Host -NoNewline "$prompt [Y/n] "
		$answer = Read-Host
		return (("$answer" -eq "y") -or ("$answer" -eq "Y") -or ("$answer" -eq ""))
	}
}

function Mitigate-Scp-PyModules {
	$scpargs = $args | ForEach-Object {
		$dist = Ghidra-Module-PyDist $_
		return "$dist\*"
	}
	$scpargs+=("$Env:OPT_HOST`:~/")
	Start-Process -FilePath "scp" -ArgumentList $scpargs -NoNewWindow -Wait
}

