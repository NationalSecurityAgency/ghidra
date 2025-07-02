
. $Env:MODULE_Debugger_rmi_trace_HOME\data\support\setuputils.ps1

function Add-Gdb-Init-Args {
	param([ref]$ArgList)

	$ArgList.Value+=("-q")
	$ArgList.Value+=("-ex", "`"set pagination off`"")
	$ArgList.Value+=("-ex", "`"set confirm off`"")
	$ArgList.Value+=("-ex", "`"show version`"")
	$ArgList.Value+=("-ex", "`"python import ghidragdb`"")
	$ArgList.Value+=("-ex", "`"python if not 'ghidragdb' in locals(): exit(253)`"")
	$ArgList.Value+=("-ex", "`"set architecture $Env:OPT_ARCH`"")
	$ArgList.Value+=("-ex", "`"set endian $Env:OPT_ENDIAN`"")
}

function Add-Gdb-Image-And-Args {
	param([ref]$ArgList, $TargetImage, $TargetArgs)

	if ("$TargetImage" -ne "") {
		$image = $TargetImage -replace "\\", "\\\\"
		$ArgList.Value+=("-ex", "`"file '$image'`"")
	}
	if ("$TargetArgs" -ne "") {
		$tgtargs = $TargetArgs -replace "`"", "\`""
		# Escaping parentheses in the arguments is no longer necessary in powershell vs cmd
		$ArgList.Value+=("-ex", "`"set args $tgtargs`"")
	}
}

function Add-Gdb-Connect-And-Sync {
	param([ref]$ArgList, $Address)

	$ArgList.Value+=("-ex", "`"ghidra trace connect '$Address'`"")
	$ArgList.Value+=("-ex", "`"ghidra trace start`"")
	$ArgList.Value+=("-ex", "`"ghidra trace sync-enable`"")
}

function Add-Gdb-Start-If-Image {
	param([ref]$ArgList, $TargetImage)

	if ("$TargetImage" -ne "") {
		$ArgList.Value+=("-ex", "`"$Env:OPT_START_CMD`"")
	}
}

function Add-Gdb-Tail-Args {
	param([ref]$ArgList)

	$ArgList.Value+=("-ex", "`"set confirm on`"")
#	$ArgList.Value+=("-ex", "`"set pagination on`"")
}

function Compute-Gdb-Usermode-Args {
	param($TargetImage, $RmiAddress)

	$arglist = @("`"$Env:OPT_GDB_PATH`"")
	Add-Gdb-Init-Args -ArgList ([ref]$arglist)
	Add-Gdb-Image-And-Args -ArgList ([ref]$arglist) -TargetImage $TargetImage -TargetArgs $Env:OPT_TARGET_ARGS
	Add-Gdb-Connect-And-Sync -ArgList ([ref]$arglist) -Address $RmiAddress
	Add-Gdb-Start-If-Image -ArgList ([ref]$arglist) -TargetImage $TargetImage
	Add-Gdb-Tail-Args -ArgList ([ref]$arglist)

	return $arglist
}

function Compute-Gdb-Remote-Args {
	param($TargetImage, $TargetCx, $RmiAddress)

	$arglist = @("`"$Env:OPT_GDB_PATH`"")
	Add-Gdb-Init-Args -ArgList ([ref]$arglist)
	Add-Gdb-Image-And-Args -ArgList ([ref]$arglist) -TargetImge $TargetImage -TargetArgs ""
	$arglist+=("-ex", "`"echo Connecting to $TargetCx\n`"")
	$arglist+=("-ex", "`"target $TargetCx`"")
	Add-Gdb-Connect-And-Sync -ArgList ([ref]$arglist) -Address $RmiAddress
	$arglist+=("-ex", "`"ghidra trace sync-synth-stopped`"")
	Add-Gdb-Tail-Args -ArgList ([ref]$arglist)

	return $arglist
}

function Compute-Gdb-PipInstall-Args {
	$argvpart = $args -join ", "
	$arglist = @("`"$Env:OPT_GDB_PATH`"")
	$arglist+=("-ex", "`"set pagination off`"")
	$arglist+=("-ex", "`"python import os, sys, runpy`"")
	$arglist+=("-ex", "`"python sys.argv=['pip', 'install', '--force-reinstall', $argvpart]`"")
	$arglist+=("-ex", "`"python os.environ['PIP_BREAK_SYSTEM_PACKAGE']='1'`"")
	$arglist+=("-ex", "`"python runpy.run_module('pip', run_name='__main__')`"")

	return $arglist
}
