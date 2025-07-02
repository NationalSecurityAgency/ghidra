
. $Env:MODULE_Debugger_rmi_trace_HOME\data\support\setuputils.ps1

function Add-Lldb-Init-Args {
	param([ref]$ArgList)

	$ArgList.Value+=("-o", "`"version`"")
	$ArgList.Value+=("-o", "`"script import os, ghidralldb`"")
	$ArgList.Value+=("-o", "`"script if not 'ghidralldb' in locals(): os._exit(253)`"")
	if ("$Env:OPT_ARCH" -ne "") {
		$ArgList.Value+=("-o", "`"settings set target.default-arch $Env:OPT_ARCH`"")
	}
}

function Add-Lldb-Image-And-Args {
	param([ref]$ArgList, $TargetImage, $TargetArgs)

	if ("$TargetImage" -ne "") {
		if ("$Env:OPT_ARCH" -ne "") {
			$ArgList.Value+=("-o", "`"target create --arch '$Env:OPT_ARCH' '$TargetImage'`"")
		}
		else {
			$ArgList.Value+=("-o", "`"target create '$TargetImage'`"")
		}
	}
	if ("$TargetArgs" -ne "") {
		$tgtargs = $TargetArgs -replace "`"", "\`""
		# Escaping parentheses in the arguments is no longer necessary in powershell vs cmd
		$ArgList.Value+=("-o", "`"settings set target.run-args $tgtargs`"")
	}
}

function Add-Lldb-Connect-And-Sync {
	param([ref]$ArgList, $Address)

	$ArgList.Value+=("-o", "`"ghidra trace connect '$Address'`"")
	$ArgList.Value+=("-o", "`"ghidra trace start`"")
	$ArgList.Value+=("-o", "`"ghidra trace sync-enable`"")
}

function Add-Lldb-Start-If-Image {
	param([ref]$ArgList, $TargetImage)

	if ("$TargetImage" -ne "") {
		$ArgList.Value+=("-o", "`"$Env:OPT_START_CMD`"")
	}
}

function Add-Lldb-Tail-Args {
	param([ref]$ArgList)
	# NOP
}

function Compute-Lldb-Usermode-Args {
	param($TargetImage, $RmiAddress)

	$arglist = @("`"$Env:OPT_LLDB_PATH`"")
	Add-Lldb-Init-Args -ArgList ([ref]$arglist)
	Add-Lldb-Image-And-Args -ArgList ([ref]$arglist) -TargetImage $TargetImage -TargetArgs $Env:OPT_TARGET_ARGS
	Add-Lldb-Connect-And-Sync -ArgList ([ref]$arglist) -Address $RmiAddress
	Add-Lldb-Start-If-Image -ArgList ([ref]$arglist) -TargetImage $TargetImage
	Add-Lldb-Tail-Args -ArgList ([ref]$arglist)

	return $arglist
}

function Compute-Lldb-Platform-Args {
	param($TargetImage, $TargetType, $TargetUrl, $RmiAddress)

	$argslist = @("`"$Env:OPT_LLDB_PATH`"")
	Add-Lldb-Init-Args -ArgList ([ref]$arglist)
	$argslist+=("-o", "`"platform select '$TargetType'`"")
	$argslist+=("-o", "`"platform connect '$TargetUrl'`"")
	Add-Lldb-Image-And-Args -ArgList ([ref]$arglistt) -TargetImage $TargetImage -TargetArgs $Env:OPT_TARGET_ARGS
	Add-Lldb-Connect-And-Sync -ArgList ([ref]$arglist) -Address $RmiAddress
	Add-Lldb-Start-If-Image -ArgList ([ref]$arglist) -TargetImage $TargetImage
	Add-Lldb-Tail-Args -ArgList ([ref]$arglist)

	return $arglist
}

function Compute-Lldb-Remote-Args {
	param($TargetImage, $TargetCx, $RmiAddress)

	$arglist = @("`"$Env:OPT_LLDB_PATH`"")
	Add-Lldb-Init-Args -ArgList ([ref]$arglist)
	Add-Lldb-Image-And-Args -ArgList ([ref]$arglist) -TargetImge $TargetImage -TargetArgs ""
	$arglist+=("-o", "`"$TargetCx`"")
	Add-Lldb-Connect-And-Sync -ArgList ([ref]$arglist) -Address $RmiAddress
	$arglist+=("-o", "`"ghidra trace sync-synth-stopped`"")
	Add-Lldb-Tail-Args -ArgList ([ref]$arglist)

	return $arglist
}

function Compute-Lldb-PipInstall-Args {
	$argvpart = $args -join ", "
	$arglist = @("`"$Env:OPT_LLDB_PATH`"")
	$arglist+=("-o", "`"script import os, sys, runpy`"")
	$arglist+=("-o", "`"script sys.argv=['pip', 'install', '--force-reinstall', $argvpart]`"")
	$arglist+=("-o", "`"script os.environ['PIP_BREAK_SYSTEM_PACKAGE']='1'`"")
	$arglist+=("-o", "`"script runpy.run_module('pip', run_name='__main__')`"")
	$arglist+=("-o", "`"quit`"")

	return $arglist
}
