/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//
// Parses preview of VS22 and DirectX to .gdt archive files
//
// To replace existing header files and have the data type ID's synchronized
//
// Must run SynchronizeGDTCategoryPaths.java script with old and replacement GDT
//  archive to synchronize upper/lower case paths
///   (only on windows archives)
//
// Then Run DataTypeArchiveTransformer in eclipse to synchronize old data types ID's
//
//@category Data Types

import java.io.File;
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.util.cparser.C.CParserUtils.CParseResults;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.util.Msg;

public class CreateExampleGDTArchiveScript extends GhidraScript {

	private File outputDirectory;
	
	// location of header files base directory
	private static String headerFilePath = "/data/HeaderFiles";

	@Override
	protected void run() throws Exception {
		outputDirectory = askDirectory("Select Directory for GDT files", "Select GDT Output Dir");
		
		parseGDT_DirectX();
		
		parseGDT_WinVS22();
	}
	
	private void parseHeaderFilesToGDT(File outputDir, String gdtName, String languageID, String compiler,
			String[] filenames, String includePaths[], String[] args)
			throws ParseException, ghidra.app.util.cparser.CPP.ParseException, IOException {
		DataTypeManager openTypes[] = null;
		
		parseHeaderFilesToGDT(openTypes, outputDir, gdtName, languageID, compiler, filenames, includePaths, args);
	}

	private void parseHeaderFilesToGDT(DataTypeManager openTypes[], File outputDir, String gdtName, String languageID, String compiler,
			String[] filenames, String[] includePaths, String[] args)
			throws ParseException, ghidra.app.util.cparser.CPP.ParseException, IOException {
		
		String dataTypeFile = outputDir + File.separator + gdtName + ".gdt";
		
		File f = getArchiveFile(dataTypeFile);
		
        FileDataTypeManager dtMgr = FileDataTypeManager.createFileArchive(f);
        
		CParseResults results = CParserUtils.parseHeaderFiles(openTypes, filenames, includePaths, args, dtMgr, languageID, compiler, monitor);
		
		Msg.info(this, results.getFormattedParseMessage(null));

		dtMgr.save();
		dtMgr.close();
	}

	/**
	 * Turn string into a file, delete old archive if it exists
	 * 
	 * @param dataTypeFile name of archive file
	 * 
	 * @return file
	 */
	private File getArchiveFile(String dataTypeFile) {
		File f = new File(dataTypeFile);
		if (f.exists()) {
			f.delete();
		}
		String lockFile = dataTypeFile + ".ulock";
		File lf = new File(lockFile);
		if (lf.exists()) {
			lf.delete();
		}
		return f;
	}
	
	
	public void parseGDT_DirectX() throws Exception {
		
		String filenames[] = {
				"SDKDDKVer.h",
				"Windows.h",
				"winnt.h",
				
				"windowsx.h",
				"ddraw.h",
				"d3d.h",
				"dinput.h",
				"mmreg.h",
				"dsound.h",
		};
		
		String includeFiles[] = {
			headerFilePath+"/VC/VS22/10.0.190141.0",
			headerFilePath+"/VC/VS22/10.0.19041.0/um",
			headerFilePath+"/VC/VS22/10.0.19041.0/shared",
			headerFilePath+"/VC/VS22/10.0.19041.0/ucrt",
			headerFilePath+"/VC/VS22/Community/VC/Tools/MSVC/14.30.30705/include",			
		};
		
		String args[] = {
				"-D_AMD64_",
				"-D_M_AMD64",
				"-D_M_X64",
				"-D_WIN64",
				"-D_WIN32",
				"-v0",
		};
		
		parseHeaderFilesToGDT(outputDirectory, "directX64", "x86:LE:64:default", "windows", filenames, includeFiles, args);
	}
	
	public void parseGDT_WinVS22() throws Exception {

		String filenames[] = {
				"# Core necessary files",
				"winapifamily.h",
				"winpackagefamily.h",
				"sdkddkver.h",
				"sal.h",
				"no_sal2.h",
				"corecrt.h",
				"wtypes.h",
				"winnt.h",
				"winternl.h",
				"#ntdef.h",
				
				"# Common headers ",
				"dos.h",
				"errno.h",
				"malloc.h",
				"signal.h",
				"stdalign.h",
				"stddef.h",
				"stdio.h",
				"stdlib.h",
				"assert.h",
				"crtdbg.h",
				"ctype.h",
				"conio.h",
				"direct.h",
				"fcntl.h",
				"float.h",
				"fpieee.h",
				"inttypes.h",
				"io.h",
				"locale.h",
				"complex.h",
				"math.h",
				"mbctype.h",
				"mbstring.h",
				"memory.h",
				"minmax.h",
				"new.h",
				"process.h",
				"search.h",
				"share.h",
				"winbase.h",
				"winuser.h",
				"Windows.h",
				
				"# Security and identity (https://docs.microsoft.com/en-us/windows/win32/api/_security/)",
				"accctrl.h",
				"aclapi.h",
				"aclui.h",
				"adtgen.h",
				"authz.h",
				"azroles.h",
				"bcrypt.h",
				"casetup.h",
				"ccgplugins.h",
				"celib.h",
				"ntlsa.h",
				"sspi.h",
				"ntsecapi.h",
				"ntsecpkg.h",
				"schannel.h",
				"certadm.h",
				"certbcli.h",
				"certcli.h",
				"certenroll.h",
				"certexit.h",
				"certif.h",
				"certmod.h",
				"certpol.h",
				"certpoleng.h",
				"certsrv.h",
				"certview.h",
				"credssp.h",
				"cryptdlg.h",
				"cryptuiapi.h",
				"cryptxml.h",
				"diagnosticdataquery.h",
				"diagnosticdataquerytypes.h",
				"dpapi.h",
				"dssec.h",
				"iads.h",
				"identitycommon.h",
				"identityprovider.h",
				"identitystore.h",
				"keycredmgr.h",
				"lmaccess.h",
				"lsalookup.h",
				"mmcobj.h",
				"mscat.h",
				"mssip.h",
				"namedpipeapi.h",
				"ncrypt.h",
				"ncryptprotect.h",
				"npapi.h",
				"processthreadsapi.h",
				"sas.h",
				"scesvc.h",
				"sddl.h",
				"securityappcontainer.h",
				"securitybaseapi.h",
				"slpublic.h",
				"subauth.h",
				"tokenbinding.h",
				"tpmvscmgr.h",
				"wincred.h",
				"wincrypt.h",
				"winnetwk.h",
				"winreg.h",
				"winsafer.h",
				"winscard.h",
				"winsvc.h",
				"wintrust.h",
				"winwlx.h",
				"xenroll.h",
				
				"# Windows sockets",
				"af_irda.h",
				"in6addr.h",
				"mstcpip.h",
				"ws2def.h",
				"winsock.h",
				"winsock2.h",
				"nsemail.h",
				"nspapi.h",
				"socketapi.h",
				"# Nothing includes this; is it necessary?",
				"#sporder.h",
				"transportsettingcommon.h",
				"ws2atm.h",
				"ws2spi.h",
				"mswsock.h",
				"ws2tcpip.h",
				"wsipv6ok.h",
				"wsnwlink.h",
				"wsrm.h",
				"mswsockdef.h",
				
				"# Remote Procedure Call (RPC)",
				"midles.h",
				"midlbase.h",
				"rpc.h",
				"rpcndr.h",
				"rpcasync.h",
				"rpcdcep.h",
				"rpcnsi.h",
				"rpcproxy.h",
				"rpcssl.h",
				
				"# COM",
				"accctrl.h",
				"callobj.h",
				"combaseapi.h",
				"comcat.h",
				"ctxtcall.h",
				"dmerror.h",
				"docobj.h",
				"eventsys.h",
				"guiddef.h",
				"iaccess.h",
				"hstring.h",
				"imessagedispatcher.h",
				"messagedispatherapi.h",
				"objbase.h",
				"objidlbase.h",
				"objidl.h",
				"ocidl.h",
				"ole.h",
				"ole2.h",
				"oledlg.h",
				"oleidl.h",
				"roapi.h",
				"rpcdce.h",
				"servprov.h",
				"shobjidl.h",
				"txlogpub.h",
				"unknwnbase.h",
				"unknwn.h",
				"urlmon.h",
				"vbinterf.h",
				"winddi.h",
				"winerror.h",
				"wtypesbase.h",
				
				"# COM+",
				"comadmin.h",
				"mtxdm.h",
				
				"# More",
				"inspectable.h",
				
				"# Windows Internet",
				"proofofpossessioncookieinfo.h",
				"wininet.h",
				"winineti.h",
				
				"# Windows HTTP Services",
				"winhttp.h",
				
				"# Compression",
				"compressapi.h",
				
				"# TraceLogging",
				"#traceloggingactivity.h",
				"#traceloggingprovider.h",
				
				"# Windows Error Reporting",
				"errorrep.h",
				"werapi.h",
				
				"# Windows and MEssages",
				"olectl.h",
				"windef.h",
				"windowsx.h",
				
				"# Shell",
				"appmgmt.h",
				"appnotify.h",
				"cpl.h",
				"credentialprovider.h",
				"dimm.h",
				"imagetranscode.h",
				"inputpanelconfiguration.h",
				"intsafe.h",
				"intshcut.h",
				"mobsync.h",
				"objectarray.h",
				"pathcch.h",
				"profinfo.h",
				"propkeydef.h",
				"scrnsave.h",
				"shappmgr.h",
				"shdeprecated.h",
				"shidfact.h",
				"shimgdata.h",
				"shlwapi.h",
				"shtypes.h",
				"storageprovider.h",
				"syncmgr.h",
				"thumbcache.h",
				"thumbnailstreamcache.h",
				"tlogstg.h",
				"userenv.h",
				
				"# Windows Controls",
				"commctrl.h",
				"commoncontrols.h",
				"dpa_dsa.h",
				"prsht.h",
				"richedit.h",
				"richole.h",
				"shlobj_core.h",
				"shlobj.h",
				"#textserv.h", // C++
				"tom.h",
				"uxtheme.h",
				
				"# Menus and other resources",
				"resourceindexer.h",
				"strsafe.h",
				"verrsrc.h",
				"winver.h",
				
				"# Windows Accessibility Features",
				"oleacc.h",
				"uiautomationcore.h",
				"uiautomationclient.h",
				"uiautomationcoreapi.h",
				
				"# Internationalization",
				"datetimeapi.h",
				"elscore.h",
				"gb18030.h",
				"imepad.h",
				"imm.h",
				"immdev.h",
				"msime.h",
				"msimeapi.h",
				"muiload.h",
				"spellcheck.h",
				"spellcheckprovider.h",
				"stringapiset.h",
				"usp10.h",
				"winnls.h",
				
				"# HTTP Server API",
				"#http.h", // included by something else
				
				"# IP Helper",
				"ifdef.h",
				"inaddr.h",
				"ip2string.h",
				"ipexport.h",
				"iphlpapi.h",
				"icmpapi.h",  // Must be included after iphlpapi.h
				"iprtrmib.h",
				"iptypes.h",
				"netioapi.h",
				"nldef.h",
				"tcpestats.h",
				"ws2ipdef.h",
				
				"# Network Management",
				"atacct.h",
				"lmalert.h",
				"lmapibuf.h",
				"lmat.h",
				"lmaudit.h",
				"lmconfig.h",
				"lmerrlog.h",
				"lmjoin.h",
				"lmmsg.h",
				"lmremutl.h",
				"lmserver.h",
				"lmsvc.h",
				"lmuse.h",
				"lmwksta.h"
		};
		
		String includeFiles[] = {
			headerFilePath+"/VC/VS22/Community/VC/Tools/MSVC/14.29.30133/include",
			headerFilePath+"/VC/VS22/10.0.19041.0/shared",
			headerFilePath+"/VC/VS22/10.0.19041.0/ucrt",
			headerFilePath+"/VC/VS22/10.0.19041.0/um",
			headerFilePath+"/VC/VS22/10.0.19041.0/winrt",			
		};
		
		String args[] = {
				"-D_MSC_VER=1924",
				"-D_INTEGRAL_MAX_BITS=64",
				"-DWINVER=0x0a00",
				"-D_WIN32_WINNT=0x0a00",
				"-D_AMD64_",
				"-D_M_AMD64",
				"-D_M_X64",
				"-D_WIN64",
				"-D_WIN32",
				"-D_USE_ATTRIBUTES_FOR_SAL",
				"-D_CRTBLD",
				"-D_OPENMP_NOFORCE_MANIFEST",
				"-DSTRSAFE_LIB",
				"-DSTRSAFE_LIB_IMPL",
				"-DLPSKBINFO=LPARAM",
				"-DCONST=const",
				"-D_CRT_SECURE_NO_WARNINGS",
				"-D_CRT_NONSTDC_NO_DEPRECATE",
				"-D_CRT_NONSTDC_NO_WARNINGS",
				"-D_CRT_OBSOLETE_NO_DEPRECATE",
				"-D_ALLOW_KEYWORD_MACROS",
				"-D_ASSERT_OK",
				"-DSTRSAFE_NO_DEPRECATE",
				"-D__possibly_notnullterminated",
				"-Dtype_info=\"void *\"",
				"-D_ThrowInfo=ThrowInfo",
				"-D__unaligned=",
				"-v0",
				"-D__inner_checkReturn=",
				"-DWINAPI_PARTITION_APP=1",
				"-DWINAPI_PARTITION_SYSTEM=1",
				"-DWINAPI_PARTITION_GAMES=1",
				"-DSECURITY_WIN32",
		};
		
		parseHeaderFilesToGDT(outputDirectory, "windows_vs22_64_new", "x86:LE:64:default", "windows", filenames, includeFiles, args);
	}
}
