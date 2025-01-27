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
// Parses UEFI header file gdt archives from
// git clone https://github.com/tianocore/edk2
//
// To replace existing header files and have the data type ID's synchronized
//
// Must run SynchronizeGDTCategoryPaths.java script with old and replacement GDT
//  archive to synchronize upper/lower case paths
///   (only on windows archives)
//
// Then Run DataTypeArchiveTransformer in eclipse to synchronize old data types ID's
// if an existing .gdt file is being replaced
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

public class CreateUEFIGDTArchivesScript extends GhidraScript {

	private File outputDirectory;
	
	private static String headerFilePath = "/data/HeaderFiles/git/edk2";

	@Override
	protected void run() throws Exception {
		outputDirectory = askDirectory("Select Directory for GDT files", "Select GDT Output Dir");

		parseUEFIHeaders("X64", "x86:LE:64:default", "windows");
		parseUEFIHeaders("Ia32", "x86:LE:32:default", "windows");
		
		parseUEFIHeaders("AArch64", "AARCH64:LE:64:v8A", "windows");
		parseUEFIHeaders("Arm", "ARM:LE:32:v8", "default");
		
		parseUEFIHeaders("RiscV64", "RISCV:LE:64:RV64G", "gcc");
		parseUEFIHeaders("LoongArch64", "Loongarch:LE:64:lp64d", "default");
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
        
		FileDataTypeManager dtMgr = CParserUtils.parseHeaderFiles(openTypes, filenames,
			includePaths, args, f.getAbsolutePath(), languageID, compiler, monitor);

		dtMgr.save();
		dtMgr.close();
	}

	/**
	 * Turn string into a file, delete old archive if it exists
	 * 
	 * @param dataTypeFile
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
	
	public void parseUEFIHeaders(String name, String languageID, String compiler) throws Exception {
		
		String filenames[] = {
			"ProcessorBind.h",
			"Uefi/UefiBaseType.h",
			"Uefi/UefiSpec.h",
			"PiDxe.h",
			"PiMm.h",
			"PiPei.h",
			"PiSmm.h",
			"Library/DxeCoreEntryPoint.h",
			"Library/PeiCoreEntryPoint.h",
			"Library/PeimEntryPoint.h",
			"Library/StandaloneMmDriverEntryPoint.h",
			"Library/UefiApplicationEntryPoint.h",
			"Library/UefiDriverEntryPoint.h",
			headerFilePath+"/MdePkg/Include/Pi/",
			headerFilePath+"/MdePkg/Include/Ppi/",
			headerFilePath+"/MdePkg/Include/Protocol/",
			headerFilePath+"/MdePkg/Include/IndustryStandard/",
		};
		
		String includePaths[] = {
			headerFilePath+"/MdePkg/Include/"+name,
			headerFilePath+"/MdePkg/Include",
		};
		
		String args[] = {
		};
		
		parseHeaderFilesToGDT(outputDirectory, "uefi_"+name, languageID, compiler, filenames, includePaths, args);
	}

}
