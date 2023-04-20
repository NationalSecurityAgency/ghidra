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
// Parses sample linux and windows JNI header files into .gdt data type archive.
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

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.util.cparser.C.CParserUtils.CParseResults;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.util.Msg;

public class CreateJNIGDTArchivesScript extends GhidraScript {

	private File outputDirectory;
	
	// location of header files base directory
	private static String headerFilePath = "/data/HeaderFiles";

	@Override
	protected void run() throws Exception {
		outputDirectory = askDirectory("Select Directory for GDT files", "Select GDT Output Dir");
		
		parseGDT_Linux_JNI();

		parseGDT_Windows_JNI();

	}

	private void parseHeaderFilesToGDT(DataTypeManager openTypes[], File outputDir, String gdtName, String languageID, String compiler, String[] filenames, String[] args)
			throws ParseException, ghidra.app.util.cparser.CPP.ParseException, IOException {
		
		String dataTypeFile = outputDir + File.separator + gdtName + ".gdt";
		
		File f = getArchiveFile(dataTypeFile);
		
        FileDataTypeManager dtMgr = FileDataTypeManager.createFileArchive(f);
        
		CParseResults results = CParserUtils.parseHeaderFiles(openTypes, filenames, args, dtMgr, languageID, compiler, monitor);
		
		Msg.info(this, results.getFormattedParseMessage(null));

		dtMgr.save();
		dtMgr.close();
	}
	
	/**
	 * Turn string into a file, delete old archive/lock file if it exists
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


	public void parseGDT_Linux_JNI() throws Exception {	
		String filenames[] = {
				"jni.h",
				"jawt.h",
				"jdwpTransport.h",
				"jvmti.h",
				"jvmticmlr.h",
				"classfile_constants.h",
		};
		
		String args[] = {
				"-I"+headerFilePath+"/jni/linux",
				"-I"+headerFilePath+"/jni/linux/linux",
				"-D_X86_",
				"-D__STDC__",
				"-D_GNU_SOURCE",
				"-D__WORDSIZE=64",
				"-D__builtin_va_list=void *",
				"-D__DO_NOT_DEFINE_COMPILE",
				"-D_Complex",
				"-D__NO_STRING_INLINES",
				"-D__signed__",
				"-D__extension__=",
				"-D__GLIBC_HAVE_LONG_LONG=1",
				"-D__need_sigset_t",
				"-Daligned_u64=uint64_t",
		};

		
		// Using another archive while parsing will cause:
		//  - a dependence on the other archive
		//  - any missing data types while parsing are supplied if present from existingDTMgr
		//  - after parsing all data types parsed that have an equivalent data type will be
		//    replaced by the data type from the existingDTMgr
		//
		// NOTE: This will only occur if the data type from the exisitngDTMgr is equivalent.
		//
		ResourceFile clib64ArchiveFile = DataTypeArchiveUtility.findArchiveFile("generic_clib_64.gdt");
		File file = new File(clib64ArchiveFile.getAbsolutePath());
		DataTypeManager existingDTMgr = FileDataTypeManager.openFileArchive(file, false);
		DataTypeManager openTypes[] = { existingDTMgr };
		
		parseHeaderFilesToGDT(openTypes, outputDirectory, "jni_linux", "x86:LE:64:default", "gcc", filenames, args);
	}
	
	public void parseGDT_Windows_JNI() throws Exception {	
		String filenames[] = {
				"jni.h",
				"jawt.h",
				"jdwpTransport.h",
				"jvmti.h",
				"jvmticmlr.h",
				"classfile_constants.h",
		};
		
		String args[] = {
				"-I"+headerFilePath+"/jni/win32",
				"-I"+headerFilePath+"/jni/win32/win32",
				"-D_X86_",
				"-D__STDC__",
				"-D_GNU_SOURCE",
				"-D__WORDSIZE=64",
				"-D__builtin_va_list=void *",
				"-D__DO_NOT_DEFINE_COMPILE",
				"-D_Complex",
				"-D__NO_STRING_INLINES",
				"-D__signed__",
				"-D__extension__=",
				"-D__GLIBC_HAVE_LONG_LONG=1",
				"-D__need_sigset_t",
				"-Daligned_u64=uint64_t",
		};

		// Using another archive while parsing will cause:
		//  - a dependence on the other archive
		//  - any missing data types while parsing are supplied if present from existingDTMgr
		//  - after parsing all data types parsed that have an equivalent data type will be
		//    replaced by the data type from the existingDTMgr
		//
		// NOTE: This will only occur if the data type from the exisitngDTMgr is equivalent.
		//
		ResourceFile clib64ArchiveFile = DataTypeArchiveUtility.findArchiveFile("windows_vs12_64.gdt");
		File file = new File(clib64ArchiveFile.getAbsolutePath());
		DataTypeManager existingDTMgr = FileDataTypeManager.openFileArchive(file, false);
		DataTypeManager openTypes[] = { existingDTMgr };
		
		parseHeaderFilesToGDT(openTypes, outputDirectory, "jni_windows", "x86:LE:64:default", "windows", filenames, args);
	}
}
