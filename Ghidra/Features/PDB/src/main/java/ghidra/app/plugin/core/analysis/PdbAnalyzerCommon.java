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
package ghidra.app.plugin.core.analysis;

import java.io.File;
import java.util.Set;

import ghidra.app.services.Analyzer;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;
import pdb.PdbPlugin;
import pdb.symbolserver.FindOption;
import pdb.symbolserver.SymbolFileInfo;

/**
 * Shared configuration values and pdb searching logic
 */
public class PdbAnalyzerCommon {
	static final String OPTION_DESCRIPTION_SEARCH_REMOTE_LOCATIONS =
		"If checked, allow searching remote symbol servers for PDB files.";
	static final String OPTION_NAME_SEARCH_REMOTE_LOCATIONS = "Search remote symbol servers";

	static final String OPTION_DESCRIPTION_PDB_FILE = "Path to a manually chosen PDB file.";
	static final String OPTION_NAME_PDB_FILE = "PDB File";

	// TODO: I changed this method from what was lifted in the old code.  I check for null string
	//  and I also check for MSCOFF_NAME (TODO: check on the validity of this!!!).  Also, changed
	//  the comparison to a substring search from a .equals).
	/**
	 * Returns true if the specified program is supported by either of the
	 * Pdb analyzers.
	 * 
	 * @param program {@link Program}
	 * @return boolean true if program is supported by Pdb analyzers
	 */
	public static boolean canAnalyzeProgram(Program program) {
		String executableFormat = program.getExecutableFormat();
		return executableFormat != null && (executableFormat.indexOf(PeLoader.PE_NAME) != -1);
		// TODO: Check for MSCOFF_NAME.  Initial investigation shows that the .debug$T section of
		//  the MSCOFF (*.obj) file has type records and the .debug$S section has symbol records.
		//  More than that, in at least one instance, there has been a TypeServer2MsType type
		//  record that give the GUID, age, and name of the PDB file associated with the MSCOFF
		//  file.  At this point in time, these two sections of the MSCOFF are read (header and
		//  raw data), but we do not interpret these sections any further.  Suggest that we "might"
		//  want to parse some of these records at load time?  Maybe not.  We could, at analysis
		//  time, add the ability to process these two sections (as part of analysis (though we
		//  will not be aware of a PDB file yet), and upon discovery of a TypeServer2MsType (or
		//  perhaps other?), proceed to find the file (if possible) and also process that file.
		//  We posit that if a record indicates a separate PDB for the types (Note: MSFT indicates
		//  that only data types will be found in an MSCOFF PDB file), then that will likely be
		//  the only record in the .debug$T section.
		// TODO: If the MSCOFF file is located in a MSCOFF ARCHIVE (*.lib), there can be a PDB
		//  associated with the archive.  We currently do not pass on this association of the
		//  PDB archive to each underlying MSCOFF file.  Moreover, we believe that we are not
		//  currently discovering the associated MSCOFF ARCHIVE PDB file when processing the
		//  MSCOFF ARCHIVE.  Initial indication is that each MSCOFF within the archive will have
		//  the PDB file that it needs listed, even if redundant for each MSCOFF within the
		//  archive.
//		return executableFormat != null && (executableFormat.indexOf(PeLoader.PE_NAME) != -1 ||
//				executableFormat.indexOf(MSCoffLoader.MSCOFF_NAME) != -1);

	}

	/**
	 * Common logic to set a manual Pdb file that the specified analyzer will find and use
	 * when it is invoked later<p>
	 * Each specific analyzer has a public method that calls this to supply the
	 * actual analyzer name to make it easier for script writers to call.
	 * 
	 * @param analyzerName name of analyzer
	 * @param program {@link Program}
	 * @param pdbFile the file
	 */
	static void setPdbFileOption(String analyzerName, Program program, File pdbFile) {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		options.setFile(analyzerName + "." + OPTION_NAME_PDB_FILE, pdbFile);
	}

	/**
	 * Common logic to set the "allow remote" option that the specified analyzer will find and use
	 * when it is invoked later<p>
	 * Each specific analyzer has a public method that calls this to supply the
	 * actual analyzer name to make it easier for script writers to call.
	 * 
	 * @param analyzerName name of analyzer
	 * @param program {@link Program}
	 * @param allowRemote boolean flag, true means the analyzer can search remote
	 * symbol servers
	 */
	static void setAllowRemoteOption(String analyzerName, Program program, boolean allowRemote) {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		options.setBoolean(analyzerName + "." + OPTION_NAME_SEARCH_REMOTE_LOCATIONS, allowRemote);
	}

	/**
	 * Common pdb searching logic between both analyzers.
	 * 
	 * @param pdbAnalyzer the analyzer doing the searching
	 * @param program the program
	 * @param allowRemote boolean flag, true means searching remote symbol servers
	 *  is allowed 
	 * @param monitor {@link TaskMonitor} to let user cancel
	 * @return File pointing to the found pdb, or null if not found or error
	 */
	static File findPdb(Analyzer pdbAnalyzer, Program program, boolean allowRemote,
			TaskMonitor monitor) {

		SymbolFileInfo symbolFileInfo = SymbolFileInfo.fromProgramInfo(program);
		if (symbolFileInfo == null) {
			Msg.info(pdbAnalyzer,
				"Skipping PDB processing: missing PDB information in program metadata");
			return null;
		}

		// First look in the program's analysis options to see if there is a
		// manually specified pdbFile. (see setPdbFileOption)
		// If not set, then do a search using the currently configured symbol servers.
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		String pdbFileOptionName = pdbAnalyzer.getName() + "." + OPTION_NAME_PDB_FILE;

		// check existence first to avoid creating option value
		File pdbFile = options.contains(pdbFileOptionName)
				? options.getFile(pdbFileOptionName, null)
				: null;
		if (pdbFile == null) {
			Set<FindOption> findOpts = allowRemote
					? FindOption.of(FindOption.ALLOW_REMOTE)
					: FindOption.NO_OPTIONS;
			pdbFile = PdbPlugin.findPdb(program, findOpts, monitor);
		}
		if (pdbFile == null) {
			Msg.info(pdbAnalyzer,
				"Skipping PDB processing: failed to locate PDB file in configured locations");
			if (SystemUtilities.isInHeadlessMode()) {
				Msg.info(pdbAnalyzer,
					"Use a script to set the PDB file location. I.e.,\n" +
					"    PdbAnalyzer.setPdbFileOption(currentProgram, new File(\"/path/to/pdb/file.pdb\")); or\n" +
					"    PdbUniversalAnalyzer.setPdbFileOption(currentProgram, new File(\"/path/to/pdb/file.pdb\"));\n" +
					"Or set the symbol server search configuration using:" +
					"    PdbPlugin.saveSymbolServerServiceConfig(...);\n" +
					" This must be done using a pre-script (prior to analysis).");
			}
			else {
				Msg.info(pdbAnalyzer,
					"You may set the PDB \"Symbol Server Config\"" +
					"\n using \"Edit->Symbol Server Config\" prior to analysis." +
					"\nIt is important that a PDB is used during initial analysis " +
					"\nif available.");
			}
		}
		else {
			Msg.info(pdbAnalyzer, "PDB analyzer parsing file: " + pdbFile);
			if (!pdbFile.isFile()) {
				Msg.error(pdbAnalyzer,
					"Skipping PDB processing: specified file does not exist or is not readable: " +
						pdbFile);
				return null;
			}

		}
		return pdbFile;
	}

}
