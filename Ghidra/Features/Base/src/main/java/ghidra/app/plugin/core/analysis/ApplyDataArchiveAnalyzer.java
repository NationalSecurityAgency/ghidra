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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class ApplyDataArchiveAnalyzer extends AbstractAnalyzer {
	private final static String NAME = "Apply Data Archives";
	private static final String DESCRIPTION =
		"Apply known data type archives based on program information.";

	protected static final String OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks";
	private static final String OPTION_DESCRIPTION_CREATE_BOOKMARKS =
		"If checked, an analysis bookmark will be created at each symbol address " +
			"where multiple function definitions were found and not applied.";
	private static final boolean OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED = true;
	private boolean createBookmarksEnabled = OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED;

	public ApplyDataArchiveAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		DataTypeManagerService service = mgr.getDataTypeManagerService();

		// pick the archives to apply
		List<String> archiveList = DataTypeArchiveUtility.getArchiveList(program);
		List<DataTypeManager> managerList = new ArrayList<>();
		monitor.initialize(archiveList.size());

		// apply the archive restricted to the address set
		for (String archiveName : archiveList) {
			if (monitor.isCancelled()) {
				break;
			}
			DataTypeManager dtm = null;
			try {
				dtm = service.openDataTypeArchive(archiveName);
				if (dtm == null) {
					log.appendMsg("Apply Data Archives",
						"Failed to locate data type archive: " + archiveName);
				}
				else {
					managerList.add(dtm);
				}
			}
			catch (Exception e) {
				Throwable cause = e.getCause();
				if (cause instanceof VersionException) {
					log.appendMsg("Apply Data Archives",
						"Unable to open archive " + archiveName + ": " + cause.toString());
				}
				else {
					String msg = e.getMessage();
					if (msg == null) {
						msg = e.toString();
					}
					log.appendMsg("Apply Data Archives",
						"Unexpected Error opening archive " + archiveName + ": " + msg);
				}
			}
		}
		monitor.setMessage("Applying Function Signatures...");
		// TODO: SourceType of imported is not exactly right here.
		//       This isn't imported.  Need to add some other sourceType, like SecondaryInfo
		ApplyFunctionDataTypesCmd cmd = new ApplyFunctionDataTypesCmd(managerList, set,
			SourceType.IMPORTED, false, createBookmarksEnabled);
		cmd.applyTo(program, monitor);
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled, null,
			OPTION_DESCRIPTION_CREATE_BOOKMARKS);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		createBookmarksEnabled =
			options.getBoolean(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled);
	}

}
