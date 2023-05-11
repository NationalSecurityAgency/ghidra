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
import java.util.*;
import java.util.stream.Collectors;

import docking.options.editor.FileChooserEditor;
import docking.options.editor.StringWithChoicesEditor;
import generic.jar.ResourceFile;
import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.model.*;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class ApplyDataArchiveAnalyzer extends AbstractAnalyzer {
	private final static String NAME = "Apply Data Archives";
	private static final String DESCRIPTION =
		"Apply known data type archives based on program information.";

	private static final String OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks";
	private static final String OPTION_DESCRIPTION_CREATE_BOOKMARKS = """
			If checked, an analysis bookmark will be created at each symbol address \
			where multiple function definitions were found and not applied.""";
	private static final boolean OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED = true;

	private static final String OPTION_NAME_ARCHIVE_CHOOSER = "Archive Chooser";
	private static final String OPTION_DESCRIPTION_ARCHIVE_CHOOSER =
		"Specifies the data type archive to apply";

	private static final String OPTION_NAME_GDT_FILEPATH = "GDT User File Archive Path";
	private static final String OPTION_DESCRIPTION_GDT_FILEPATH = """
			Path to a user-supplied data type archive .gdt file, \
			only valid when 'Archive Chooser' is '[User-File-Archive]'""";

	private static final String OPTION_NAME_PROJECT_PATH = "User Project Archive Path";
	private static final String OPTION_DESCRIPTION_PROJECT_PATH = """
			Path to a user-supplied data type archive located in the project, \
			only valid when 'Archive Chooser' is '[User-Project-Archive]'""";

	private static final String CHOOSER_AUTO_DETECT = "[Auto-Detect]";
	private static final String CHOOSER_USER_FILE_ARCHIVE = "[User-File-Archive]";
	private static final String CHOOSER_USER_PROJECT_ARCHIVE = "[User-Project-Archive]";

	private boolean createBookmarksEnabled = OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED;
	private String archiveChooser = CHOOSER_AUTO_DETECT;
	private File userGdtFileArchive;
	private String userProjectArchive;
	private Map<String, ResourceFile> builtinGDTs = getBuiltInGdts();
	private DataTypeManagerService dtmService;

	public ApplyDataArchiveAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		if ("golang".equals(program.getCompilerSpec().getCompilerSpecID().toString())) {
			return false;
		}
		return super.getDefaultEnablement(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		dtmService = AutoAnalysisManager.getAnalysisManager(program).getDataTypeManagerService();

		// pick the archives to apply, typically 0 or 1
		List<DataTypeManager> managerList = getDataTypeArchives(program, log, monitor);

		if (!managerList.isEmpty()) {
			monitor.setMessage("Applying Function Signatures...");

			// TODO: SourceType of imported is not exactly right here.
			//       This isn't imported.  Need to add some other sourceType, like SecondaryInfo
			ApplyFunctionDataTypesCmd cmd = new ApplyFunctionDataTypesCmd(managerList, set,
				SourceType.IMPORTED, false, createBookmarksEnabled);
			cmd.applyTo(program, monitor);

			for (DataTypeManager dtm : managerList) {
				Msg.info(this, "Applied data type archive: %s".formatted(dtm.getName()));
			}
		}
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled, null,
			OPTION_DESCRIPTION_CREATE_BOOKMARKS);

		List<String> chooserList = new ArrayList<>();
		chooserList.add(CHOOSER_AUTO_DETECT);
		chooserList.add(CHOOSER_USER_FILE_ARCHIVE);
		chooserList.add(CHOOSER_USER_PROJECT_ARCHIVE);
		chooserList.addAll(builtinGDTs.keySet());

		options.registerOption(OPTION_NAME_ARCHIVE_CHOOSER, OptionType.STRING_TYPE,
			CHOOSER_AUTO_DETECT, null, OPTION_DESCRIPTION_ARCHIVE_CHOOSER,
			new StringWithChoicesEditor(chooserList));

		options.registerOption(OPTION_NAME_GDT_FILEPATH, OptionType.FILE_TYPE, null, null,
			OPTION_DESCRIPTION_GDT_FILEPATH,
			new FileChooserEditor(FileDataTypeManager.GDT_FILEFILTER));
		options.registerOption(OPTION_NAME_PROJECT_PATH, OptionType.STRING_TYPE, null, null,
			OPTION_DESCRIPTION_PROJECT_PATH, new ProjectPathChooserEditor(
				"Choose Data Type Archive", DATATYPEARCHIVE_PROJECT_FILTER));
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		createBookmarksEnabled =
			options.getBoolean(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled);
		archiveChooser = options.getString(OPTION_NAME_ARCHIVE_CHOOSER, archiveChooser);
		userGdtFileArchive = options.getFile(OPTION_NAME_GDT_FILEPATH, userGdtFileArchive);
		userProjectArchive = options.getString(OPTION_NAME_PROJECT_PATH, userProjectArchive);
	}

	private List<DataTypeManager> getDataTypeArchives(Program program, MessageLog log,
			TaskMonitor monitor) {
		switch (archiveChooser) {
			case CHOOSER_AUTO_DETECT:
				return getAutoDTMs(program, log, monitor);
			case CHOOSER_USER_FILE_ARCHIVE:
				return openUserFileArchive(userGdtFileArchive, log);
			case CHOOSER_USER_PROJECT_ARCHIVE:
				return openUserProjectArchive(userProjectArchive, program, log, monitor);
			default:
				return openBuiltinGDT(archiveChooser, log);
		}
	}

	private List<DataTypeManager> getAutoDTMs(Program program, MessageLog log,
			TaskMonitor monitor) {
		List<String> archiveList = DataTypeArchiveUtility.getArchiveList(program);
		List<DataTypeManager> result = new ArrayList<>();
		monitor.initialize(archiveList.size());

		for (String archiveName : archiveList) {
			if (monitor.isCancelled()) {
				break;
			}
			try {
				DataTypeManager dtm = dtmService.openDataTypeArchive(archiveName);
				if (dtm == null) {
					log.appendMsg("Apply Data Archives",
						"Failed to locate data type archive: " + archiveName);
				}
				else {
					result.add(dtm);
				}
			}
			catch (Exception e) {
				Throwable cause = e.getCause();
				if (cause instanceof VersionException) {
					log.appendMsg("Apply Data Archives",
						"Unable to open archive %s: %s".formatted(archiveName, cause.toString()));
				}
				else {
					String msg = Objects.requireNonNullElse(e.getMessage(), e.toString());
					log.appendMsg("Apply Data Archives",
						"Unexpected Error opening archive %s: %s".formatted(archiveName, msg));
				}
			}
		}
		return result;
	}

	private List<DataTypeManager> openBuiltinGDT(String gdtName, MessageLog log) {
		// opens a gdt that was included in the ghidra distro, not the 'built-in' dtm.

		ResourceFile gdtFile = builtinGDTs.get(gdtName);
		if (gdtFile == null) {
			log.appendMsg("Unknown built-in archive: %s".formatted(gdtName));
			return List.of();
		}
		try {
			return List.of(dtmService.openArchive(gdtFile, false));
		}
		catch (Exception e) {
			Throwable cause = e.getCause();
			if (cause instanceof VersionException) {
				log.appendMsg("Apply Data Archives",
					"Unable to open archive %s: %s".formatted(gdtName, cause.toString()));
			}
			else {
				String msg = Objects.requireNonNullElse(e.getMessage(), e.toString());
				log.appendMsg("Apply Data Archives",
					"Unexpected Error opening archive %s: %s".formatted(gdtName, msg));
			}
		}
		return List.of();
	}

	private List<DataTypeManager> openUserFileArchive(File gdtFile, MessageLog log) {
		if (gdtFile == null) {
			return List.of();
		}
		if (!gdtFile.isFile()) {
			log.appendMsg("Missing archive: %s".formatted(gdtFile));
			return List.of();
		}
		try {
			return List.of(dtmService.openArchive(new ResourceFile(gdtFile), false));
		}
		catch (Exception e) {
			Throwable cause = e.getCause();
			if (cause instanceof VersionException) {
				log.appendMsg("Apply Data Archives",
					"Unable to open archive %s: %s".formatted(gdtFile, cause.toString()));
			}
			else {
				String msg = Objects.requireNonNullElse(e.getMessage(), e.toString());
				log.appendMsg("Apply Data Archives",
					"Unexpected Error opening archive %s: %s".formatted(gdtFile, msg));
			}
		}
		return List.of();
	}

	private List<DataTypeManager> openUserProjectArchive(String filename, Program program,
			MessageLog log, TaskMonitor monitor) {
		if (filename == null || filename.isBlank()) {
			return List.of();
		}
		ProjectData projectData = program.getDomainFile().getParent().getProjectData();
		DomainFile gdtDomainFile = projectData.getFile(filename);
		if (gdtDomainFile == null) {
			log.appendMsg("Missing project archive: %s".formatted(filename));
			return List.of();
		}
		if (!DataTypeArchive.class.isAssignableFrom(gdtDomainFile.getDomainObjectClass())) {
			log.appendMsg("Bad project file type: %s".formatted(filename));
			return List.of();
		}

		try {
			return List.of(dtmService.openArchive(gdtDomainFile, monitor));
		}
		catch (Exception e) {
			Throwable cause = e.getCause();
			if (cause instanceof VersionException) {
				log.appendMsg("Apply Data Archives",
					"Unable to open project archive %s: %s".formatted(filename, cause.toString()));
			}
			else {
				String msg = Objects.requireNonNullElse(e.getMessage(), e.toString());
				log.appendMsg("Apply Data Archives",
					"Unexpected Error opening project archive %s: %s".formatted(filename, msg));
			}
		}
		return List.of();
	}
	//---------------------------------------------------------------------------------------------

	private static Map<String, ResourceFile> getBuiltInGdts() {
		return Application.findFilesByExtensionInApplication(".gdt")
				.stream()
				.collect(Collectors.toMap(f -> f.getName(), f -> f));
	}

	private static final DomainFileFilter DATATYPEARCHIVE_PROJECT_FILTER =
		df -> DataTypeArchive.class.isAssignableFrom(df.getDomainObjectClass());
}
