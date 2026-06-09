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
package ghidra.app.plugin.core.sourcefilestable;

import static ghidra.program.util.ProgramEvent.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.*;

import docking.DockingWindowManager;
import docking.action.builder.ActionBuilder;
import docking.options.editor.StringWithChoicesEditor;
import docking.widgets.values.GValuesMap;
import docking.widgets.values.ValuesMapDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.EclipseIntegrationService;
import ghidra.app.services.VSCodeIntegrationService;
import ghidra.framework.model.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.database.sourcemap.UserDataPathTransformer;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.sourcemap.*;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.SourceMapFieldLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.bean.opteditor.OptionsVetoException;
import ghidra.util.task.MonitoredRunnable;
import ghidra.util.task.TaskBuilder;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Source File Table",
	description = "Plugin for viewing and managing source file information.",
	eventsConsumed = { ProgramClosedPluginEvent.class }
)
//@formatter:on

/**
 * A {@link ProgramPlugin} for displaying source file information about a program
 * and for managing source file path transforms.
 */
public class SourceFilesTablePlugin extends ProgramPlugin implements OptionsChangeListener {

	private SourceFilesTableProvider provider;
	private DomainObjectListener listener;

	private static final String USE_EXISTING_AS_DEFAULT_OPTION_NAME =
		"Use Existing Path as Default";
	private boolean useExistingAsDefault = true;

	private static final String ECLIPSE = "Eclipse";
	private static final String VS_CODE = "VS Code";
	private static final String[] VIEWERS = { ECLIPSE, VS_CODE };
	private static final String SELECTED_VIEWER_OPTION_NAME = "Viewer for Source Files";
	private String selectedViewer = VS_CODE;
	private File vscodeExecutable = null;
	private File eclipseExecutable = null;

	/**
	 * Constructor
	 * @param plugintool tool
	 */
	public SourceFilesTablePlugin(PluginTool plugintool) {
		super(plugintool);
	}

	@Override
	public void init() {
		super.init();
		provider = new SourceFilesTableProvider(this);
		listener = createDomainObjectListener();
		initOptions(tool.getOptions("Source Files and Transforms"));
		createAction();
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) throws OptionsVetoException {
		switch (optionName) {
			case USE_EXISTING_AS_DEFAULT_OPTION_NAME:
				useExistingAsDefault =
					options.getBoolean(USE_EXISTING_AS_DEFAULT_OPTION_NAME, true);
				break;
			case SELECTED_VIEWER_OPTION_NAME:
				selectedViewer = options.getString(SELECTED_VIEWER_OPTION_NAME, VS_CODE);
				break;
			default:
				break;
		}
	}

	@Override
	protected void programActivated(Program program) {
		program.addListener(listener);
		provider.programActivated(program);
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(listener);
		provider.clearTableModels();
	}

	@Override
	protected void dispose() {
		if (currentProgram != null) {
			currentProgram.removeListener(listener);
		}
		tool.removeComponentProvider(provider);
	}

	private DomainObjectListener createDomainObjectListener() {
		// @formatter:off
		return new DomainObjectListenerBuilder(this)
			.ignoreWhen(() -> !provider.isVisible())
			.any(DomainObjectEvent.RESTORED, MEMORY_BLOCK_MOVED, MEMORY_BLOCK_REMOVED)
			.terminate(c -> provider.setIsStale(true))
			.with(ProgramChangeRecord.class)
			.each(SOURCE_FILE_ADDED,SOURCE_FILE_REMOVED,SOURCE_MAP_CHANGED)
			.call(provider::handleProgramChange)
			.build();
		// @formatter:on
	}

	private void createAction() {
		new ActionBuilder("View Source", getName())
				.popupMenuPath("View Source...")
				.popupMenuGroup("ZZZ")
				.helpLocation(new HelpLocation(getName(), "View_Source"))
				.withContext(ListingActionContext.class)
				.enabledWhen(c -> isEnabled(c))
				.onAction(c -> viewSourceFile(c))
				.buildAndInstall(tool);
	}

	private boolean isEnabled(ListingActionContext context) {
		Address address = context.getAddress();
		SourceFileManager manager = getCurrentProgram().getSourceFileManager();
		return manager.getSourceMapEntries(address).size() > 0;
	}

	private void viewSourceFile(ListingActionContext context) {
		Address address = context.getAddress();
		SourceFileManager manager = getCurrentProgram().getSourceFileManager();
		List<SourceMapEntry> entries = manager.getSourceMapEntries(address);
		if (entries.isEmpty()) {
			return; // sanity check
		}
		// if there's only one entry associated with the address, just view it
		if (entries.size() == 1) {
			SourceMapEntry entry = entries.get(0);
			openInViewer(entry.getSourceFile(), entry.getLineNumber());
			return;
		}
		// if there are multiple entries, we need to decide which one to view
		// if the user right-clicked in the SourceMapField in the Listing, open
		// the associated entry
		if (context.getLocation() instanceof SourceMapFieldLocation sourceLoc) {
			SourceMapEntry entry = sourceLoc.getSourceMapEntry();
			openInViewer(entry.getSourceFile(), entry.getLineNumber());
			return;
		}
		// otherwise pop up a window and ask the user to select an entry
		GValuesMap valuesMap = new GValuesMap();
		Map<String, SourceMapEntry> stringsToEntries = new HashMap<>();
		for (SourceMapEntry entry : entries) {
			stringsToEntries.put(entry.toString(), entry);
		}
		valuesMap.defineChoice("Entry", entries.get(0).toString(),
			stringsToEntries.keySet().toArray(new String[0]));
		ValuesMapDialog dialog =
			new ValuesMapDialog("Select Entry to View", null, valuesMap);
		DockingWindowManager.showDialog(dialog);
		if (dialog.isCancelled()) {
			return;
		}
		GValuesMap results = dialog.getValues();
		if (results == null) {
			return;
		}
		String selected = results.getChoice("Entry");
		if (selected == null) {
			return;
		}
		SourceMapEntry entryToShow = stringsToEntries.get(selected);
		openInViewer(entryToShow.getSourceFile(), entryToShow.getLineNumber());
	}

	void openInViewer(SourceFile sourceFile, int lineNum) {
		if (sourceFile == null) {
			return;
		}
		SourcePathTransformer transformer =
			UserDataPathTransformer.getPathTransformer(currentProgram);
		String transformedPath =
			transformer.getTransformedPath(sourceFile, useExistingAsDefault);

		if (transformedPath == null) {
			Msg.showWarn(this, null, "No Path Transform",
				"No path transformation applies to " + sourceFile.toString());
			return;
		}

		File localSourceFile = new File(transformedPath);
		if (!localSourceFile.exists()) {
			Msg.showWarn(transformer, null, "File Not Found",
				localSourceFile.getAbsolutePath() + " does not exist");
			return;
		}

		switch (selectedViewer) {
			case ECLIPSE:
				openFileInEclipse(localSourceFile.getAbsolutePath(), lineNum);
				break;
			case VS_CODE:
				openFileInVsCode(localSourceFile.getAbsolutePath(), lineNum);
				break;
			default:
				throw new AssertionError("Unsupported Viewer: " + selectedViewer);
		}
	}

	private void openFileInEclipse(String path, int lineNumber) {
		EclipseIntegrationService eclipseService = tool.getService(EclipseIntegrationService.class);
		if (eclipseService == null) {
			Msg.showError(this, null, "Eclipse Service Error",
				"Eclipse service not configured for tool");
			return;
		}

		try {
			eclipseExecutable = eclipseService.getEclipseExecutableFile();
		}
		catch (FileNotFoundException e) {
			Msg.showError(this, null, "Missing Eclipse Executable", e.getMessage());
			return;
		}
		MonitoredRunnable r = m -> {
			try {
				List<String> args = new ArrayList<>();
				args.add(eclipseExecutable.getAbsolutePath());
				args.add(path + ":" + lineNumber);
				new ProcessBuilder(args).redirectErrorStream(true).start();
			}
			catch (Exception e) {
				eclipseService.handleEclipseError(
					"Unexpected exception occurred while launching Eclipse.", false,
					null);
				return;
			}
		};

		new TaskBuilder("Opening File in Eclipse", r)
				.setHasProgress(false)
				.setCanCancel(true)
				.launchModal();
		return;

	}

	private void openFileInVsCode(String path, int lineNumber) {
		VSCodeIntegrationService vscodeService = tool.getService(VSCodeIntegrationService.class);
		if (vscodeService == null) {
			Msg.showError(this, null, "VSCode Service Error",
				"VSCode service not configured for tool");
			return;
		}

		try {
			vscodeExecutable = vscodeService.getVSCodeExecutableFile();
		}
		catch (FileNotFoundException e) {
			Msg.showError(this, null, "Missing VSCode executable", e.getMessage());
			return;
		}

		MonitoredRunnable r = m -> {
			try {
				List<String> args = new ArrayList<>();
				args.add(vscodeExecutable.getAbsolutePath());
				args.add("--goto");
				args.add(path + ":" + lineNumber);
				new ProcessBuilder(args).redirectErrorStream(true).start();
			}
			catch (Exception e) {
				vscodeService.handleVSCodeError(
					"Unexpected exception occurred while launching Visual Studio Code.", false,
					null);
				return;
			}
		};

		new TaskBuilder("Opening File in VSCode", r)
				.setHasProgress(false)
				.setCanCancel(true)
				.launchModal();
		return;

	}

	private void initOptions(ToolOptions options) {
		options.registerOption(USE_EXISTING_AS_DEFAULT_OPTION_NAME, true,
			new HelpLocation(getName(), "Use_Existing_As_Default"),
			"Use a source file's existing path if no transform applies");
		useExistingAsDefault = options.getBoolean(USE_EXISTING_AS_DEFAULT_OPTION_NAME, true);

		options.registerOption(SELECTED_VIEWER_OPTION_NAME,
			OptionType.STRING_TYPE, VS_CODE,
			new HelpLocation(getName(), "Viewer_for_Source_Files"),
			"Viewer for Source Files",
			() -> new StringWithChoicesEditor(VIEWERS));
		selectedViewer = options.getString(SELECTED_VIEWER_OPTION_NAME, VS_CODE);
		options.addOptionsChangeListener(this);

		options.setOptionsHelpLocation(
			new HelpLocation(getName(), "Source_Files_Table_Plugin_Options"));
	}
}
