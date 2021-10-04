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
package ghidra.plugin.importer;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.util.*;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.*;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.LibrarySearchPathManager;
import ghidra.app.util.opinion.LoaderMap;
import ghidra.app.util.opinion.LoaderService;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileCache.FileCacheEntry;
import ghidra.formats.gfilesystem.FileCache.FileCacheEntryBuilder;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.main.*;
import ghidra.framework.main.datatree.DomainFolderNode;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.plugins.importer.batch.BatchImportDialog;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.TaskLauncher;

/**
 * A {@link Plugin} that supplies menu items and tasks to import files into Ghidra.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Import External Files (NEW)",
	description = ImporterPlugin.IMPORTER_PLUGIN_DESC,
	servicesRequired = { TextEditorService.class },
	servicesProvided = { FileImporterService.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class ImporterPlugin extends Plugin
		implements FileImporterService, FrontEndable, ProjectListener {

	private static final String IMPORT_MENU_GROUP = "Import";
	static final String IMPORTER_PLUGIN_DESC =
		"This plugin manages importing files, including those contained within " +
			"firmware/filesystem images.";

	private DockingAction importAction;
	private DockingAction importSelectionAction;// NA in front-end
	private DockingAction addToProgramAction;
	private GhidraFileChooser chooser;
	private FrontEndService frontEndService;
	private DockingAction batchImportAction;

	public ImporterPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();

		frontEndService = tool.getService(FrontEndService.class);
		if (frontEndService != null) {
			frontEndService.addProjectListener(this);
		}

		setupImportAction();
		setupImportSelectionAction();
		setupAddToProgramAction();
		setupBatchImportAction();
	}

	@Override
	public void readConfigState(SaveState saveState) {
		super.readConfigState(saveState);
		String[] paths = saveState.getStrings("library search paths", null);
		if (paths != null) {
			LibrarySearchPathManager.setLibraryPaths(paths);
		}
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		super.writeConfigState(saveState);

		String[] paths = LibrarySearchPathManager.getLibraryPaths();
		saveState.putStrings("library search paths", paths);
	}

	@Override
	protected void dispose() {
		super.dispose();
		if (importAction != null) {
			importAction.dispose();
		}
		if (importSelectionAction != null) {
			importSelectionAction.dispose();
		}
		if (addToProgramAction != null) {
			addToProgramAction.dispose();
		}
		if (frontEndService != null) {
			frontEndService.removeProjectListener(this);
			frontEndService = null;
		}
		chooser = null;
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);

		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent pape = (ProgramActivatedPluginEvent) event;
			Program currentProgram = pape.getActiveProgram();
			importSelectionAction.setEnabled(currentProgram != null);
			addToProgramAction.setEnabled(currentProgram != null);
		}
	}

	@Override
	public void importFiles(DomainFolder destFolder, List<File> files) {
		BatchImportDialog.showAndImport(tool, null, files2FSRLs(files), destFolder,
			getTool().getService(ProgramManager.class));
	}

	private List<FSRL> files2FSRLs(List<File> files) {
		if (files == null) {
			return Collections.emptyList();
		}

		List<FSRL> result = new ArrayList<>(files.size());
		for (File f : files) {
			result.add(FileSystemService.getInstance().getLocalFSRL(f));
		}
		return result;
	}

	@Override
	public void importFile(DomainFolder folder, File file) {

		FSRL fsrl = FileSystemService.getInstance().getLocalFSRL(file);
		ProgramManager manager = tool.getService(ProgramManager.class);
		ImporterUtilities.showImportDialog(tool, manager, fsrl, folder, null);
	}

	@Override
	public void projectClosed(Project project) {
		if (importAction != null) {
			importAction.setEnabled(false);
		}
		if (importSelectionAction != null) {
			importSelectionAction.setEnabled(false);
		}
		if (addToProgramAction != null) {
			addToProgramAction.setEnabled(false);
		}
		ProgramMappingService.clear();
	}

	@Override
	public void projectOpened(Project project) {
		if (importAction != null) {
			importAction.setEnabled(true);
		}
		if (importSelectionAction != null) {
			importSelectionAction.setEnabled(false);
		}
		if (addToProgramAction != null) {
			addToProgramAction.setEnabled(false);
		}

		ProgramMappingService.clear();
	}

	private void setupImportAction() {
		String title = "Import File";
		importAction = new DockingAction(title, this.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				doSingleImportAction(getFolderFromContext(context));
			}
		};
		importAction.setMenuBarData(new MenuData(new String[] { "&File", title + "..." }, null,
			IMPORT_MENU_GROUP, MenuData.NO_MNEMONIC, "1"));
		importAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_I, 0));
		importAction.setDescription(IMPORTER_PLUGIN_DESC);
		importAction.setEnabled(tool.getProject() != null);
		importAction.setHelpLocation(new HelpLocation("ImporterPlugin", "Import_File"));
		tool.addAction(importAction);
	}

	private void setupBatchImportAction() {
		String title = "Batch Import";
		batchImportAction = new DockingAction(title, this.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				BatchImportDialog.showAndImport(tool, null, null, getFolderFromContext(context),
					getTool().getService(ProgramManager.class));
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return tool.getProject() != null;
			}
		};
		batchImportAction.setMenuBarData(new MenuData(new String[] { "&File", title + "..." }, null,
			IMPORT_MENU_GROUP, MenuData.NO_MNEMONIC, "2"));
		batchImportAction.setDescription(IMPORTER_PLUGIN_DESC);
		batchImportAction.setHelpLocation(new HelpLocation("ImporterPlugin", title));

		tool.addAction(batchImportAction);
	}

	private void setupImportSelectionAction() {
		String title = "Extract and Import";
		importSelectionAction = new DockingAction(title, this.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (context instanceof ListingActionContext) {
					doImportSelectionAction(
						((ListingActionContext) context).getNavigatable().getSelection());
				}
			}

			@Override
			public boolean isValidContext(ActionContext context) {
				if (context instanceof ListingActionContext) {
					ProgramSelection selection =
						((ListingActionContext) context).getNavigatable().getSelection();
					return selection != null && selection.getNumAddressRanges() == 1;
				}
				return false;
			}
		};
		importSelectionAction.setPopupMenuData(new MenuData(new String[] { title + "..." }, null,
			IMPORT_MENU_GROUP, MenuData.NO_MNEMONIC, "d"));
		importSelectionAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_I,
			InputEvent.CTRL_DOWN_MASK | InputEvent.ALT_DOWN_MASK));
		importSelectionAction.setDescription(IMPORTER_PLUGIN_DESC);
		importSelectionAction.setEnabled(tool.getProject() != null);

		tool.addAction(importSelectionAction);
	}

	private void setupAddToProgramAction() {
		String title = "Add To Program";

		addToProgramAction = new DockingAction(title, this.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				doAddToProgram();
			}
		};
		addToProgramAction.setMenuBarData(new MenuData(new String[] { "&File", title + "..." },
			null, IMPORT_MENU_GROUP, MenuData.NO_MNEMONIC, "zz"));
		addToProgramAction.setDescription(IMPORTER_PLUGIN_DESC);
		addToProgramAction.setEnabled(false);

		// Add to program makes no sense in the front end tool, but we create it so that the
		// addToProgramAction won't be null and we would have to check that in other places.
		if (!(tool instanceof FrontEndTool)) {
			tool.addAction(addToProgramAction);
		}
	}

	private static DomainFolder getFolderFromContext(ActionContext context) {
		Object contextObj = context.getContextObject();
		if (contextObj instanceof DomainFolderNode) {
			DomainFolderNode node = (DomainFolderNode) contextObj;
			return node.getDomainFolder();
		}

		return AppInfo.getActiveProject().getProjectData().getRootFolder();
	}

	private void initializeChooser(String title, String buttonText, boolean multiSelect) {
		if (chooser == null) {
			chooser = new GhidraFileChooser(tool.getActiveWindow());
			chooser.addFileFilter(ImporterUtilities.LOADABLE_FILES_FILTER);
			chooser.addFileFilter(ImporterUtilities.CONTAINER_FILES_FILTER);
			chooser.setSelectedFileFilter(GhidraFileFilter.ALL);
		}
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setMultiSelectionEnabled(multiSelect);
		chooser.setTitle(title);
		chooser.setApproveButtonText(buttonText);

		String lastFile = Preferences.getProperty(ImporterDialog.LAST_IMPORTFILE_PREFERENCE_KEY);
		if (lastFile != null) {
			chooser.setSelectedFile(new File(lastFile));
		}
	}

	private void doSingleImportAction(DomainFolder defaultFolder) {
		initializeChooser("Select File to Import", "Select File To Import", false);
		File file = chooser.getSelectedFile();
		if (chooser.wasCancelled()) {
			return;
		}

		if (file == null) {
			Msg.showInfo(this, tool.getActiveWindow(), "No file selected",
				"No file will be imported.");
		}
		else if (!file.exists()) {
			Msg.showInfo(this, tool.getActiveWindow(), "File Error",
				"File does not exist: " + file.getPath());
		}
		else {
			importFile(defaultFolder, file);
		}
	}

	private void doAddToProgram() {
		initializeChooser("Add To Program", "Add To Program", false);
		File file = chooser.getSelectedFile();
		if (file == null) {
			Msg.showInfo(getClass(), null, "No file selected", "No file will be imported.");
			return;
		}
		addToProgram(file);
	}

	private void addToProgram(File file) {
		if (file.length() == 0) {
			Msg.showInfo(this, null, "Import File Failed",
				"File " + file.getName() + " is empty (0 bytes).");
			return;
		}

		ProgramManager manager = tool.getService(ProgramManager.class);
		Program program = manager.getCurrentProgram();

		FSRL fsrl = FileSystemService.getInstance().getLocalFSRL(file);
		TaskLauncher.launchModal("Show Add To Program Dialog", monitor -> {
			ImporterUtilities.showAddToProgramDialog(fsrl, program, tool, monitor);
		});

	}

	protected void doImportSelectionAction(ProgramSelection selection) {
		if (selection == null || selection.getNumAddressRanges() != 1) {
			return;
		}

		AddressRange range = selection.getFirstRange();// should only be 1
		if (range.getLength() >= (Integer.MAX_VALUE & 0xffffffffL)) {
			Msg.showInfo(getClass(), tool.getActiveWindow(), "Selection Too Large",
				"The selection is too large to extract.");
			return;
		}

		ProgramManager programManager = tool.getService(ProgramManager.class);
		Program program = programManager.getCurrentProgram();
		if (program == null) {
			return;
		}

		try {
			Memory memory = program.getMemory();
			FileSystemService fsService = FileSystemService.getInstance();

			// create a tmp ByteProvider that contains the bytes from the selected region
			FileCacheEntry tmpFile;
			try (FileCacheEntryBuilder tmpFileBuilder =
				fsService.createTempFile(range.getLength())) {
				byte[] bytes = new byte[(int) range.getLength()];
				memory.getBytes(range.getMinAddress(), bytes);
				tmpFileBuilder.write(bytes);
				tmpFile = tmpFileBuilder.finish();
			}

			MemoryBlock block = memory.getBlock(range.getMinAddress());
			String rangeName =
				block.getName() + "[" + range.getMinAddress() + "," + range.getMaxAddress() + "]";
			ByteProvider bp =
				fsService.getNamedTempFile(tmpFile, program.getName() + " " + rangeName);
			LoaderMap loaderMap = LoaderService.getAllSupportedLoadSpecs(bp);

			ImporterDialog importerDialog =
				new ImporterDialog(tool, programManager, loaderMap, bp, null);
			tool.showDialog(importerDialog);
		}
		catch (IOException e) {
			Msg.showError(this, null, "I/O Error Occurred", e.getMessage(), e);
		}
		catch (MemoryAccessException e) {
			Msg.showError(this, null, "Memory Access Error Occurred", e.getMessage(), e);
		}
	}
}
