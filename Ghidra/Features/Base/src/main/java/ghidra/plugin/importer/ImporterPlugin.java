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
import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.List;

import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.FileImporterService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.*;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileCache.FileCacheEntry;
import ghidra.formats.gfilesystem.FileCache.FileCacheEntryBuilder;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.main.*;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.*;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.store.local.ItemDeserializer;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.plugins.importer.batch.BatchImportDialog;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.*;

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
	servicesProvided = { FileImporterService.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class ImporterPlugin extends Plugin
		implements FileImporterService, ApplicationLevelPlugin, ProjectListener {

	private static final String IMPORT_MENU_GROUP = "Import";
	static final String IMPORTER_PLUGIN_DESC =
		"This plugin manages importing files, including those contained within " +
			"firmware/filesystem images.";

	private static final String SIMPLE_UNPACK_OPTION = "Enable simple GZF/GDT unpack";
	private static final boolean SIMPLE_UNPACK_OPTION_DEFAULT = false;

	private DockingAction importAction;
	private DockingAction importSelectionAction;
	private DockingAction addToProgramAction;
	private DockingAction loadLibrariesAction;
	private GhidraFileChooser chooser;
	private FrontEndService frontEndService;
	private DockingAction batchImportAction;
	private FileSystemService fsService;

	public ImporterPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();

		frontEndService = tool.getService(FrontEndService.class);
		if (frontEndService != null) {
			frontEndService.addProjectListener(this);

			ToolOptions options = tool.getOptions(ToolConstants.FILE_IMPORT_OPTIONS);
			HelpLocation help = new HelpLocation("ImporterPlugin", "Project_Tree");

			options.registerOption(SIMPLE_UNPACK_OPTION, SIMPLE_UNPACK_OPTION_DEFAULT, help,
				"Perform simple unpack when any packed DB file is imported");
		}

		setupImportAction();
		setupImportSelectionAction();
		setupAddToProgramAction();
		setupLoadLibrariesAction();
		setupBatchImportAction();
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

		if (chooser != null) {
			chooser.dispose();
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);

		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent pape = (ProgramActivatedPluginEvent) event;
			Program currentProgram = pape.getActiveProgram();
			importSelectionAction.setEnabled(currentProgram != null);
			addToProgramAction.setEnabled(currentProgram != null);
			loadLibrariesAction.setEnabled(shouldEnableLoadLibraries(currentProgram));
		}
	}

	private boolean shouldEnableLoadLibraries(Program program) {
		if (program == null) {
			return false;
		}
		ByteProvider provider = ImporterUtilities.getProvider(program);
		if (provider == null) {
			return false;
		}
		LoadSpec loadSpec = ImporterUtilities.getLoadSpec(provider, program);
		if (loadSpec == null) {
			return false;
		}
		return loadSpec.getLoader()
				.getDefaultOptions(provider, loadSpec, null, false)
				.stream()
				.anyMatch(e -> e.getName()
						.equals(AbstractLibrarySupportLoader.LOAD_ONLY_LIBRARIES_OPTION_NAME));
	}

	@Override
	public void importFiles(DomainFolder destFolder, List<File> files) {

		if (destFolder == null) {
			destFolder = tool.getProject().getProjectData().getRootFolder();
		}

		files = handleSimpleDBUnpack(destFolder, files);
		if (files.isEmpty()) {
			return;
		}

		List<FSRL> fsrls = files.stream().map(f -> fsService().getLocalFSRL(f)).toList();
		BatchImportDialog.showAndImport(tool, null, fsrls, destFolder,
			getTool().getService(ProgramManager.class));
	}

	@Override
	public void importFile(DomainFolder folder, File file) {

		if (folder == null) {
			folder = tool.getProject().getProjectData().getRootFolder();
		}

		if (handleSimpleDBUnpack(folder, file)) {
			return;
		}

		FSRL fsrl = fsService().getLocalFSRL(file);
		ProgramManager manager = tool.getService(ProgramManager.class);
		ImporterUtilities.showImportDialog(tool, manager, fsrl, folder, null);
	}

	private static String makeValidUniqueFilename(String name, DomainFolder folder) {

		// Trim-off file extension if ours *.g?? (e.g., gzf, gdt, etc.)
		int extIndex = name.lastIndexOf(".g");
		if (extIndex > 1 && (name.length() - extIndex) == 4) {
			name = name.substring(0, extIndex);
		}

		CharBuffer buf = CharBuffer.wrap(name.toCharArray());
		for (int i = 0; i < buf.length(); i++) {
			if (!LocalFileSystem.isValidNameCharacter(buf.get(i))) {
				buf.put(i, '_');
			}
		}

		String baseName = buf.toString();
		name = baseName;
		int count = 0;
		while (folder.getFile(name) != null) {
			++count;
			name = baseName + "." + count;
		}
		return name;
	}

	private List<File> handleSimpleDBUnpack(DomainFolder folder, List<File> files) {
		if (frontEndService == null || !isSimpleUnpackEnabled()) {
			return files;
		}

		ArrayList<File> remainingFiles = new ArrayList<>();

		Task task = new Task("", true, true, true) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {

				for (File f : files) {
					monitor.checkCancelled();

					// Test for Packed DB file using ItemDeserializer
					ItemDeserializer itemDeserializer = null;
					try {
						itemDeserializer = new ItemDeserializer(f); // fails for non-packed file
					}
					catch (IOException e) {
						remainingFiles.add(f);
						continue; // not a Packed DB - skip file
					}
					finally {
						if (itemDeserializer != null) {
							itemDeserializer.dispose();
						}
					}

					monitor.setMessage("Unpacking " + f.getName() + " ...");

					// Perform direct unpack of Packed DB file
					String filename = makeValidUniqueFilename(f.getName(), folder);
					try {
						DomainFile df = folder.createFile(filename, f, monitor);
						Msg.info(this, "Imported " + f.getName() + " to " + df.getPathname());
					}
					catch (InvalidNameException e) {
						throw new AssertException(e); // unexpected - valid name was used
					}
					catch (IOException e) {
						Msg.showError(JavaFileListHandler.class, tool.getToolFrame(),
							"Packed DB Import Failed", "Failed to import " + f.getName(), e);
					}
				}

			}
		};

		TaskLauncher.launchModal("Import", task);
		if (task.isCancelled()) {
			return List.of(); // return empty list if cancelled
		}

		return remainingFiles; // return files not yet imported
	}

	private boolean handleSimpleDBUnpack(DomainFolder folder, File file) {
		List<File> files = handleSimpleDBUnpack(folder, List.of(file));
		return files.isEmpty();
	}

	private boolean isSimpleUnpackEnabled() {
		if (frontEndService == null) {
			return false;
		}
		ToolOptions options = tool.getOptions(ToolConstants.FILE_IMPORT_OPTIONS);
		return options.getBoolean(SIMPLE_UNPACK_OPTION, SIMPLE_UNPACK_OPTION_DEFAULT);
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
					ListingActionContext lac = (ListingActionContext) context;
					doImportSelectionAction(lac.getProgram(), lac.getSelection());
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

	private void setupLoadLibrariesAction() {
		String title = "Load Libraries";

		loadLibrariesAction = new DockingAction(title, this.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				doLoadLibraries();
			}
		};
		loadLibrariesAction.setMenuBarData(new MenuData(new String[] { "&File", title + "..." },
			null, IMPORT_MENU_GROUP, MenuData.NO_MNEMONIC, "zzz"));
		loadLibrariesAction.setDescription(IMPORTER_PLUGIN_DESC);
		loadLibrariesAction.setEnabled(false);

		// Load libraries makes no sense in the front end tool, but we create it so that the
		// loadLibrariesAction won't be null and we would have to check that in other places.
		if (!(tool instanceof FrontEndTool)) {
			tool.addAction(loadLibrariesAction);
		}
	}

	private static DomainFolder getFolderFromContext(ActionContext context) {
		Object contextObj = context.getContextObject();
		if (contextObj instanceof DomainFolderNode) {
			DomainFolderNode node = (DomainFolderNode) contextObj;
			return node.getDomainFolder();
		}
		if (contextObj instanceof DomainFileNode) {
			DomainFileNode node = (DomainFileNode) contextObj;
			DomainFile domainFile = node.getDomainFile();
			return domainFile != null ? domainFile.getParent() : null;
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

		String lastFile = Preferences.getProperty(Preferences.LAST_IMPORT_FILE);
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

		FSRL fsrl = fsService().getLocalFSRL(file);
		TaskLauncher.launchModal("Show Add To Program Dialog", monitor -> {
			ImporterUtilities.showAddToProgramDialog(fsrl, program, tool, monitor);
		});

	}

	private void doLoadLibraries() {
		ProgramManager manager = tool.getService(ProgramManager.class);
		Program program = manager.getCurrentProgram();

		TaskLauncher.launchModal("Show Load Libraries Dialog", monitor -> {
			ImporterUtilities.showLoadLibrariesDialog(program, tool, manager, monitor);
		});
	}

	protected void doImportSelectionAction(Program program, ProgramSelection selection) {
		if (selection == null || selection.getNumAddressRanges() != 1) {
			return;
		}

		AddressRange range = selection.getFirstRange();// should only be 1
		if (range.getLength() >= Integer.MAX_VALUE) {
			Msg.showInfo(getClass(), tool.getActiveWindow(), "Selection Too Large",
				"The selection is too large to extract.");
			return;
		}

		try {
			Memory memory = program.getMemory();

			// create a tmp ByteProvider that contains the bytes from the selected region
			FileCacheEntry tmpFile;
			try (FileCacheEntryBuilder tmpFileBuilder =
				fsService().createTempFile(range.getLength())) {
				byte[] bytes = new byte[(int) range.getLength()];
				memory.getBytes(range.getMinAddress(), bytes);
				tmpFileBuilder.write(bytes);
				tmpFile = tmpFileBuilder.finish();
			}

			MemoryBlock block = memory.getBlock(range.getMinAddress());
			String rangeName =
				block.getName() + "[" + range.getMinAddress() + "," + range.getMaxAddress() + "]";
			ByteProvider bp =
				fsService().getNamedTempFile(tmpFile, program.getName() + " " + rangeName);
			LoaderMap loaderMap = LoaderService.getAllSupportedLoadSpecs(bp);

			ImporterDialog importerDialog = new ImporterDialog(tool,
				tool.getService(ProgramManager.class), loaderMap, bp, null);
			tool.showDialog(importerDialog);
		}
		catch (IOException e) {
			Msg.showError(this, null, "I/O Error Occurred", e.getMessage(), e);
		}
		catch (MemoryAccessException e) {
			Msg.showError(this, null, "Memory Access Error Occurred", e.getMessage(), e);
		}
	}

	private FileSystemService fsService() {
		// use a delayed initialization so we don't force the FileSystemService to initialize
		if (fsService == null) {
			fsService = FileSystemService.getInstance();
		}
		return fsService;
	}
}
