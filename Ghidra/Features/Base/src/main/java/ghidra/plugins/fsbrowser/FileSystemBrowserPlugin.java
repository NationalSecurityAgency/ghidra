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
package ghidra.plugins.fsbrowser;

import java.awt.Component;
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
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.*;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.main.FrontEndService;
import ghidra.framework.main.FrontEndable;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectListener;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.plugin.importer.ImporterUtilities;
import ghidra.plugin.importer.ProgramMappingService;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * A {@link Plugin} that supplies a {@link GFileSystem filesystem} browser component
 * that allows the user to view the contents of filesystems and perform actions on the
 * files inside those filesystems.x
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Browse Filesystems in containers",
	description = "This plugin allows users to browse and use the contents of containers (zips, tars, filesystems, etc)",
	servicesProvided = { FileSystemBrowserService.class },
	servicesRequired = { TextEditorService.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class FileSystemBrowserPlugin extends Plugin implements FrontEndable, ProjectListener,
		FileSystemEventListener, FileSystemBrowserService {

	private static final String MENU_GROUP = "Import";

	/* package */ DockingAction openFilesystemAction;
	private GhidraFileChooser chooserOpen;
	private FrontEndService frontEndService;
	private Map<FSRL, FileSystemBrowserComponentProvider> currentBrowsers = new HashMap<>();

	public FileSystemBrowserPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();

		frontEndService = tool.getService(FrontEndService.class);
		if (frontEndService != null) {
			frontEndService.addProjectListener(this);
		}
		else {
			FSBUtils.getProgramManager(tool, false);
		}

		setupOpenFileSystemAction();
	}

	@Override
	protected void dispose() {
		super.dispose();
		if (openFilesystemAction != null) {
			openFilesystemAction.dispose();
		}
		if (frontEndService != null) {
			frontEndService.removeProjectListener(this);
			frontEndService = null;
		}
		chooserOpen = null;

		for (FileSystemBrowserComponentProvider provider : currentBrowsers.values()) {
			provider.dispose();
		}
		currentBrowsers.clear();
	}

	@Override
	public void openFileSystem(FSRL fsrl) {
		TaskLauncher.launchModal("Open File System", (monitor) -> {
			doOpenFilesystem(fsrl, tool.getActiveWindow(), monitor);
		});
	}

	/**
	 * Creates a new browser UI component for an already open {@link GFileSystem} (pinned
	 * with the specified {@link FileSystemRef} that will be taken ownership of by this
	 * method).
	 *
	 * @param fsRef {@link FileSystemRef} of open {@link GFileSystem}
	 * @param show boolean true if the new browser component should be shown
	 */
	/* package */ void createNewFileSystemBrowser(FileSystemRef fsRef, boolean show) {
		Swing.runIfSwingOrRunLater(() -> doCreateNewFileSystemBrowser(fsRef, show));
	}

	private void doCreateNewFileSystemBrowser(FileSystemRef fsRef, boolean show) {
		FSRLRoot fsFSRL = fsRef.getFilesystem().getFSRL();
		FileSystemBrowserComponentProvider provider = currentBrowsers.get(fsFSRL);
		if (provider != null) {
			Msg.info(this, "Filesystem browser already open for " + fsFSRL);
			fsRef.close();
		}
		else {
			fsRef.getFilesystem().getRefManager().addListener(this);
			provider = new FileSystemBrowserComponentProvider(this, fsRef);
			currentBrowsers.put(fsFSRL, provider);
			getTool().addComponentProvider(provider, false);
			provider.afterAddedToTool();
		}

		if (show) {
			getTool().showComponentProvider(provider, true);
			getTool().toFront(provider);
		}
	}

	/**
	 * Closes any FilesystemBrowser window component that is showing the specified filesystem.
	 *
	 * @param fsFSRL {@link FSRLRoot} of the filesystem to close.
	 */
	/* package */ void removeFileSystemBrowser(FSRLRoot fsFSRL) {
		Swing.runIfSwingOrRunLater(() -> {
			FileSystemBrowserComponentProvider fsbcp = currentBrowsers.get(fsFSRL);
			if (fsbcp == null) {
				return;
			}

			currentBrowsers.remove(fsFSRL);
			fsbcp.removeFromTool();
			fsbcp.dispose();
		});
	}

	/**
	 * Close all file system browser windows.
	 */
	private void removeAllFileSystemBrowsers() {
		Swing.runIfSwingOrRunLater(() -> {
			for (FileSystemBrowserComponentProvider fsbcp : new ArrayList<>(
				currentBrowsers.values())) {
				fsbcp.removeFromTool();
				fsbcp.dispose();
			}
			currentBrowsers.clear();
		});
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);

		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent pape = (ProgramActivatedPluginEvent) event;
			ProgramMappingService.createAutoAssocation(pape.getActiveProgram());
		}
	}

	@Override
	public void projectClosed(Project project) {
		removeAllFileSystemBrowsers();
		if (FileSystemService.isInitialized()) {
			FileSystemService.getInstance().closeUnusedFileSystems();
		}
	}

	@Override
	public void projectOpened(Project project) {
		// nada
	}

	private void setupOpenFileSystemAction() {
		String actionName = "Open File System";

		openFilesystemAction = new DockingAction(actionName, this.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				doOpenFileSystem();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return tool.getProject() != null;
			}
		};
		openFilesystemAction.setMenuBarData(
			new MenuData(new String[] { "&File", actionName + "..." }, null, MENU_GROUP,
				MenuData.NO_MNEMONIC, "z"));
		openFilesystemAction.setKeyBindingData(
			new KeyBindingData(KeyEvent.VK_I, InputEvent.CTRL_DOWN_MASK));
		openFilesystemAction.setDescription(getPluginDescription().getDescription());
		openFilesystemAction.setEnabled(tool.getProject() != null);

		tool.addAction(openFilesystemAction);
	}

	private void openChooser(String title, String buttonText, boolean multiSelect) {
		if (chooserOpen == null) {
			chooserOpen = new GhidraFileChooser(tool.getActiveWindow());
			chooserOpen.addFileFilter(ImporterUtilities.LOADABLE_FILES_FILTER);
			chooserOpen.addFileFilter(ImporterUtilities.CONTAINER_FILES_FILTER);
			chooserOpen.setSelectedFileFilter(GhidraFileFilter.ALL);
		}
		chooserOpen.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooserOpen.setMultiSelectionEnabled(multiSelect);
		chooserOpen.setTitle(title);
		chooserOpen.setApproveButtonText(buttonText);
	}

	/**
	 * Worker function for doOpenFilesystem, meant to be called in a task thread.
	 *
	 * @param containerFSRL {@link FSRL} of the container to open
	 * @param parent parent {@link Component} for error dialogs, null ok
	 * @param monitor {@link TaskMonitor} to watch and update.
	 */
	private void doOpenFilesystem(FSRL containerFSRL, Component parent, TaskMonitor monitor) {
		try {
			monitor.setMessage("Probing " + containerFSRL.getName() + " for filesystems");
			FileSystemRef ref = FileSystemService.getInstance()
					.probeFileForFilesystem(
						containerFSRL, monitor, FileSystemProbeConflictResolver.GUI_PICKER);
			if (ref == null) {
				Msg.showWarn(this, parent, "Open Filesystem",
					"No filesystem provider for " + containerFSRL.getName());
				return;
			}

			Swing.runLater(() -> {
				createNewFileSystemBrowser(ref, true);
			});
		}
		catch (IOException | CancelledException e) {
			FSUtilities.displayException(this, parent, "Open Filesystem Error",
				"Error opening filesystem for " + containerFSRL.getName(), e);
		}
	}

	/**
	 * Prompts the user to pick a file system container file to open using a local
	 * filesystem browser and then displays that filesystem in a new fsb browser.
	 */
	/* package */ void openFileSystem() {
		Swing.runLater(this::doOpenFileSystem);
	}

	private void doOpenFileSystem() {
		Component parent = getTool().getActiveWindow();
		openChooser("Select Filesystem Container To Open", "Open", false);
		chooserOpen.setFileSelectionMode(GhidraFileChooserMode.FILES_AND_DIRECTORIES);
		File file = chooserOpen.getSelectedFile();
		if (file == null) {
			return; // cancelled
		}
		else if (!file.exists()) {
			Msg.showInfo(this, parent, "Open File System Failed",
				"The specified file does not exist: " + file.getPath());
			return;
		}

		if (FileUtilities.isEmpty(file)) {
			Msg.showInfo(this, parent, "Empty file",
				"The selected file is 0 bytes long, skipping.");
			return;
		}

		FSRL containerFSRL = FileSystemService.getInstance().getLocalFSRL(file);
		TaskLauncher.launchModal("Open File System", (monitor) -> {
			doOpenFilesystem(containerFSRL, parent, monitor);
		});
	}

	@Override
	public void onFilesystemClose(GFileSystem fs) {
		Msg.info(this, "File system " + fs.getFSRL() + " was closed! Closing browser window");
		removeFileSystemBrowser(fs.getFSRL());
	}

	@Override
	public void onFilesystemRefChange(GFileSystem fs, FileSystemRefManager refManager) {
		//Msg.info(this, "File system " + fs.getFSRL() + " ref changed");
		// nada
	}

	/**
	 * Returns true if there is a {@link ProgramManager} associated with this FSB.
	 *
	 * @return boolean true if there is a ProgramManager.
	 */
	/* package */ boolean hasProgramManager() {
		return tool.getService(ProgramManager.class) != null ||
			FSBUtils.getRunningProgramManagerTools(getTool()).size() == 1;
	}

	/**
	 * For testing access only.
	 *
	 * @param fsFSRL {@link FSRLRoot} of browser component to fetch.
	 * @return provider or null if not found.
	 */
	/* package */ FileSystemBrowserComponentProvider getProviderFor(FSRLRoot fsFSRL) {
		FileSystemBrowserComponentProvider provider = currentBrowsers.get(fsFSRL);
		if (provider == null) {
			Msg.info(this, "Could not find browser for " + fsFSRL);
			return null;
		}
		return provider;
	}
}
