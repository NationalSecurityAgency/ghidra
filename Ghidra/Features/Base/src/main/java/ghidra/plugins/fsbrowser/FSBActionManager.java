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
import java.io.*;
import java.util.*;

import javax.swing.*;
import javax.swing.tree.TreePath;

import org.apache.commons.io.FilenameUtils;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.MultiLineMessageDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GIconLabel;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.TextEditorService;
import ghidra.app.util.opinion.LoaderService;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.plugin.importer.ImporterUtilities;
import ghidra.plugin.importer.ProgramMappingService;
import ghidra.plugins.fsbrowser.tasks.GFileSystemExtractAllTask;
import ghidra.plugins.importer.batch.BatchImportDialog;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Handles the menu actions for the {@link FileSystemBrowserComponentProvider}.
 *
 * Visible to just this package.
 */
class FSBActionManager {
	private static final int MAX_PROJECT_SIZE_TO_SEARCH_WITHOUT_WARNING_USER = 1000;
	private static final int MAX_TEXT_FILE_LEN = 64 * 1024;

	/* package visibility menu actions */
	DockingAction actionShowSupportedFileSystemsAndLoaders;
	DockingAction actionImport;
	DockingAction actionOpenPrograms;
	DockingAction actionOpenFileSystemChooser;
	DockingAction actionOpenFileSystemNewWindow;
	DockingAction actionOpenFileSystemNested;
	DockingAction actionGetInfo;
	DockingAction actionListMountedFileSystems;
	DockingAction actionViewAsText;
	DockingAction actionViewAsImage;
	DockingAction actionExportAll;
	DockingAction actionExport;
	DockingAction actionExpand;
	DockingAction actionCollapse;
	DockingAction actionImportBatch;
	DockingAction actionCloseFileSystem;
	/* end package visibility */

	protected FileSystemBrowserPlugin plugin;
	protected FileSystemBrowserComponentProvider provider;

	private TextEditorService textEditorService;

	private GTree gTree;

	private GhidraFileChooser chooserExport;
	private GhidraFileChooser chooserExportAll;

	private List<DockingAction> actions = new ArrayList<>();

	FSBActionManager(FileSystemBrowserPlugin plugin, FileSystemBrowserComponentProvider provider,
			TextEditorService textEditorService, GTree gTree) {

		this.plugin = plugin;
		this.provider = provider;

		this.textEditorService = textEditorService;
		this.gTree = gTree;

		chooserExport = new GhidraFileChooser(provider.getComponent());
		chooserExportAll = new GhidraFileChooser(provider.getComponent());

		createActions();
	}

	private void createActions() {
		actions.add((actionCloseFileSystem = createCloseAction()));
		actions.add((actionOpenPrograms = createOpenAllProgramsAction()));
		actions.add((actionImport = createImportAction()));
		actions.add((actionImportBatch = createBatchImportAction()));
		actions.add((actionOpenFileSystemNewWindow = createOpenFileSystemActionNewWindow()));
		actions.add((actionOpenFileSystemNested = createOpenNestedFileSystemAction()));
		actions.add((actionOpenFileSystemChooser = createOpenNewFileSystemAction()));
		actions.add((actionExpand = createExpandAllAction()));
		actions.add((actionCollapse = createCollapseAllAction()));
		actions.add((actionViewAsImage = createViewAsImageAction()));
		actions.add((actionViewAsText = createViewAsTextAction()));
		actions.add((actionExport = createExportAction()));
		actions.add((actionExportAll = createExportAllAction()));
		actions.add((actionGetInfo = createGetInfoAction()));
		actions.add(
			(actionShowSupportedFileSystemsAndLoaders = createSupportedFileSystemsAction()));
		actions.add((actionListMountedFileSystems = createListMountedFilesystemsAction()));
	}

	private void removeActions() {
		for (DockingAction action : actions) {
			plugin.getTool().removeLocalAction(provider, action);
		}
	}

	public void registerComponentActionsInTool() {
		for (DockingAction action : actions) {
			plugin.getTool().addLocalAction(provider, action);
		}
	}

	public void dispose() {
		removeActions();
	}

	private List<FSRL> getLoadableFSRLsFromContext(ActionContext context) {
		Object contextObject = context.getContextObject();
		if (contextObject instanceof FSBNode) {
			contextObject = new FSBNode[] { (FSBNode) contextObject };
		}
		if (!(contextObject instanceof FSBNode[])) {
			return Collections.emptyList();
		}

		List<FSRL> fsrls = new ArrayList<>();
		for (FSBNode node : (FSBNode[]) contextObject) {
			FSRL fsrl = node.getFSRL();

			FSRL validated = vaildateFsrl(fsrl, node);
			if (validated != null) {
				fsrls.add(validated);
				continue;
			}
			else if (node instanceof FSBRootNode && fsrl.getFS().hasContainer()) {
				// 'convert' a file system root node back into its container file
				fsrls.add(fsrl.getFS().getContainer());
			}
			else if (node instanceof FSBFileNode) {
				fsrls.add(fsrl);
			}
		}
		return fsrls;
	}

	private FSRL vaildateFsrl(FSRL fsrl, FSBNode node) {
		if ((node instanceof FSBDirNode) || (node instanceof FSBRootNode)) {
			FSBRootNode rootNode = FSBUtils.getNodesRoot(node);
			GFileSystem fs = rootNode.getFSRef().getFilesystem();
			if (fs instanceof GFileSystemProgramProvider) {
				GFile gfile;
				try {
					gfile = fs.lookup(node.getFSRL().getPath());
					if (gfile != null &&
						((GFileSystemProgramProvider) fs).canProvideProgram(gfile)) {
						return fsrl;
					}
				}
				catch (IOException e) {
					// ignore error and return null
				}
			}
		}

		return null;
	}

	private FSRL getLoadableFSRLFromContext(ActionContext context) {
		if (context == null || !(context.getContextObject() instanceof FSBNode)) {
			return null;
		}

		FSBNode node = (FSBNode) context.getContextObject();
		FSRL fsrl = node.getFSRL();
		if ((node instanceof FSBDirNode) || (node instanceof FSBRootNode)) {
			FSBRootNode rootNode = FSBUtils.getNodesRoot(node);
			GFileSystem fs = rootNode.getFSRef().getFilesystem();
			if (fs instanceof GFileSystemProgramProvider) {
				GFile gfile;
				try {
					gfile = fs.lookup(node.getFSRL().getPath());
					if (gfile != null &&
						((GFileSystemProgramProvider) fs).canProvideProgram(gfile)) {
						return fsrl;
					}
				}
				catch (IOException e) {
					// ignore error and fall thru to normal file handling
				}
			}
		}
		if (node instanceof FSBRootNode && fsrl.getFS().hasContainer()) {
			// 'convert' a file system root node back into its container file
			return fsrl.getFS().getContainer();
		}
		return (node instanceof FSBFileNode) ? fsrl : null;
	}

	/*
	 * Transforms the GTree path specified by the context parameter into a
	 * folder-like path, suitable for use in a filepath.
	 */
	private String getFormattedTreePath(ActionContext context) {
		if (context != null && context.getContextObject() instanceof FSBNode) {
			TreePath treePath = ((FSBNode) context.getContextObject()).getTreePath();
			StringBuilder path = new StringBuilder();
			for (Object pathElement : treePath.getPath()) {
				if (pathElement instanceof FSBNode) {
					FSBNode node = (FSBNode) pathElement;
					FSRL fsrl = node.getFSRL();
					if (path.length() != 0) {
						path.append("/");
					}
					String s;
					if (fsrl instanceof FSRLRoot) {
						s = fsrl.getFS().hasContainer() ? fsrl.getFS().getContainer().getName()
								: "/";
					}
					else {
						s = fsrl.getName();
					}
					path.append(s);
				}
			}

			return path.toString();
		}

		return null;
	}

	private boolean isSelectedContextAllDirs(ActionContext context) {
		Object contextObject = context.getContextObject();
		if (contextObject instanceof FSBNode[]) {
			for (FSBNode node : (FSBNode[]) context.getContextObject()) {
				boolean isDir = (node instanceof FSBDirNode) || (node instanceof FSBRootNode);
				if (!isDir) {
					return false;
				}
			}
			return true;
		}
		return (contextObject instanceof FSBDirNode) || (contextObject instanceof FSBRootNode);
	}

	private List<FSRL> getFSRLsFromNodes(FSBNode[] nodes, boolean dirsOk) {
		List<FSRL> fsrls = new ArrayList<>();
		for (FSBNode node : nodes) {
			FSRL fsrl = node.getFSRL();
			if (!dirsOk && node instanceof FSBRootNode && fsrl.getFS().hasContainer()) {
				// 'convert' a file system root node back into its container file node
				fsrl = fsrl.getFS().getContainer();
			}
			else {
				boolean isDir = (node instanceof FSBDirNode) || (node instanceof FSBRootNode);
				if (isDir && !dirsOk) {
					continue;
				}
			}
			fsrls.add(fsrl);
		}
		return fsrls;
	}

	private List<FSRL> getFSRLsFromContext(ActionContext context, boolean dirsOk) {
		Object contextObject = context.getContextObject();
		if (contextObject instanceof FSBNode) {
			contextObject = new FSBNode[] { (FSBNode) contextObject };
		}
		if (contextObject instanceof FSBNode[]) {
			return getFSRLsFromNodes((FSBNode[]) contextObject, dirsOk);
		}
		return Collections.emptyList();
	}

	private List<FSRL> getFileFSRLsFromContext(ActionContext context) {
		return getFSRLsFromContext(context, false);
	}

	private void openProgramFromFile(FSRL file, String suggestedDestinationPath) {
		ProgramManager pm = FSBUtils.getProgramManager(plugin.getTool(), false);
		if (pm == null) {
			return;
		}

		TaskLauncher.launchModal("Open Programs", monitor -> {
			boolean success = doOpenProgramFromFile(file, suggestedDestinationPath, pm, monitor);
			if (!success) {
				ImporterUtilities.showImportDialog(plugin.getTool(), pm, file, null,
					suggestedDestinationPath, monitor);
			}
		});
	}

	private boolean doOpenProgramFromFile(FSRL fsrl, String suggestedDestinationPath,
			ProgramManager programManager, TaskMonitor monitor) {

		Object consumer = new Object();
		Program program = ProgramMappingService.findMatchingProgramOpenIfNeeded(fsrl, consumer,
			programManager, ProgramManager.OPEN_CURRENT);

		if (program == null) {
			return searchProjectForMatchingFileOrFail(fsrl, suggestedDestinationPath,
				programManager, monitor);
		}

		program.release(consumer);
		return true;
	}

	private boolean searchProjectForMatchingFileOrFail(FSRL fsrl, String suggestedDestinationPath,
			ProgramManager programManager, TaskMonitor monitor) {
		boolean doSearch = isProjectSmallEnoughToSearchWithoutWarningUser() ||
			OptionDialog.showYesNoDialog(null, "Search Project for matching program?",
				"Search entire Project for matching program? (WARNING, could take large amount of time)") == OptionDialog.YES_OPTION;

		Map<FSRL, DomainFile> matchedFSRLs = doSearch
				? ProgramMappingService.searchProjectForMatchingFiles(Arrays.asList(fsrl), monitor)
				: Collections.emptyMap();

		DomainFile domainFile = matchedFSRLs.get(fsrl);
		if (domainFile != null) {
			ProgramMappingService.createAssociation(fsrl, domainFile);
			showProgramInProgramManager(fsrl, domainFile, programManager, true);
			return true;
		}
		return false;
	}

	/**
	 * Helper function to let {@link FileSystemBrowserComponentProvider fsb components}
	 * open selected files in a code browser that this plugin is tracking.
	 * <p>
	 * If there is no {@link ProgramManager} associated with the current tool, one will
	 * be searched for and the user may be prompted for confirmation, or warned if
	 * no PM found.
	 *
	 * @param files List of {@link FSRL} files to open in the active {@link ProgramManager}.
	 */
	private void openProgramsFromFiles(List<FSRL> files) {
		ProgramManager pm = FSBUtils.getProgramManager(plugin.getTool(), false);
		if (pm == null) {
			return;
		}

		TaskLauncher.launchModal("Open Programs", monitor -> {
			List<FSRL> unmatchedFiles = doOpenProgramsFromFiles(files, pm, monitor);

			if (unmatchedFiles.size() == 1) {
				ImporterUtilities.showImportDialog(plugin.getTool(), pm, unmatchedFiles.get(0),
					null, null, monitor);
			}
			else if (unmatchedFiles.size() > 1) {
				BatchImportDialog.showAndImport(plugin.getTool(), null, unmatchedFiles, null, pm);
			}
		});

	}

	/**
	 * Opens the Ghidra {@link Program}s that were previously imported from the specified
	 * {@link FSRL files}.
	 * <p>
	 * Relies on {@link ProgramMappingService#findMatchingProgramOpenIfNeeded(FSRL, Object, ProgramManager, int)}
	 * and if that fails, will search the entire project for the file if the user so chooses.
	 *
	 * @param fsrls {@link List} of {@link FSRL}s of the files to search for.
	 * @param programManager {@link ProgramManager} to use to open the programs, null ok.
	 * @param monitor {@link TaskMonitor} to watch for cancel and update with progress.
	 * @return list of unmatched files that need to be imported
	 */
	private List<FSRL> doOpenProgramsFromFiles(List<FSRL> fsrls, ProgramManager programManager,
			TaskMonitor monitor) {

		int programsOpened = 0;
		List<FSRL> unmatchedFiles = new ArrayList<>();
		Object consumer = new Object();
		for (FSRL fsrl : fsrls) {
			Program program = ProgramMappingService.findMatchingProgramOpenIfNeeded(fsrl, consumer,
				programManager,
				(programsOpened == 0) ? ProgramManager.OPEN_CURRENT : ProgramManager.OPEN_VISIBLE);

			if (program == null) {
				unmatchedFiles.add(fsrl);
				continue;
			}

			program.release(consumer);
			programsOpened++;
		}

		// UnmatchedFiles contains any files that had no association to a Program
		// Give the user a chance to search the project for it, and import it if not found
		if (!unmatchedFiles.isEmpty()) {
			unmatchedFiles = searchProjectForMatchingFilesOrFail(unmatchedFiles, programManager,
				monitor, programsOpened);
		}

		return unmatchedFiles;
	}

	private List<FSRL> searchProjectForMatchingFilesOrFail(List<FSRL> fsrlList,
			ProgramManager programManager, TaskMonitor monitor, int programsOpened) {
		boolean doSearch = isProjectSmallEnoughToSearchWithoutWarningUser() ||
			OptionDialog.showYesNoDialog(null, "Search Project for matching programs?",
				"Search entire Project for matching programs? " +
					"(WARNING, could take large amount of time)") == OptionDialog.YES_OPTION;

		Map<FSRL, DomainFile> matchedFSRLs =
			doSearch ? ProgramMappingService.searchProjectForMatchingFiles(fsrlList, monitor)
					: Collections.emptyMap();

		List<FSRL> unmatchedFSRLs = new ArrayList<>();
		for (FSRL fsrl : fsrlList) {
			DomainFile domainFile = matchedFSRLs.get(fsrl);
			if (domainFile != null) {
				ProgramMappingService.createAssociation(fsrl, domainFile);
			}
			if (showProgramInProgramManager(fsrl, domainFile, programManager,
				programsOpened == 0)) {
				programsOpened++;
			}
			else {
				unmatchedFSRLs.add(fsrl);
			}
		}

		return unmatchedFSRLs;
	}

	private boolean isProjectSmallEnoughToSearchWithoutWarningUser() {
		int fc = AppInfo.getActiveProject().getProjectData().getFileCount();
		return fc >= 0 && fc < MAX_PROJECT_SIZE_TO_SEARCH_WITHOUT_WARNING_USER;
	}

	private boolean showProgramInProgramManager(FSRL fsrl, DomainFile domainFile,
			ProgramManager programManager, boolean show) {
		Program program = null;
		Object consumer = new Object();
		try {
			program = ProgramMappingService.findMatchingProgramOpenIfNeeded(fsrl, domainFile,
				consumer, programManager,
				show ? ProgramManager.OPEN_CURRENT : ProgramManager.OPEN_VISIBLE);
			return (program != null);
		}
		finally {
			if (program != null) {
				program.release(consumer);
			}
		}

	}

	/**
	 * Shows a dialog with information about the specified file.
	 *
	 * @param fsrl {@link FSRL} of the file to display info about.
	 * @param monitor {@link TaskMonitor} to monitor and update when accessing the filesystems.
	 */
	private void showInfoForFile(FSRL fsrl, TaskMonitor monitor) {
		String title;
		String info;

		if (fsrl != null) {
			info = "";
			title = "Info about " + fsrl.getName();
			if (fsrl instanceof FSRLRoot && ((FSRLRoot) fsrl).hasContainer()) {
				FSRL containerFSRL = ((FSRLRoot) fsrl).getContainer();
				title = containerFSRL.getName();
				info = getInfoStringFor(containerFSRL, monitor);
				info += "------------------------------------\n";
			}
			info += getInfoStringFor(fsrl, monitor);
		}
		else {
			title = "Missing File";
			info = "Unable to retrieve information";
		}

		MultiLineMessageDialog.showMessageDialog(plugin.getTool().getActiveWindow(), title, null,
			info, MultiLineMessageDialog.INFORMATION_MESSAGE);

	}

	private String getInfoStringFor(FSRL fsrl, TaskMonitor monitor) {
		try (RefdFile refdFile = FileSystemService.getInstance().getRefdFile(fsrl, monitor)) {
			GFileSystem fs = refdFile.fsRef.getFilesystem();
			String result = "File system: " + fs.getDescription() + "\n";
			result += "FSRL: " + fsrl + "\n";
			DomainFile associatedDomainFile = ProgramMappingService.getCachedDomainFileFor(fsrl);
			if (associatedDomainFile != null) {
				result += "Project file: " + associatedDomainFile.getPathname() + "\n";
			}
			String nodeInfo = fs.getInfo(refdFile.file, monitor);
			if (nodeInfo != null) {
				result += nodeInfo;
			}
			return result;
		}
		catch (IOException | CancelledException e) {
			return "Error retrieving information: " + e.getMessage() + "\n";
		}
	}

	/**
	 * Shows a list of supported file system types and loaders.
	 */
	private void showSupportedFileSystems() {
		StringBuilder sb = new StringBuilder();

		sb.append(
			"<html><table><tr><td>Supported File Systems</td><td>Supported Loaders</td></tr>\n");
		sb.append("<tr valign='top'><td><ul>");
		for (String fileSystemName : FileSystemService.getInstance().getAllFilesystemNames()) {
			sb.append("<li>" + fileSystemName + "\n");
		}

		sb.append("</ul></td><td><ul>");
		for (String loaderName : LoaderService.getAllLoaderNames()) {
			sb.append("<li>" + loaderName + "\n");
		}
		sb.append("</ul></td></tr></table>");

		MultiLineMessageDialog.showModalMessageDialog(plugin.getTool().getActiveWindow(),
			"Supported File Systems and Loaders", "", sb.toString(),
			MultiLineMessageDialog.INFORMATION_MESSAGE);
	}

	//----------------------------------------------------------------------------------
	// DockingActions
	//----------------------------------------------------------------------------------
	private DockingAction createSupportedFileSystemsAction() {

		FSBAction action = new FSBAction("Display Supported File Systems and Loaders", plugin) {
			@Override
			public void actionPerformed(ActionContext context) {
				showSupportedFileSystems();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return true;
			}
		};
		action.setToolBarData(new ToolBarData(ImageManager.INFO));
		action.setDescription(action.getMenuText());
		action.setEnabled(true);
		return action;
	}

	private DockingAction createExportAction() {

		FSBAction action = new FSBAction("Export", plugin) {
			@Override
			public void actionPerformed(ActionContext context) {
				FSRL fsrl = FSBUtils.getFileFSRLFromContext(context);
				if (fsrl != null) {
					File selectedFile =
						new File(chooserExport.getCurrentDirectory(), fsrl.getName());
					chooserExport.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
					chooserExport.setTitle("Select Where To Export File");
					chooserExport.setApproveButtonText(getMenuText());
					chooserExport.setSelectedFile(selectedFile);
					File outputFile = chooserExport.getSelectedFile();
					if (outputFile == null) {
						return;
					}
					if (outputFile.exists()) {
						int answer = OptionDialog.showYesNoDialog(provider.getComponent(),
							"Confirm Overwrite", outputFile.getAbsolutePath() + "\n" +
								"The file already exists." + "\n" + "Do you want to overwrite it?");
						if (answer == OptionDialog.NO_OPTION) {
							return;
						}
					}
					gTree.runTask(monitor -> doExtractFile(fsrl, outputFile, monitor));
				}
			}

			private void doExtractFile(FSRL fsrl, File outputFile, TaskMonitor monitor) {
				monitor.setMessage("Exporting...");
				try {
					File cacheFile = FileSystemService.getInstance().getFile(fsrl, monitor);
					long totalBytesCopied =
						FileUtilities.copyFile(cacheFile, outputFile, false, monitor);
					Msg.info(this, "Exported " + fsrl.getName() + " to " + outputFile + ", " +
						totalBytesCopied + " bytes copied.");
				}
				catch (IOException | CancelledException | UnsupportedOperationException e) {
					FSUtilities.displayException(this, plugin.getTool().getActiveWindow(),
						"Error Exporting File", e.getMessage(), e);
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				// allow files or the root node of nested filesystems
				FSRL fsrl = FSBUtils.getFileFSRLFromContext(context);
				return !gTree.isBusy() && (fsrl != null);
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		action.setPopupMenuData(new MenuData(new String[] { action.getMenuText() + "..." },
			ImageManager.EXTRACT, "F", MenuData.NO_MNEMONIC, "B"));
		action.setEnabled(true);
		return action;
	}

	private DockingAction createExportAllAction() {

		FSBAction action = new FSBAction("Export All", plugin) {
			@Override
			public void actionPerformed(ActionContext context) {
				FSRL fsrl = FSBUtils.getFSRLFromContext(context, true);
				if (fsrl == null) {
					return;
				}
				if (fsrl instanceof FSRLRoot) {
					fsrl = fsrl.appendPath("/");
				}

				chooserExportAll.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
				chooserExportAll.setTitle("Select Export Directory");
				chooserExportAll.setApproveButtonText(getMenuText());
				chooserExportAll.setSelectedFile(null);
				File outputFile = chooserExportAll.getSelectedFile();
				if (outputFile == null) {
					return;
				}

				if (!outputFile.isDirectory()) {
					Msg.showInfo(getClass(), provider.getComponent(), getMenuText(),
						"Selected file is not a directory.");
					return;
				}
				Component parentComp = plugin.getTool().getActiveWindow();
				TaskLauncher.launch(new GFileSystemExtractAllTask(fsrl, outputFile, parentComp));
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				FSRL fsrl = FSBUtils.getFSRLFromContext(context, true);
				return !gTree.isBusy() && (fsrl != null) && isSelectedContextAllDirs(context);
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		action.setPopupMenuData(new MenuData(new String[] { action.getMenuText() + "..." },
			ImageManager.EXTRACT, "F", MenuData.NO_MNEMONIC, "C"));
		action.setEnabled(false);
		return action;
	}

	private DockingAction createViewAsImageAction() {

		FSBAction action = new FSBAction("View As Image", plugin) {
			@Override
			public void actionPerformed(ActionContext context) {
				FSRL fsrl = FSBUtils.getFSRLFromContext(context, false);
				if (fsrl != null) {
					gTree.runTask(monitor -> doViewAsImage(fsrl, monitor));
				}
			}

			private void doViewAsImage(FSRL fsrl, TaskMonitor monitor) {
				Component parent = plugin.getTool().getActiveWindow();
				try (RefdFile refdFile =
					FileSystemService.getInstance().getRefdFile(fsrl, monitor)) {
					Icon icon = GIconProvider.getIconForFile(refdFile.file, monitor);
					if (icon == null) {
						Msg.showError(this, parent, "Unable To View Image",
							"Unable to view " + fsrl.getName() + " as an image.");
					}
					else {
						SystemUtilities.runSwingLater(() -> {
							JLabel label = new GIconLabel(icon);
							JOptionPane.showMessageDialog(null, label,
								"Image Viewer: " + fsrl.getName(), JOptionPane.INFORMATION_MESSAGE);
						});
					}
				}
				catch (IOException | CancelledException e) {
					FSUtilities.displayException(this, parent, "Error Viewing Image File",
						e.getMessage(), e);
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				FSRL fsrl = FSBUtils.getFSRLFromContext(context, false);
				return !gTree.isBusy() && (fsrl != null);
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		action.setPopupMenuData(
			new MenuData(new String[] { action.getMenuText() }, ImageManager.VIEW_AS_IMAGE, "G"));
		action.setEnabled(true);
		return action;
	}

	private DockingAction createViewAsTextAction() {

		FSBAction action = new FSBAction("View As Text", plugin) {
			@Override
			public void actionPerformed(ActionContext context) {
				FSRL fsrl = FSBUtils.getFSRLFromContext(context, false);
				if (fsrl != null) {
					gTree.runTask(monitor -> doViewAsText(fsrl, monitor));
				}
			}

			private void doViewAsText(FSRL fsrl, TaskMonitor monitor) {
				Component parent = plugin.getTool().getActiveWindow();
				try {
					File file = FileSystemService.getInstance().getFile(fsrl, monitor);
					if (file.length() == -1 || file.length() > MAX_TEXT_FILE_LEN) {
						Msg.showInfo(this, parent, "View As Text Failed",
							"File too large to view as text inside Ghidra. " +
								"Please use the \"EXPORT\" action.");
						return;
					}
					if (file.length() == 0) {
						Msg.showInfo(this, parent, "View As Text Failed",
							"File " + fsrl.getName() + " is empty (0 bytes).");
						return;
					}
					try {
						InputStream inputStream = new FileInputStream(file);
						// textEditorService closes the inputStream, and must be
						// called on the swing thread or you get concurrentmodification
						// exceptions.
						SystemUtilities.runSwingLater(
							() -> textEditorService.edit(fsrl.getName(), inputStream));
					}
					catch (IOException e) {
						Msg.showError(this, parent, "View As Text Failed",
							"Error when trying to view text file " + fsrl.getName(), e);
					}
				}
				catch (IOException | CancelledException e) {
					FSUtilities.displayException(this, parent, "Error viewing text file",
						e.getMessage(), e);
				}

			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				FSRL fsrl = FSBUtils.getFSRLFromContext(context, false);
				return !gTree.isBusy() && (fsrl != null);
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		action.setPopupMenuData(
			new MenuData(new String[] { action.getMenuText() }, ImageManager.VIEW_AS_TEXT, "G"));
		action.setEnabled(true);
		return action;
	}

	private DockingAction createListMountedFilesystemsAction() {

		FSBAction action = new FSBAction("List Mounted Filesystems", plugin) {
			@Override
			public void actionPerformed(ActionContext context) {
				FSRLRoot fsFSRL = SelectFromListDialog.selectFromList(
					FileSystemService.getInstance().getMountedFilesystems(), "Select filesystem",
					"Choose filesystem to view", f -> f.toPrettyString());

				FileSystemRef fsRef;
				if (fsFSRL != null && (fsRef =
					FileSystemService.getInstance().getMountedFilesystem(fsFSRL)) != null) {
					plugin.createNewFileSystemBrowser(fsRef, true);
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return !gTree.isBusy();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		action.setPopupMenuData(
			new MenuData(new String[] { action.getMenuText() }, ImageManager.LIST_MOUNTED, "L"));
		action.setToolBarData(new ToolBarData(ImageManager.LIST_MOUNTED, "ZZZZ"));
		action.setDescription(action.getMenuText());
		action.setEnabled(true);
		return action;
	}

	private DockingAction createExpandAllAction() {

		FSBAction action = new FSBAction("Expand All", plugin) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (context.getContextObject() instanceof GTreeNode) {
					GTreeNode node = (GTreeNode) context.getContextObject();
					gTree.expandTree(node);
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object co = context.getContextObject();
				return !gTree.isBusy() &&
					((co instanceof FSBRootNode) || (co instanceof FSBDirNode));
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		action.setPopupMenuData(new MenuData(new String[] { action.getMenuText() },
			ImageManager.EXPAND_ALL, "B", MenuData.NO_MNEMONIC, "A"));
		action.setEnabled(true);
		return action;
	}

	private DockingAction createCollapseAllAction() {

		FSBAction action = new FSBAction("Collapse All", plugin) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (context.getContextObject() instanceof GTreeNode) {
					GTreeNode node = (GTreeNode) context.getContextObject();
					gTree.collapseAll(node);
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object co = context.getContextObject();
				return !gTree.isBusy() &&
					((co instanceof FSBRootNode) || (co instanceof FSBDirNode));
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		action.setPopupMenuData(new MenuData(new String[] { action.getMenuText() },
			ImageManager.COLLAPSE_ALL, "B", MenuData.NO_MNEMONIC, "B"));
		action.setEnabled(true);
		return action;
	}

	private DockingAction createGetInfoAction() {

		FSBAction action = new FSBAction("Get Info", plugin) {
			@Override
			public void actionPerformed(ActionContext context) {
				FSRL fsrl = FSBUtils.getFSRLFromContext(context, true);
				gTree.runTask(monitor -> showInfoForFile(fsrl, monitor));
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				FSRL fsrl = FSBUtils.getFSRLFromContext(context, true);
				return !gTree.isBusy() && fsrl != null;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		action.setPopupMenuData(
			new MenuData(new String[] { action.getMenuText() }, ImageManager.INFO, "A"));
		action.setEnabled(true);
		return action;
	}

	private DockingAction createOpenFileSystemActionNewWindow() {
		FSBAction action = new FSBAction("Open File System In New Window",
			"Open File System in new window", plugin) {
			@Override
			public void actionPerformed(ActionContext context) {

				FSRL containerFSRL = FSBUtils.getFileFSRLFromContext(context);
				if (containerFSRL != null) {
					gTree.runTask(monitor -> {
						doOpenFileSystem(containerFSRL, monitor);
					});
				}
			}

			/*
			 * run on gTree task thread
			 */
			private void doOpenFileSystem(FSRL containerFSRL, TaskMonitor monitor) {
				try {
					monitor.setMessage("Probing " + containerFSRL.getName() + " for filesystems");
					FileSystemRef ref = FileSystemService.getInstance()
							.probeFileForFilesystem(
								containerFSRL, monitor, FileSystemProbeConflictResolver.GUI_PICKER);
					if (ref == null) {
						Msg.showWarn(this, plugin.getTool().getActiveWindow(), "Open Filesystem",
							"No filesystem provider for " + containerFSRL.getName());
						return;
					}

					SystemUtilities.runSwingLater(() -> {
						plugin.createNewFileSystemBrowser(ref, true);
					});
				}
				catch (IOException | CancelledException e) {
					FSUtilities.displayException(this, plugin.getTool().getActiveWindow(),
						"Open Filesystem",
						"Error opening filesystem for " + containerFSRL.getName(), e);
				}
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				FSRL containerFSRL = FSBUtils.getFSRLFromContext(context, false);
				return !gTree.isBusy() && (containerFSRL != null);
			}
		};
		action.setPopupMenuData(new MenuData(new String[] { action.getMenuText() },
			ImageManager.OPEN_FILE_SYSTEM, "C"));
		action.setEnabled(true);
		return action;
	}

	private DockingAction createOpenNewFileSystemAction() {
		FSBAction action = new FSBAction("Open File System Chooser", plugin) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.openFileSystem();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return false;
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return true;
			}
		};
		action.setPopupMenuData(new MenuData(new String[] { action.getMenuText() },
			ImageManager.OPEN_FILE_SYSTEM, "C"));
		action.setDescription(action.getMenuText());
		action.setToolBarData(new ToolBarData(ImageManager.OPEN_FILE_SYSTEM, "B"));
		action.setEnabled(true);
		return action;
	}

	private DockingAction createOpenAllProgramsAction() {

		FSBAction action = new FSBAction("Open Programs", "Open Program(s)", plugin) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (!plugin.hasProgramManager()) {
					Msg.showInfo(this, plugin.getTool().getActiveWindow(), "Open Program Error",
						"There is no tool currently open that can be used to show a program.");
					return;
				}
				List<FSRL> files = getLoadableFSRLsFromContext(context);
				if (files.size() == 1) {
					String treePath =
						FilenameUtils.getFullPathNoEndSeparator(getFormattedTreePath(context));
					openProgramFromFile(files.get(0), treePath);
				}
				else if (files.size() > 1) {
					openProgramsFromFiles(files);
				}
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return !gTree.isBusy() && !getLoadableFSRLsFromContext(context).isEmpty();
			}
		};
		action.setPopupMenuData(new MenuData(new String[] { action.getMenuText() },
			ImageManager.OPEN_ALL, "D", MenuData.NO_MNEMONIC, "B"));
		action.setEnabled(plugin.hasProgramManager());
		return action;
	}

	private DockingAction createCloseAction() {
		FSBAction action = new FSBAction("Close", plugin) {
			@Override
			public void actionPerformed(ActionContext context) {

				if (!(context.getContextObject() instanceof FSBRootNode)) {
					return;
				}
				FSBRootNode node = (FSBRootNode) context.getContextObject();
				if (node.equals(gTree.getModelRoot())) {
					// Close entire window
					FileSystemRef fsRef = node.getFSRef();
					if (fsRef != null && !fsRef.isClosed() &&
						OptionDialog.showYesNoDialog(provider.getComponent(), "Close File System",
							"Do you want to close the filesystem browser for " +
								fsRef.getFilesystem().getName() + "?") == OptionDialog.YES_OPTION) {
						plugin.removeFileSystemBrowser(fsRef.getFilesystem().getFSRL());
						this.setEnabled(false);
					}
				}
				else {
					// Close file system that is nested in the container's tree.
					gTree.runTask(monitor -> {
						int indexInParent = node.getIndexInParent();
						GTreeNode parent = node.getParent();
						parent.removeNode(node);
						GTreeNode prevNode = node.getPrevNode();
						parent.addNode(indexInParent, prevNode);
						node.dispose();
					});
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return !gTree.isBusy() && (context.getContextObject() instanceof FSBRootNode);
			}
		};
		action.setPopupMenuData(
			new MenuData(new String[] { action.getMenuText() }, ImageManager.CLOSE, "ZZZZ"));
		action.setDescription(action.getMenuText());
		action.setToolBarData(new ToolBarData(ImageManager.CLOSE, "ZZZZ"));
		action.setEnabled(false);
		return action;
	}

	private DockingAction createImportAction() {
		FSBAction action = new FSBAction("Import Single", "Import", plugin) {

			@Override
			public void actionPerformed(ActionContext context) {
				FSRL fsrl = getLoadableFSRLFromContext(context);
				if (fsrl == null) {
					return;
				}

				String treePath = getFormattedTreePath(context);
				String suggestedPath =
					FilenameUtils.getFullPathNoEndSeparator(treePath).replaceAll(":/", "/");

				PluginTool tool = plugin.getTool();
				ProgramManager pm = FSBUtils.getProgramManager(tool, false);
				ImporterUtilities.showImportDialog(tool, pm, fsrl, null, suggestedPath);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return !gTree.isBusy() && getLoadableFSRLFromContext(context) != null;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		action.setPopupMenuData(new MenuData(new String[] { action.getMenuText() },
			ImageManager.IMPORT, "F", MenuData.NO_MNEMONIC, "A"));
		action.setEnabled(true);

		return action;
	}

	private DockingAction createBatchImportAction() {
		FSBAction action = new FSBAction("Import Batch", "Batch Import", plugin) {

			@Override
			public void actionPerformed(ActionContext context) {
				// Do some fancy selection logic.
				// If the user selected a combination of files and folders,
				// ignore the folders.
				// If they only selected folders, leave them in the list.
				List<FSRL> files = getFSRLsFromContext(context, true);
				if (files.isEmpty()) {
					return;
				}

				boolean allDirs = isSelectedContextAllDirs(context);
				if (files.size() > 1 && !allDirs) {
					files = getFileFSRLsFromContext(context);
				}

				BatchImportDialog.showAndImport(plugin.getTool(), null, files, null,
					FSBUtils.getProgramManager(plugin.getTool(), false));
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return !gTree.isBusy() && !getFSRLsFromContext(context, true).isEmpty();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		action.setPopupMenuData(new MenuData(new String[] { action.getMenuText() },
			ImageManager.IMPORT, "F", MenuData.NO_MNEMONIC, "B"));
		action.setEnabled(true);

		return action;
	}

	private DockingAction createOpenNestedFileSystemAction() {
		FSBAction action = new FSBAction("Open File System Nested", "Open File System", plugin) {
			@Override
			public void actionPerformed(ActionContext context) {
				FSRL containerFSRL = FSBUtils.getFileFSRLFromContext(context);
				if (containerFSRL != null && context.getContextObject() instanceof FSBFileNode) {
					FSBFileNode xfileNode = (FSBFileNode) context.getContextObject();
					FSBFileNode modelFileNode =
						(FSBFileNode) gTree.getModelNodeForPath(xfileNode.getTreePath());

					gTree.runTask(monitor -> {
						try {
							FileSystemRef fsRef =
								FileSystemService.getInstance()
										.probeFileForFilesystem(
											containerFSRL, monitor,
											FileSystemProbeConflictResolver.GUI_PICKER);
							if (fsRef == null) {
								Msg.showWarn(this, gTree, "No File System Provider",
									"No file system provider for " + containerFSRL.getName());
								return;
							}

							FSBRootNode nestedRootNode = new FSBRootNode(fsRef, modelFileNode);
							nestedRootNode.setChildren(nestedRootNode.generateChildren(monitor));

							int indexInParent = modelFileNode.getIndexInParent();
							GTreeNode parent = modelFileNode.getParent();
							parent.removeNode(modelFileNode);
							parent.addNode(indexInParent, nestedRootNode);
							gTree.expandPath(nestedRootNode);
						}
						catch (CancelledException | IOException e) {
							FSUtilities.displayException(this, gTree, "Error Opening FileSystem",
								e.getMessage(), e);
						}
					});
				}
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				FSRL containerFSRL = FSBUtils.getFileFSRLFromContext(context);
				return !gTree.isBusy() && (containerFSRL != null) &&
					(context.getContextObject() instanceof FSBFileNode);
			}
		};
		action.setPopupMenuData(new MenuData(new String[] { action.getMenuText() },
			ImageManager.OPEN_FILE_SYSTEM, "C"));
		action.setEnabled(true);
		return action;
	}
	//----------------------------------------------------------------------------------
	// end DockingActions
	//----------------------------------------------------------------------------------

}
