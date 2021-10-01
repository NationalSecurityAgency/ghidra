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

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;
import static java.util.Map.*;

import java.awt.Component;
import java.io.*;
import java.util.*;
import java.util.function.Function;

import javax.swing.*;

import org.apache.commons.io.FilenameUtils;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.MultiLineMessageDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GIconLabel;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.TextEditorService;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoaderService;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.crypto.CachedPasswordProvider;
import ghidra.formats.gfilesystem.crypto.CryptoProviders;
import ghidra.formats.gfilesystem.fileinfo.*;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.plugin.importer.ImporterUtilities;
import ghidra.plugin.importer.ProgramMappingService;
import ghidra.plugins.fsbrowser.tasks.GFileSystemExtractAllTask;
import ghidra.plugins.importer.batch.BatchImportDialog;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

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
	DockingAction actionClearCachedPasswords;
	/* end package visibility */

	protected FileSystemBrowserPlugin plugin;
	protected FileSystemBrowserComponentProvider provider;

	private TextEditorService textEditorService;

	private GTree gTree;

	private GhidraFileChooser chooserExport;
	private GhidraFileChooser chooserExportAll;

	private List<DockingAction> actions = new ArrayList<>();
	private FileSystemService fsService = FileSystemService.getInstance();

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
		actions.add((actionOpenPrograms = createOpenProgramsAction()));
		actions.add((actionImport = createImportAction()));
		actions.add((actionImportBatch = createBatchImportAction()));
		actions.add((actionOpenFileSystemNewWindow = createOpenFileSystemNewWindowAction()));
		actions.add((actionOpenFileSystemNested = createOpenFileSystemNestedAction()));
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
		actions.add((actionClearCachedPasswords = createClearCachedPasswordsAction()));
		actions.add(createRefreshAction());
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

	private void openProgramFromFile(FSRL file, FSBNode node, String suggestedDestinationPath) {
		ProgramManager pm = FSBUtils.getProgramManager(plugin.getTool(), false);
		if (pm == null) {
			return;
		}

		gTree.runTask(monitor -> {
			boolean success = doOpenProgramFromFile(file, suggestedDestinationPath, pm, monitor);
			if (!success) {
				if (!ensureFileAccessable(file, node, monitor)) {
					return;
				}
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

		if (program != null) {
			program.release(consumer);
			return true;
		}

		return searchProjectForMatchingFileOrFail(fsrl, suggestedDestinationPath, programManager,
			monitor);
	}

	private boolean searchProjectForMatchingFileOrFail(FSRL fsrl, String suggestedDestinationPath,
			ProgramManager programManager, TaskMonitor monitor) {
		boolean doSearch = isProjectSmallEnoughToSearchWithoutWarningUser() ||
			OptionDialog.showYesNoDialog(null, "Search Project for matching program?",
				"Search entire Project for matching program? (WARNING, could take large amount of time)") == OptionDialog.YES_OPTION;

		Map<FSRL, DomainFile> matchedFSRLs = doSearch
				? ProgramMappingService.searchProjectForMatchingFiles(List.of(fsrl), monitor)
				: Map.of();

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

		gTree.runTask(monitor -> {
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

		Map<FSRL, DomainFile> matchedFSRLs = doSearch
				? ProgramMappingService.searchProjectForMatchingFiles(fsrlList, monitor)
				: Map.of();

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
	 * Shows a list of supported file system types and loaders.
	 */
	private void showSupportedFileSystems() {
		StringBuilder sb = new StringBuilder();

		sb.append(
			"<html><table><tr><td>Supported File Systems</td><td>Supported Loaders</td></tr>\n");
		sb.append("<tr valign='top'><td><ul>");
		for (String fileSystemName : fsService.getAllFilesystemNames()) {
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
		return new ActionBuilder("FSB Display Supported File Systems and Loaders", plugin.getName())
				.description("Display Supported File Systems and Loaders")
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> true)
				.toolBarIcon(ImageManager.INFO)
				.onAction(ac -> showSupportedFileSystems())
				.build();
	}

	private DockingAction createExportAction() {
		return new ActionBuilder("FSB Export", plugin.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getFileFSRL() != null)
				.popupMenuIcon(ImageManager.EXTRACT)
				.popupMenuPath("Export...")
				.popupMenuGroup("F", "B")
				.onAction(
					ac -> {
						FSRL fsrl = ac.getFileFSRL();
						if (fsrl == null) {
							return;
						}
						File selectedFile =
							new File(chooserExport.getCurrentDirectory(), fsrl.getName());
						chooserExport.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
						chooserExport.setTitle("Select Where To Export File");
						chooserExport.setApproveButtonText("Export");
						chooserExport.setSelectedFile(selectedFile);
						File outputFile = chooserExport.getSelectedFile();
						if (outputFile == null) {
							return;
						}
						if (outputFile.exists()) {
							int answer = OptionDialog.showYesNoDialog(provider.getComponent(),
								"Confirm Overwrite", outputFile.getAbsolutePath() + "\n" +
									"The file already exists.\n" +
									"Do you want to overwrite it?");
							if (answer == OptionDialog.NO_OPTION) {
								return;
							}
						}
						gTree.runTask(monitor -> doExtractFile(fsrl, outputFile,
							ac.getSelectedNode(), monitor));
					})
				.build();
	}

	private DockingAction createExportAllAction() {
		return new ActionBuilder("FSB Export All", plugin.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.isSelectedAllDirs())
				.popupMenuIcon(ImageManager.EXTRACT)
				.popupMenuPath("Export All...")
				.popupMenuGroup("F", "C")
				.onAction(
					ac -> {
						FSRL fsrl = ac.getFSRL(true);
						if (fsrl == null) {
							return;
						}
						if (fsrl instanceof FSRLRoot) {
							fsrl = fsrl.appendPath("/");
						}

						chooserExportAll
								.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
						chooserExportAll.setTitle("Select Export Directory");
						chooserExportAll.setApproveButtonText("Export All");
						chooserExportAll.setSelectedFile(null);
						File outputFile = chooserExportAll.getSelectedFile();
						if (outputFile == null) {
							return;
						}

						if (!outputFile.isDirectory()) {
							Msg.showInfo(this, provider.getComponent(), "Export All",
								"Selected file is not a directory.");
							return;
						}
						Component parentComp = plugin.getTool().getActiveWindow();
						TaskLauncher.launch(
							new GFileSystemExtractAllTask(fsrl, outputFile, parentComp));
					})
				.build();
	}

	private DockingAction createViewAsImageAction() {
		return new ActionBuilder("FSB View As Image", plugin.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getFileFSRL() != null)
				.popupMenuIcon(ImageManager.VIEW_AS_IMAGE)
				.popupMenuPath("View As Image")
				.popupMenuGroup("G")
				.onAction(
					ac -> {
						FSRL fsrl = ac.getFileFSRL();
						if (fsrl != null) {
							gTree.runTask(
								monitor -> doViewAsImage(fsrl, ac.getSelectedNode(), monitor));
						}
					})
				.build();
	}

	private DockingAction createViewAsTextAction() {
		return new ActionBuilder("FSB View As Text", plugin.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getFileFSRL() != null)
				.popupMenuIcon(ImageManager.VIEW_AS_TEXT)
				.popupMenuPath("View As Text")
				.popupMenuGroup("G")
				.onAction(
					ac -> {
						FSRL fsrl = ac.getFileFSRL();
						if (fsrl != null) {
							gTree.runTask(
								monitor -> doViewAsText(fsrl, ac.getSelectedNode(), monitor));
						}
					})
				.build();
	}

	private DockingAction createListMountedFilesystemsAction() {
		return new ActionBuilder("FSB List Mounted Filesystems", plugin.getName())
				.description("List Mounted Filesystems")
				.withContext(FSBActionContext.class)
				.enabledWhen(FSBActionContext::notBusy)
				.toolBarIcon(ImageManager.LIST_MOUNTED)
				.toolBarGroup("ZZZZ")
				.popupMenuIcon(ImageManager.LIST_MOUNTED)
				.popupMenuPath("List Mounted Filesystems")
				.popupMenuGroup("L")
				.onAction(ac -> {
					FSRLRoot fsFSRL = SelectFromListDialog.selectFromList(
						fsService.getMountedFilesystems(),
						"Select filesystem",
						"Choose filesystem to view", f -> f.toPrettyString());

					FileSystemRef fsRef;
					if (fsFSRL != null &&
						(fsRef = fsService.getMountedFilesystem(fsFSRL)) != null) {
						plugin.createNewFileSystemBrowser(fsRef, true);
					}
				})
				.build();
	}

	private DockingAction createExpandAllAction() {
		return new ActionBuilder("FSB Expand All", plugin.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(
					ac -> ac.notBusy() && ac.getSelectedCount() == 1 && ac.isSelectedAllDirs())
				.popupMenuIcon(ImageManager.EXPAND_ALL)
				.popupMenuPath("Expand All")
				.popupMenuGroup("B", "A")
				.onAction(ac -> {
					FSBNode selectedNode = ac.getSelectedNode();
					if (selectedNode != null) {
						gTree.expandTree(selectedNode);
					}
				})
				.build();
	}

	private DockingAction createCollapseAllAction() {
		return new ActionBuilder("FSB Collapse All", plugin.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(
					ac -> ac.notBusy() && ac.getSelectedCount() == 1 && ac.isSelectedAllDirs())
				.popupMenuIcon(ImageManager.COLLAPSE_ALL)
				.popupMenuPath("Collapse All")
				.popupMenuGroup("B", "B")
				.onAction(ac -> {
					FSBNode selectedNode = ac.getSelectedNode();
					if (selectedNode != null) {
						gTree.collapseAll(selectedNode);
					}
				})
				.build();
	}

	private DockingAction createGetInfoAction() {
		return new ActionBuilder("Get Info", plugin.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getFSRL(true) != null)
				.popupMenuPath("Get Info")
				.popupMenuGroup("A")
				.popupMenuIcon(ImageManager.INFO)
				.description("Show information about a file")
				.onAction(
					ac -> {
						FSRL fsrl = ac.getFSRL(true);
						gTree.runTask(monitor -> showInfoForFile(fsrl, monitor));
					})
				.build();
	}

	private DockingAction createOpenFileSystemNewWindowAction() {
		return new ActionBuilder("FSB Open File System In New Window", plugin.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getSelectedNode() instanceof FSBFileNode)
				.popupMenuIcon(ImageManager.OPEN_FILE_SYSTEM)
				.popupMenuPath("Open File System in new window")
				.popupMenuGroup("C")
				.onAction(
					ac -> {
						if (!(ac.getSelectedNode() instanceof FSBFileNode) ||
							ac.getSelectedNode().getFSRL() == null) {
							return;
						}
						FSBFileNode selectedNode = (FSBFileNode) ac.getSelectedNode();
						FSRL containerFSRL = selectedNode.getFSRL();
						if (containerFSRL != null) {
							gTree.runTask(monitor -> {
								doOpenFileSystem(containerFSRL, selectedNode, false, monitor);
							});
						}
					})
				.build();
	}

	private DockingAction createOpenFileSystemNestedAction() {
		return new ActionBuilder("FSB Open File System Nested", plugin.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getSelectedNode() instanceof FSBFileNode)
				.popupMenuIcon(ImageManager.OPEN_FILE_SYSTEM)
				.popupMenuPath("Open File System")
				.popupMenuGroup("C")
				.onAction(ac -> {
					if (!(ac.getSelectedNode() instanceof FSBFileNode) ||
						ac.getSelectedNode().getFSRL() == null) {
						return;
					}
					FSBFileNode selectedNode = (FSBFileNode) ac.getSelectedNode();
					FSRL containerFSRL = selectedNode.getFSRL();
					if (containerFSRL != null) {
						gTree.runTask(monitor -> {
							doOpenFileSystem(containerFSRL, selectedNode, true, monitor);
						});
					}
				})
				.build();
	}

	private DockingAction createOpenNewFileSystemAction() {
		return new ActionBuilder("FSB Open File System Chooser", plugin.getName())
				.description("Open File System Chooser")
				.withContext(FSBActionContext.class)
				.enabledWhen(FSBActionContext::notBusy)
				.toolBarIcon(ImageManager.OPEN_FILE_SYSTEM)
				.toolBarGroup("B")
				.onAction(ac -> plugin.openFileSystem())
				.build();
	}

	private DockingAction createOpenProgramsAction() {
		return new ActionBuilder("FSB Open Programs", plugin.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && plugin.hasProgramManager() &&
					!ac.getLoadableFSRLs().isEmpty())
				.popupMenuIcon(ImageManager.OPEN_ALL)
				.popupMenuPath("Open Program(s)")
				.popupMenuGroup("D", "B")
				.onAction(ac -> {
					if (!plugin.hasProgramManager()) {
						Msg.showInfo(this, plugin.getTool().getActiveWindow(), "Open Program Error",
							"There is no tool currently open that can be used to show a program.");
						return;
					}
					List<FSRL> files = ac.getLoadableFSRLs();
					if (files.size() == 1) {
						String treePath =
							FilenameUtils.getFullPathNoEndSeparator(ac.getFormattedTreePath());
						openProgramFromFile(files.get(0), ac.getSelectedNodes().get(0), treePath);
					}
					else if (files.size() > 1) {
						openProgramsFromFiles(files);
					}
				})
				.build();
	}

	private DockingAction createCloseAction() {
		return new ActionBuilder("FSB Close", plugin.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getSelectedNode() instanceof FSBRootNode)
				.description("Close")
				.toolBarIcon(ImageManager.CLOSE)
				.toolBarGroup("ZZZZ")
				.popupMenuIcon(ImageManager.CLOSE)
				.popupMenuPath("Close")
				.popupMenuGroup("ZZZZ")
				.onAction(ac -> {
					FSBNode selectedNode = ac.getSelectedNode();
					if (!(selectedNode instanceof FSBRootNode)) {
						return;
					}
					FSBRootNode node = (FSBRootNode) selectedNode;
					if (node.getParent() == null) {
						// Close entire window
						if (OptionDialog.showYesNoDialog(provider.getComponent(),
							"Close File System",
							"Do you want to close the filesystem browser for " + node.getName() +
								"?") == OptionDialog.YES_OPTION) {
							provider.componentHidden();	// cause component to close itself
						}
					}
					else {
						// Close file system that is nested in the container's tree and swap
						// in the saved node that was the original container file
						gTree.runTask(monitor -> node.swapBackPrevModelNodeAndDispose());
					}
				})
				.build();
	}

	private DockingAction createImportAction() {
		return new ActionBuilder("FSB Import Single", plugin.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getLoadableFSRL() != null)
				.popupMenuIcon(ImageManager.IMPORT)
				.popupMenuPath("Import")
				.popupMenuGroup("F", "A")
				.onAction(ac -> {
					FSRL fsrl = ac.getLoadableFSRL();
					if (fsrl == null) {
						return;
					}

					String treePath = ac.getFormattedTreePath();
					String suggestedPath =
						FilenameUtils.getFullPathNoEndSeparator(treePath).replaceAll(":/", "/");

					PluginTool tool = plugin.getTool();
					ProgramManager pm = FSBUtils.getProgramManager(tool, false);

					gTree.runTask(monitor -> {
						if (!ensureFileAccessable(fsrl, ac.getSelectedNode(), monitor)) {
							return;
						}
						ImporterUtilities.showImportDialog(tool, pm, fsrl, null, suggestedPath,
							monitor);
					});
				})
				.build();
	}

	private DockingAction createBatchImportAction() {
		return new ActionBuilder("FSB Import Batch", plugin.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getSelectedCount() > 0)
				.popupMenuIcon(ImageManager.IMPORT)
				.popupMenuPath("Batch Import")
				.popupMenuGroup("F", "B")
				.onAction(ac -> {
					// Do some fancy selection logic.
					// If the user selected a combination of files and folders,
					// ignore the folders.
					// If they only selected folders, leave them in the list.
					List<FSRL> files = ac.getFSRLs(true);
					if (files.isEmpty()) {
						return;
					}

					boolean allDirs = ac.isSelectedAllDirs();
					if (files.size() > 1 && !allDirs) {
						files = ac.getFileFSRLs();
					}

					BatchImportDialog.showAndImport(plugin.getTool(), null, files, null,
						FSBUtils.getProgramManager(plugin.getTool(), false));
				})
				.build();
	}

	private DockingAction createClearCachedPasswordsAction() {
		return new ActionBuilder("FSB Clear Cached Passwords", plugin.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(FSBActionContext::notBusy)
				.popupMenuPath("Clear Cached Passwords")
				.popupMenuGroup("Z", "B")
				.description("Clear cached container file passwords")
				.onAction(
					ac -> {
						CachedPasswordProvider ccp =
							CryptoProviders.getInstance().getCachedCryptoProvider();
						int preCount = ccp.getCount();
						ccp.clearCache();
						Msg.info(this,
							"Cleared " + (preCount - ccp.getCount()) + " cached passwords.");
					})
				.build();
	}

	private DockingAction createRefreshAction() {
		return new ActionBuilder("FSB Refresh", plugin.getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.hasSelectedNodes())
				.popupMenuPath("Refresh")
				.popupMenuGroup("Z", "Z")
				.description("Refresh file info")
				.onAction(
					ac -> gTree.runTask(monitor -> doRefreshInfo(ac.getSelectedNodes(), monitor)))
				.build();
	}

	//----------------------------------------------------------------------------------
	// end DockingActions
	//----------------------------------------------------------------------------------

	private void doExtractFile(FSRL fsrl, File outputFile, FSBNode node, TaskMonitor monitor) {
		if (!ensureFileAccessable(fsrl, node, monitor)) {
			return;
		}
		monitor.setMessage("Exporting...");
		try (ByteProvider fileBP = fsService.getByteProvider(fsrl, false, monitor)) {
			long bytesCopied =
				FSUtilities.copyByteProviderToFile(fileBP, outputFile, monitor);
			Msg.info(this, "Exported " + fsrl.getName() + " to " + outputFile + ", " +
				bytesCopied + " bytes copied.");
		}
		catch (IOException | CancelledException | UnsupportedOperationException e) {
			FSUtilities.displayException(this, plugin.getTool().getActiveWindow(),
				"Error Exporting File", e.getMessage(), e);
		}
	}

	/*
	 * run on gTree task thread
	 */
	private void doOpenFileSystem(FSRL containerFSRL, FSBFileNode node, boolean nested,
			TaskMonitor monitor) {
		try {
			if (!ensureFileAccessable(containerFSRL, node, monitor)) {
				return;
			}

			monitor.setMessage("Probing " + containerFSRL.getName() + " for filesystems");
			FileSystemRef ref = fsService.probeFileForFilesystem(containerFSRL, monitor,
				FileSystemProbeConflictResolver.GUI_PICKER);
			if (ref == null) {
				Msg.showWarn(this, plugin.getTool().getActiveWindow(), "Open Filesystem",
					"No filesystem detected in " + containerFSRL.getName());
				return;
			}

			Swing.runLater(() -> {
				if (nested) {
					FSBFileNode modelFileNode =
						(FSBFileNode) gTree.getModelNodeForPath(node.getTreePath());

					FSBRootNode nestedRootNode = new FSBRootNode(ref, modelFileNode);
					try {
						nestedRootNode.setChildren(nestedRootNode.generateChildren(monitor));
					}
					catch (CancelledException e) {
						Msg.warn(this, "Failed to populate FSB root node with children");
					}

					int indexInParent = modelFileNode.getIndexInParent();
					GTreeNode parent = modelFileNode.getParent();
					parent.removeNode(modelFileNode);
					parent.addNode(indexInParent, nestedRootNode);
					gTree.expandPath(nestedRootNode);
					provider.contextChanged();
				}
				else {
					plugin.createNewFileSystemBrowser(ref, true);
				}
			});
		}
		catch (IOException | CancelledException e) {
			FSUtilities.displayException(this, plugin.getTool().getActiveWindow(),
				"Open Filesystem",
				"Error opening filesystem for " + containerFSRL.getName(), e);
		}
	}

	private void doViewAsImage(FSRL fsrl, FSBNode node, TaskMonitor monitor) {
		if (!ensureFileAccessable(fsrl, node, monitor)) {
			return;
		}

		Component parent = plugin.getTool().getActiveWindow();
		try (RefdFile refdFile = fsService.getRefdFile(fsrl, monitor)) {

			Icon icon = GIconProvider.getIconForFile(refdFile.file, monitor);
			if (icon == null) {
				Msg.showError(this, parent, "Unable To View Image",
					"Unable to view " + fsrl.getName() + " as an image.");
				return;
			}
			Swing.runLater(() -> {
				JLabel label = new GIconLabel(icon);
				JOptionPane.showMessageDialog(null, label,
					"Image Viewer: " + fsrl.getName(), JOptionPane.INFORMATION_MESSAGE);
			});
		}
		catch (IOException | CancelledException e) {
			FSUtilities.displayException(this, parent, "Error Viewing Image File",
				e.getMessage(), e);
		}
	}

	private void doViewAsText(FSRL fsrl, FSBNode node, TaskMonitor monitor) {
		if (!ensureFileAccessable(fsrl, node, monitor)) {
			return;
		}

		Component parent = plugin.getTool().getActiveWindow();
		try (ByteProvider fileBP = fsService.getByteProvider(fsrl, false, monitor)) {

			if (fileBP.length() > MAX_TEXT_FILE_LEN) {
				Msg.showInfo(this, parent, "View As Text Failed",
					"File too large to view as text inside Ghidra. " +
						"Please use the \"EXPORT\" action.");
				return;
			}
			if (fileBP.length() == 0) {
				Msg.showInfo(this, parent, "View As Text Failed",
					"File " + fsrl.getName() + " is empty (0 bytes).");
				return;
			}
			try {
				// textEditorService closes the inputStream, and must be
				// called on the swing thread or you get concurrentmodification
				// exceptions.
				ByteArrayInputStream bais =
					new ByteArrayInputStream(fileBP.readBytes(0, fileBP.length()));
				Swing.runLater(() -> textEditorService.edit(fsrl.getName(), bais));
			}
			catch (IOException e) {
				Msg.showError(this, parent, "View As Text Failed",
					"Error when trying to view text file " + fsrl.getName(), e);
			}
		}
		catch (IOException | CancelledException e) {
			FSUtilities.displayException(this, parent, "Error Viewing Text File",
				e.getMessage(), e);
		}
	}

	void doRefreshInfo(List<FSBNode> nodes, TaskMonitor monitor) {
		Set<FSBRootNode> rootNodes = new HashSet<>();
		for (FSBNode node : nodes) {
			if (node instanceof FSBFileNode) {
				// for each file node, if it's password attr info is out of date, build a unique
				// list of the containing root nodes that will later be used to refresh the
				// entire FS
				if (((FSBFileNode) node).needsFileAttributesUpdate(monitor)) {
					rootNodes.add(node.getFSBRootNode());
				}
			}
			else if (node instanceof FSBDirNode) {
				// if the user selected a dir node, force the FS to be refreshed
				rootNodes.add(node.getFSBRootNode());
			}
			else if (node instanceof FSBRootNode) {
				rootNodes.add((FSBRootNode) node);
			}
		}
		try {
			for (FSBRootNode rootNode : rootNodes) {
				rootNode.updateFileAttributes(monitor);
			}
			gTree.refilterLater();	// force the changed modelNodes to be recloned and displayed (if filter active)
		}
		catch (CancelledException e) {
			// stop
		}
		Swing.runLater(() -> gTree.repaint());
	}

	private boolean ensureFileAccessable(FSRL fsrl, FSBNode node, TaskMonitor monitor) {

		FSBFileNode fileNode = (node instanceof FSBFileNode) ? (FSBFileNode) node : null;

		monitor.initialize(0);
		monitor.setMessage("Testing file access");
		boolean wasMissingPasword = (fileNode != null) ? fileNode.hasMissingPassword() : false;
		try (ByteProvider bp = fsService.getByteProvider(fsrl, false, monitor)) {
			// if we can get here and it used to have a missing password, update the node's status
			if (fileNode != null && wasMissingPasword) {
				doRefreshInfo(List.of(fileNode), monitor);
			}
			return true;
		}
		catch (CryptoException e) {
			Msg.showWarn(this, gTree, "Crypto / Password Error",
				"Unable to access the specified file.\n" +
					"This could be caused by not entering the correct password or because of missing crypto information.\n\n" +
					e.getMessage());
			return false;
		}
		catch (IOException e) {
			Msg.showError(this, gTree, "File IO Error",
				"Unable to access the specified file.\n\n" + e.getMessage(), e);
			return false;
		}
		catch (CancelledException e) {
			return false;
		}

	}

	//---------------------------------------------------------------------------------------------
	// static lookup tables for rendering file attributes
	//---------------------------------------------------------------------------------------------
	private static final Function<Object, String> PLAIN_TOSTRING = o -> o.toString();
	private static final Function<Object, String> SIZE_TOSTRING = o -> (o instanceof Long)
			? FSUtilities.formatSize((Long) o)
			: o.toString();
	private static final Function<Object, String> UNIX_ACL_TOSTRING = o -> (o instanceof Number)
			? String.format("%05o", (Number) o)
			: o.toString();
	private static final Function<Object, String> DATE_TOSTRING = o -> (o instanceof Date)
			? FSUtilities.formatFSTimestamp((Date) o)
			: o.toString();
	private static final Function<Object, String> FSRL_TOSTRING = o -> (o instanceof FSRL)
			? ((FSRL) o).toPrettyString().replace("|", "|\n\t")
			: o.toString();

	private static final Map<FileAttributeType, Function<Object, String>> FAT_TOSTRING_FUNCS =
		Map.ofEntries(
			entry(FSRL_ATTR, FSRL_TOSTRING),
			entry(SIZE_ATTR, SIZE_TOSTRING),
			entry(COMPRESSED_SIZE_ATTR, SIZE_TOSTRING),
			entry(CREATE_DATE_ATTR, DATE_TOSTRING),
			entry(MODIFIED_DATE_ATTR, DATE_TOSTRING),
			entry(ACCESSED_DATE_ATTR, DATE_TOSTRING),
			entry(UNIX_ACL_ATTR, UNIX_ACL_TOSTRING));

	/**
	 * Shows a dialog with information about the specified file.
	 *
	 * @param fsrl {@link FSRL} of the file to display info about.
	 * @param monitor {@link TaskMonitor} to monitor and update when accessing the filesystems.
	 */
	private void showInfoForFile(FSRL fsrl, TaskMonitor monitor) {
		if (fsrl == null) {
			Msg.showError(this, null, "Missing File", "Unable to retrieve information");
			return;
		}

		// if looking at the root of a nested file system, also include its parent container
		List<FSRL> fsrls = (fsrl instanceof FSRLRoot && ((FSRLRoot) fsrl).hasContainer())
				? List.of(((FSRLRoot) fsrl).getContainer(), fsrl)
				: List.of(fsrl);
		String title = "Info about " + fsrls.get(0).getName();
		List<FileAttributes> fattrs = new ArrayList<>();
		for (FSRL fsrl2 : fsrls) {
			try {
				fattrs.add(getAttrsFor(fsrl2, monitor));
			}
			catch (IOException e) {
				Msg.warn(this, "Failed to get info for file " + fsrl2, e);
			}
			catch (CancelledException e) {
				return;
			}
		}
		String html = getHTMLInfoStringForAttributes(fattrs);

		MultiLineMessageDialog.showMessageDialog(plugin.getTool().getActiveWindow(), title, null,
			html, MultiLineMessageDialog.INFORMATION_MESSAGE);
	}

	private FileAttributes getAttrsFor(FSRL fsrl, TaskMonitor monitor)
			throws CancelledException, IOException {
		try (RefdFile refdFile = fsService.getRefdFile(fsrl, monitor)) {
			GFileSystem fs = refdFile.fsRef.getFilesystem();
			GFile file = refdFile.file;
			FileAttributes fattrs = fs.getFileAttributes(file, monitor);
			if (fattrs == null) {
				fattrs = FileAttributes.EMPTY;
			}
			fattrs = fattrs.clone();
			DomainFile associatedDomainFile = ProgramMappingService.getCachedDomainFileFor(fsrl);
			if (associatedDomainFile != null) {
				fattrs.add(PROJECT_FILE_ATTR, associatedDomainFile.getPathname());
			}

			if (!fattrs.contains(NAME_ATTR)) {
				fattrs.add(NAME_ATTR, file.getName());
			}
			if (!fattrs.contains(PATH_ATTR)) {
				fattrs.add(PATH_ATTR, FilenameUtils.getFullPath(file.getPath()));
			}
			if (!fattrs.contains(FSRL_ATTR)) {
				fattrs.add(FSRL_ATTR, file.getFSRL());
			}
			return fattrs;
		}
	}

	private String getHTMLInfoStringForAttributes(List<FileAttributes> fileAttributesList) {
		StringBuilder sb =
			new StringBuilder("<html>\n<table>\n");
		sb.append("<tr><th>Property</th><th>Value</th></tr>\n");
		for (FileAttributes fattrs : fileAttributesList) {
			if (fattrs != fileAttributesList.get(0)) {
				// not first element, put a visual divider line
				sb.append("<tr><td colspan=2><hr></td></tr>");
			}
			List<FileAttribute<?>> sortedAttribs = fattrs.getAttributes();
			Collections.sort(sortedAttribs,
				(o1, o2) -> Integer.compare(o1.getAttributeType().ordinal(),
					o2.getAttributeType().ordinal()));

			FileAttributeTypeGroup group = null;
			for (FileAttribute<?> attr : sortedAttribs) {
				if (attr.getAttributeType().getGroup() != group) {
					group = attr.getAttributeType().getGroup();
					if (group != FileAttributeTypeGroup.GENERAL_INFO) {
						sb
								.append("<tr><td><b>")
								.append(group.getDescriptiveName())
								.append("</b></td><td><hr></td></tr>\n");
					}
				}
				String valStr =
					FAT_TOSTRING_FUNCS.getOrDefault(attr.getAttributeType(), PLAIN_TOSTRING)
							.apply(attr.getAttributeValue());

				String html = HTMLUtilities.escapeHTML(valStr);
				html = html.replace("\n", "<br>\n");
				sb
						.append("<tr><td>")
						.append(attr.getAttributeDisplayName())
						.append(":</td><td>")
						.append(html)
						.append("</td></tr>\n");
			}
		}
		sb.append("</table>");
		return sb.toString();
	}

}
