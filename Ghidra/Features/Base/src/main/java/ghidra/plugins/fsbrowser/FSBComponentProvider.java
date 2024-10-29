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

import java.awt.Component;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import docking.*;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.actions.PopupActionProvider;
import docking.event.mouse.GMouseListenerAdapter;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeRenderer;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.plugin.importer.ImporterUtilities;
import ghidra.plugin.importer.ProjectIndexService;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.MonitoredRunnable;
import ghidra.util.task.TaskMonitor;

/**
 * Plugin component provider for the {@link FileSystemBrowserPlugin}.
 * <p>
 * An instance of this class is created for each file system browser window (w/tree).
 * <p>
 * See the {@link FSBFileHandler} interface for how to add actions to this component.
 */
public class FSBComponentProvider extends ComponentProviderAdapter
		implements FileSystemEventListener, PopupActionProvider {
	private static final String TITLE = "Filesystem Viewer";

	private FSBIcons fsbIcons = FSBIcons.getInstance();
	private FileSystemService fsService = FileSystemService.getInstance();
	private ProjectIndexService projectIndex = ProjectIndexService.getInstance();

	private FileSystemBrowserPlugin plugin;
	private GTree gTree;
	private FSBRootNode rootNode;
	private List<FSBFileHandler> fileHandlers = List.of();
	private ProgramManager pm;

	/**
	 * Creates a new {@link FSBComponentProvider} instance, taking
	 * ownership of the passed-in {@link FileSystemRef fsRef}.
	 *
	 * @param plugin parent plugin
	 * @param fsRef {@link FileSystemRef} to a {@link GFileSystem}.
	 */
	public FSBComponentProvider(FileSystemBrowserPlugin plugin, FileSystemRef fsRef) {
		super(plugin.getTool(), fsRef.getFilesystem().getName(), plugin.getName());

		this.plugin = plugin;
		this.rootNode = new FSBRootNode(fsRef);
		this.pm = plugin.getTool().getService(ProgramManager.class);

		setTransient();
		setIcon(FSBIcons.PHOTO);

		initTree();
		fsRef.getFilesystem().getRefManager().addListener(this);
		initFileHandlers();

		setHelpLocation(
			new HelpLocation("FileSystemBrowserPlugin", "FileSystemBrowserIntroduction"));

	}

	void initFileHandlers() {
		FSBFileHandlerContext context =
			new FSBFileHandlerContext(plugin, this, fsService, projectIndex);
		fileHandlers = ClassSearcher.getInstances(FSBFileHandler.class);
		for (FSBFileHandler fileHandler : fileHandlers) {
			fileHandler.init(context);
		}
		fileHandlers.add(new DefaultFileHandler());
		plugin.getTool().addPopupActionProvider(this); // delegate to fileHandler's getPopupProviderActions()
	}

	void initTree() {
		gTree = new GTree(rootNode);
		gTree.getSelectionModel().setSelectionMode(TreeSelectionModel.DISCONTIGUOUS_TREE_SELECTION);
		gTree.getSelectionModel().addTreeSelectionListener(e -> {
			tool.contextChanged(FSBComponentProvider.this);
			TreePath[] paths = gTree.getSelectionPaths();
			if (paths.length == 1) {
				GTreeNode clickedNode = (GTreeNode) paths[0].getLastPathComponent();
				handleSingleClick(clickedNode);
			}
		});
		gTree.addMouseListener(new GMouseListenerAdapter() {
			@Override
			public void doubleClickTriggered(MouseEvent e) {
				if (handleDoubleClick(gTree.getNodeForLocation(e.getX(), e.getY()))) {
					e.consume();
				}
			}

			@Override
			public void mouseClicked(MouseEvent e) {
				super.mouseClicked(e);
				if (!e.isConsumed()) {
					handleSingleClick(gTree.getNodeForLocation(e.getX(), e.getY()));
				}
			}
		});
		gTree.setCellRenderer(new GTreeRenderer() {
			@Override
			public Component getTreeCellRendererComponent(JTree tree, Object value,
					boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus) {

				super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row,
					hasFocus);

				if (value instanceof FSBRootNode fsRootNode) {
					renderFS(fsRootNode, selected);
				}
				else if (value instanceof FSBDirNode) {
					// do nothing special, but exclude FSBFileNode
				}
				else if (value instanceof FSBFileNode fileNode) {
					renderFile(fileNode, selected);
				}

				return this;
			}

			private void renderFS(FSBRootNode node, boolean selected) {
				FileSystemRef nodeFSRef = node.getFSRef();
				if (nodeFSRef == null || nodeFSRef.getFilesystem() == null) {
					return;
				}
				Icon image = fsbIcons.getIcon(node.getContainerName(),
					List.of(FSBIcons.FILESYSTEM_OVERLAY_ICON));
				setIcon(image);
			}

			private void renderFile(FSBFileNode node, boolean selected) {
				FSRL fsrl = node.getFSRL();
				String filename = fsrl.getName();
				List<Icon> overlays = new ArrayList<>(4);

				DomainFile df = projectIndex.findFirstByFSRL(fsrl);
				if (df != null) {
					overlays.add(FSBIcons.IMPORTED_OVERLAY_ICON);

					if (plugin.isOpen(df)) {
						// TODO: change this to a OVERLAY_OPEN option when fetching icon
						setForeground(selected ? Palette.CYAN : Palette.MAGENTA);
					}
				}
				if (fsService.isFilesystemMountedAt(fsrl)) {
					overlays.add(FSBIcons.FILESYSTEM_OVERLAY_ICON);
				}
				if (node.isSymlink()) {
					overlays.add(FSBIcons.LINK_OVERLAY_ICON);
				}
				if (node.hasMissingPassword()) {
					overlays.add(FSBIcons.MISSING_PASSWORD_OVERLAY_ICON);
				}

				String ext = node.getFilenameExtOverride();
				if (ext != null && !ext.isEmpty()) {
					if (ext.startsWith(".")) {
						Msg.error(this,
							"Extension override '" + ext + "' should not begin with a dot");
					} else {
						filename += "." + ext;
					}
				}

				Icon icon = fsbIcons.getIcon(filename, overlays);
				setIcon(icon);
			}
		});
	}

	public FileSystemBrowserPlugin getPlugin() {
		return plugin;
	}

	/**
	 *
	 * @return this provider's GTree.
	 */
	public GTree getGTree() {
		return gTree;
	}

	FSRL getFSRL() {
		return rootNode != null ? rootNode.getFSRL() : null;
	}

	public ProjectIndexService getProjectIndex() {
		return projectIndex;
	}

	void dispose() {
		plugin.getTool().removePopupActionProvider(this);

		if (rootNode != null && rootNode.getFSRef() != null && !rootNode.getFSRef().isClosed()) {
			rootNode.getFSRef().getFilesystem().getRefManager().removeListener(this);
		}
		fileHandlers.clear();
		if (gTree != null) {
			gTree.setCellRenderer(null); // avoid npe's in the cellrenderer when disposed
			gTree.dispose(); // calls dispose() on tree's rootNode, which will release the fsRefs
		}
		removeFromTool();
		rootNode = null;
		plugin = null;
		gTree = null;
	}

	@Override
	public void componentHidden() {
		// if the component is 'closed', nuke ourselves
		if (plugin != null) {
			plugin.removeFileSystemBrowserComponent(this);
			dispose();
		}
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext context) {
		List<DockingActionIf> results = new ArrayList<>();
		for (FSBFileHandler fileHandler : fileHandlers) {
			List<DockingAction> actions = fileHandler.getPopupProviderActions();
			results.addAll(actions);
		}
		return results;
	}

	public void afterAddedToTool() {
		fileHandlers.stream()
				.flatMap(fh -> fh.createActions().stream())
				.forEach(this::addLocalAction);

		setProject(tool.getProject());
	}

	public void setProject(Project project) {
		gTree.runTask(monitor -> {
			projectIndex.setProject(project, monitor);
			Swing.runLater(() -> gTree.repaint()); // icons might need repainting after new info is available
		});
	}

	@Override
	public void onFilesystemClose(GFileSystem fs) {
		Msg.info(this, "File system " + fs.getFSRL() + " was closed! Closing browser window");
		Swing.runIfSwingOrRunLater(() -> componentHidden());
	}

	@Override
	public void onFilesystemRefChange(GFileSystem fs, FileSystemRefManager refManager) {
		// nothing
	}

	public void runTask(MonitoredRunnable runnableTask) {
		gTree.runTask(runnableTask);
	}

	/*****************************************/

	private boolean handleSingleClick(GTreeNode clickedNode) {
		if (clickedNode instanceof FSBFileNode fileNode) {
			for (FSBFileHandler handler : fileHandlers) {
				if (handler.fileFocused(fileNode)) {
					return true;
				}
			}
		}
		return false;
	}

	private boolean handleDoubleClick(GTreeNode clickedNode) {
		if (clickedNode instanceof FSBFileNode fileNode) {
			for (FSBFileHandler handler : fileHandlers) {
				if (handler.fileDefaultAction(fileNode)) {
					return true;
				}
			}
		}
		return false;
	}

	/*****************************************/

	@Override
	public FSBActionContext getActionContext(MouseEvent event) {
		return new FSBActionContext(this, getSelectedNodes(event), event, gTree);
	}

	private List<FSBNode> getSelectedNodes(MouseEvent event) {
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		List<FSBNode> list = new ArrayList<>(selectionPaths.length);
		for (TreePath selectionPath : selectionPaths) {
			Object lastPathComponent = selectionPath.getLastPathComponent();
			if (lastPathComponent instanceof FSBNode fsbNode) {
				list.add(fsbNode);
			}
		}
		if (list.isEmpty() && event != null) {
			Object source = event.getSource();
			if (source instanceof JTree sourceTree && gTree.isMyJTree(sourceTree)) {
				int x = event.getX();
				int y = event.getY();
				GTreeNode nodeAtEventLocation = gTree.getNodeForLocation(x, y);
				if (nodeAtEventLocation != null && nodeAtEventLocation instanceof FSBNode fsbNode) {
					list.add(fsbNode);
				}
			}
		}
		return list;
	}

	@Override
	public JComponent getComponent() {
		return gTree;
	}

	@Override
	public String getName() {
		return TITLE;
	}

	@Override
	public WindowPosition getDefaultWindowPosition() {
		return WindowPosition.WINDOW;
	}

	public boolean ensureFileAccessable(FSRL fsrl, FSBNode node, TaskMonitor monitor) {

		FSBFileNode fileNode = (node instanceof FSBFileNode) ? (FSBFileNode) node : null;

		monitor.initialize(0);
		monitor.setMessage("Testing file access");
		boolean wasMissingPasword = (fileNode != null) ? fileNode.hasMissingPassword() : false;
		try (ByteProvider bp = fsService.getByteProvider(fsrl, false, monitor)) {
			// if we can get here and it used to have a missing password, update the node's status
			if (wasMissingPasword) {
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

	public boolean openFileSystem(FSBNode node, boolean nested) {
		if (!(node instanceof FSBFileNode fileNode) || fileNode.getFSRL() == null) {
			return false;
		}
		FSRL fsrl = fileNode.getFSRL();
		gTree.runTask(monitor -> {
			if (!ensureFileAccessable(fsrl, fileNode, monitor)) {
				return;
			}
			if (!doOpenFileSystem(fsrl, fileNode, nested, monitor)) {
				return;
			}
		});
		return true;
	}

	/*
	 * run on gTree task thread
	 */
	boolean doOpenFileSystem(FSRL containerFSRL, FSBFileNode node, boolean nested,
			TaskMonitor monitor) {
		try {
			monitor.setMessage("Probing " + containerFSRL.getName() + " for filesystems");
			FileSystemRef ref = fsService.probeFileForFilesystem(containerFSRL, monitor,
				FileSystemProbeConflictResolver.GUI_PICKER);
			if (ref == null) {
				Msg.showWarn(this, plugin.getTool().getActiveWindow(), "Open Filesystem",
					"No filesystem detected in " + containerFSRL.getName());
				return false;
			}

			Swing.runLater(() -> {
				if (nested) {
					FSBFileNode modelFileNode =
						(FSBFileNode) gTree.getModelNodeForPath(node.getTreePath());

					FSBRootNode nestedRootNode = new FSBRootNode(ref, modelFileNode);

					int indexInParent = modelFileNode.getIndexInParent();
					GTreeNode parent = modelFileNode.getParent();
					parent.removeNode(modelFileNode);
					parent.addNode(indexInParent, nestedRootNode);
					gTree.expandPath(nestedRootNode);
					try {
						nestedRootNode.init(monitor);
					}
					catch (CancelledException e) {
						Msg.warn(this, "Failed to populate FSB root node with children");
					}
					contextChanged();
				}
				else {
					plugin.createNewFileSystemBrowser(ref, true);
				}
			});
			return true;
		}
		catch (IOException | CancelledException e) {
			FSUtilities.displayException(this, plugin.getTool().getActiveWindow(),
				"Open Filesystem", "Error opening filesystem for " + containerFSRL.getName(), e);
			return false;
		}
	}

	void doRefreshInfo(List<FSBNode> nodes, TaskMonitor monitor) {
		try {
			for (FSBNode node : nodes) {
				node.refreshNode(monitor);
			}
			gTree.refilterLater();	// force the changed modelNodes to be recloned and displayed (if filter active)
		}
		catch (CancelledException e) {
			// stop
		}
		Swing.runLater(() -> gTree.repaint());
	}

	//---------------------------------------------------------------------------------------------

	private class DefaultFileHandler implements FSBFileHandler {

		@Override
		public void init(FSBFileHandlerContext context) {
			// empty
		}

		@Override
		public List<DockingAction> createActions() {
			return List.of();
		}

		@Override
		public boolean fileFocused(FSBFileNode fileNode) {

			FSRL fsrl = fileNode.getFSRL();
			if (fsrl != null) {
				if (pm != null) {
					// if this tool is a codebrowser-ish tool, switch focus to the matching focused file
					DomainFile df = projectIndex.findFirstByFSRL(fsrl);
					DomainObject domObj;
					if (df != null && (domObj = df.getOpenedDomainObject(this)) != null) {
						domObj.release(this);
						if (domObj instanceof Program program) {
							runTask(monitor -> pm.setCurrentProgram(program));
						}
						return true;
					}
				}

				if (fileNode.hasMissingPassword()) {
					runTask(monitor -> doRefreshInfo(List.of(fileNode), monitor));
				}
			}
			return false;
		}

		@Override
		public boolean fileDefaultAction(FSBFileNode fileNode) {
			FSRL fsrl = fileNode.getFSRL();
			if (fsrl == null) {
				return false;
			}

			if (fileNode.isSymlink()) {
				gotoSymlinkDest(fileNode);
				return true;
			}

			if (!fileNode.isLeaf()) {
				return false;
			}

			runTask(monitor -> {
				if (!ensureFileAccessable(fsrl, fileNode, monitor)) {
					return;
				}
				try {
					FSRL fullFsrl = fsService.getFullyQualifiedFSRL(fsrl, monitor);
					if (fsService.isFileFilesystemContainer(fullFsrl, monitor)) {
						doOpenFileSystem(fullFsrl, fileNode, true, monitor);
						return;
					}

					DomainFile df = projectIndex.findFirstByFSRL(fsrl);
					OpenWithTarget openWithTarget = OpenWithTarget.getDefault(plugin.getTool());
					if (df != null && openWithTarget != null) {
						Swing.runLater(() -> openWithTarget.open(List.of(df)));
						return;
					}
					ImporterUtilities.showImportSingleFileDialog(fullFsrl, null,
						fileNode.getFormattedTreePath(), plugin.getTool(), openWithTarget.getPm(),
						monitor);
				}
				catch (IOException | CancelledException e) {
					// fall thru
				}
			});

			return true;
		}

		private void gotoSymlinkDest(FSBFileNode fileNode) {
			GFile file = fileNode.file;
			try {
				FSBRootNode fsRootNode = fileNode.getFSBRootNode();
				GFile destFile = file.getFilesystem().resolveSymlinks(file);
				if (destFile != null && fsRootNode != null) {
					gTree.runTask(monitor -> {
						FSBNode destNode = fsRootNode.getGFileFSBNode(destFile, monitor);
						if (destNode != null) {
							Swing.runLater(() -> gTree.setSelectedNodes(destNode));
						}
					});
					return;
				}
			}
			catch (IOException e) {
				// fall thru
			}
			FileAttributes fattrs = file.getFilesystem().getFileAttributes(file, null);
			String symlinkDest = fattrs.get(SYMLINK_DEST_ATTR, String.class, null);
			plugin.getTool()
					.setStatusInfo("Unable to resolve symlink [%s]".formatted(symlinkDest), true);
		}

	}

}
