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

import java.awt.Color;
import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import docking.ActionContext;
import docking.WindowPosition;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeRenderer;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.TextEditorService;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.plugin.importer.ProgramMappingService;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * Plugin component provider for the {@link FileSystemBrowserPlugin}.
 * <p>
 * An instance of this class is created for each file system browser window (w/tree).
 * <p>
 * Visible to just this package.
 */
class FileSystemBrowserComponentProvider extends ComponentProviderAdapter {
	private static final String TITLE = "Filesystem Viewer";

	private FileSystemBrowserPlugin plugin;
	private FSBActionManager actionManager;
	private GTree gTree;
	private FSBRootNode rootNode;

	/**
	 * Creates a new {@link FileSystemBrowserComponentProvider} instance, taking
	 * ownership of the passed-in {@link FileSystemRef fsRef}.
	 *
	 * @param plugin parent plugin
	 * @param fsRef {@link FileSystemRef} to a {@link GFileSystem}.
	 */
	public FileSystemBrowserComponentProvider(FileSystemBrowserPlugin plugin, FileSystemRef fsRef) {
		super(plugin.getTool(), fsRef.getFilesystem().getName(), plugin.getName());

		this.plugin = plugin;
		this.rootNode = new FSBRootNode(fsRef);

		setTransient();
		setIcon(ImageManager.PHOTO);

		gTree = new GTree(rootNode);
		gTree.getSelectionModel().setSelectionMode(TreeSelectionModel.DISCONTIGUOUS_TREE_SELECTION);
		gTree.getSelectionModel().addTreeSelectionListener(e -> {
			tool.contextChanged(FileSystemBrowserComponentProvider.this);
			TreePath[] paths = gTree.getSelectionPaths();
			if (paths.length == 1) {
				GTreeNode clickedNode = (GTreeNode) paths[0].getLastPathComponent();
				handleSingleClick(clickedNode);
			}
		});
		gTree.addMouseListener(new MouseAdapter() {
			/**
			 * Keep track of the previous mouse button that was clicked so we
			 * can ensure that it was two left clicks that activated
			 * our dbl-click handler.
			 */
			int prevMouseButton = -1;

			@Override
			public void mouseReleased(MouseEvent e) {
				// keep track of the mouse button so it can be checked next time
				int localPrevMouseButton = prevMouseButton;
				prevMouseButton = e.getButton();

				if (e.isPopupTrigger()) {
					return;
				}

				GTreeNode clickedNode = gTree.getNodeForLocation(e.getX(), e.getY());
				if (e.getClickCount() == 1) {
					handleSingleClick(clickedNode);
				}
				if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1 &&
					localPrevMouseButton == MouseEvent.BUTTON1) {
					handleDoubleClick(clickedNode);
				}
			}
		});
		gTree.setCellRenderer(new GTreeRenderer() {
			@Override
			public Component getTreeCellRendererComponent(JTree tree, Object value,
					boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus) {

				super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row,
					hasFocus);

				if (value instanceof FSBRootNode) {
					renderFS((FSBRootNode) value, selected);
				}
				else if (value instanceof FSBFileNode) {
					renderFile((FSBFileNode) value, selected);
				}
				else if (value instanceof FSBNode) {
					renderNode((FSBNode) value, selected);
				}

				return this;
			}

			private void renderFS(FSBRootNode node, boolean selected) {
				FileSystemRef nodeFSRef = node.getFSRef();
				if (nodeFSRef == null || nodeFSRef.getFilesystem() == null) {
					return;
				}
				FSRLRoot fsFSRL = nodeFSRef.getFilesystem().getFSRL();
				String containerFilename =
					fsFSRL.hasContainer() ? fsFSRL.getContainer().getName() : "unknown";
				Icon image = FileIconService.getInstance().getImage(containerFilename,
					FileIconService.OVERLAY_FILESYSTEM);
				setIcon(image);
			}

			private void renderFile(FSBFileNode node, boolean selected) {
				FSRL fsrl = node.getFSRL();
				String filename = fsrl.getName();
				Icon ico = FileIconService.getInstance().getImage(filename,
					ProgramMappingService.isFileImportedIntoProject(fsrl)
							? FileIconService.OVERLAY_IMPORTED
							: null,
					FileSystemService.getInstance().isFilesystemMountedAt(fsrl)
							? FileIconService.OVERLAY_FILESYSTEM
							: null);
				setIcon(ico);
				if (ProgramMappingService.isFileOpen(fsrl)) {
					// TODO: change this to a OVERLAY_OPEN option when fetching icon
					setForeground(selected ? Color.CYAN : Color.MAGENTA);
				}
			}

			private void renderNode(FSBNode node, boolean selected) {
				// do nothing for now
			}
		});

		actionManager = new FSBActionManager(plugin, this,
			plugin.getTool().getService(TextEditorService.class), gTree);

		// TODO: fix this Help stuff
		setHelpLocation(
			new HelpLocation("FileSystemBrowserPlugin", "FileSystemBrowserIntroduction"));

	}

	/**
	 * For testing access only.
	 *
	 * @return this provider's GTree.
	 */
	GTree getGTree() {
		return gTree;
	}

	FSBActionManager getActionManager() {
		return actionManager;
	}

	@Override
	public void componentHidden() {
		// if the component is 'closed', nuke ourselves via the plugin
		if (plugin != null && rootNode.getFSRef() != null &&
			rootNode.getFSRef().getFilesystem() != null) {
			plugin.removeFileSystemBrowser(rootNode.getFSRef().getFilesystem().getFSRL());
		}
	}

	public void afterAddedToTool() {
		actionManager.registerComponentActionsInTool();
	}

	/*****************************************/

	/**
	 * Finds an associated already open {@link Program} and makes it visible in the
	 * current tool's ProgramManager.
	 *
	 * @param fsrl {@link FSRL} of the file to attempt to quickly show if its already open in a PM.
	 * @return boolean true if already open program was found and it was switched to.
	 */
	private boolean quickShowProgram(FSRL fsrl) {
		if (plugin.hasProgramManager()) {
			ProgramManager programManager = FSBUtils.getProgramManager(plugin.getTool(), false);
			if (programManager != null) {
				Object consumer = new Object();
				Program program = ProgramMappingService.findMatchingOpenProgram(fsrl, consumer);
				if (program != null) {
					programManager.setCurrentProgram(program);
					program.release(consumer);
					return true;
				}
			}
		}

		return false;
	}

	private void handleSingleClick(GTreeNode clickedNode) {
		if (clickedNode instanceof FSBFileNode) {
			FSBFileNode node = (FSBFileNode) clickedNode;
			if (node.getFSRL() != null) {
				quickShowProgram(node.getFSRL());
			}
		}
	}

	private void handleDoubleClick(GTreeNode clickedNode) {
		if (clickedNode instanceof FSBFileNode) {
			FSBFileNode node = (FSBFileNode) clickedNode;

			if (node.getFSRL() != null && !quickShowProgram(node.getFSRL())) {
				actionManager.actionOpenPrograms.actionPerformed(getActionContext(null));
			}
		}
	}

	/*****************************************/

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		if (selectionPaths != null && selectionPaths.length == 1) {
			Object lastPathComponent = selectionPaths[0].getLastPathComponent();
			return new FSBActionContext(this, lastPathComponent, gTree);
		}
		if (selectionPaths != null && selectionPaths.length > 0) {
			List<FSBNode> list = new ArrayList<>();
			for (TreePath selectionPath : selectionPaths) {
				Object lastPathComponent = selectionPath.getLastPathComponent();
				if (lastPathComponent instanceof FSBNode) {
					FSBNode node = (FSBNode) lastPathComponent;
					list.add(node);
				}
			}
			if (list.size() == 1) {
				return new FSBActionContext(this, list.get(0), gTree);
			}
			FSBNode[] nodes = new FSBNode[list.size()];
			list.toArray(nodes);
			return new FSBActionContext(this, nodes, gTree);
		}
		if (event != null) {
			Object source = event.getSource();
			int x = event.getX();
			int y = event.getY();
			if (source instanceof JTree) {
				JTree sourceTree = (JTree) source;
				if (gTree.isMyJTree(sourceTree)) {
					return new FSBActionContext(this, gTree.getNodeForLocation(x, y), gTree);
				}
			}
		}
		return null;
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

	void dispose() {
		if (actionManager != null) {
			actionManager.dispose();
			actionManager = null;
		}
		if (gTree != null) {
			gTree.dispose();
			gTree = null;
		}
		plugin = null;
	}
}
