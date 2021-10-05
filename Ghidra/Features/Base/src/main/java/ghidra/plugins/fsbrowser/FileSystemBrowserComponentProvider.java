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
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import docking.WindowPosition;
import docking.event.mouse.GMouseListenerAdapter;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeRenderer;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.TextEditorService;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.plugin.importer.ProgramMappingService;
import ghidra.program.model.listing.Program;
import ghidra.util.*;

/**
 * Plugin component provider for the {@link FileSystemBrowserPlugin}.
 * <p>
 * An instance of this class is created for each file system browser window (w/tree).
 * <p>
 * Visible to just this package.
 */
class FileSystemBrowserComponentProvider extends ComponentProviderAdapter
		implements FileSystemEventListener {
	private static final String TITLE = "Filesystem Viewer";

	private FileSystemBrowserPlugin plugin;
	private FSBActionManager actionManager;
	private GTree gTree;
	private FSBRootNode rootNode;
	private FileSystemService fsService = FileSystemService.getInstance();

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
		gTree.addMouseListener(new GMouseListenerAdapter() {
			@Override
			public void doubleClickTriggered(MouseEvent e) {
				handleDoubleClick(gTree.getNodeForLocation(e.getX(), e.getY()));
				e.consume();
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

				if (value instanceof FSBRootNode) {
					renderFS((FSBRootNode) value, selected);
				}
				else if (value instanceof FSBDirNode) {
					// do nothing special
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

				String importOverlay = ProgramMappingService.isFileImportedIntoProject(fsrl)
						? FileIconService.OVERLAY_IMPORTED
						: null;
				String mountedOverlay = fsService.isFilesystemMountedAt(fsrl)
						? FileIconService.OVERLAY_FILESYSTEM
						: null;

				String missingPasswordOverlay = node.hasMissingPassword()
						? FileIconService.OVERLAY_MISSING_PASSWORD
						: null;

				Icon ico = FileIconService.getInstance()
						.getImage(filename, importOverlay, mountedOverlay, missingPasswordOverlay);
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

		fsRef.getFilesystem().getRefManager().addListener(this);
	}

	/**
	 * For testing access only.
	 *
	 * @return this provider's GTree.
	 */
	GTree getGTree() {
		return gTree;
	}

	FSRL getFSRL() {
		return rootNode != null ? rootNode.getFSRL() : null;
	}

	FSBActionManager getActionManager() {
		return actionManager;
	}

	void dispose() {
		if (rootNode != null && rootNode.getFSRef() != null && !rootNode.getFSRef().isClosed()) {
			rootNode.getFSRef().getFilesystem().getRefManager().removeListener(this);
		}
		removeFromTool();
		if (actionManager != null) {
			actionManager.dispose();
			actionManager = null;
		}
		if (gTree != null) {
			gTree.dispose(); // calls dispose() on tree's rootNode, which will release the fsRefs
			gTree = null;
		}
		rootNode = null;
		plugin = null;
	}

	@Override
	public void componentHidden() {
		// if the component is 'closed', nuke ourselves
		if (plugin != null) {
			plugin.removeFileSystemBrowserComponent(this);
			dispose();
		}
	}

	public void afterAddedToTool() {
		actionManager.registerComponentActionsInTool();
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
				updatePasswordStatus(node);
			}
		}
	}

	private void updatePasswordStatus(FSBFileNode node) {
		// currently this is the only state that might change
		// and that effect the node display
		if (node.hasMissingPassword()) {
			// check and see if its status has changed
			gTree.runTask(monitor -> {
				if (node.needsFileAttributesUpdate(monitor)) {
					actionManager.doRefreshInfo(List.of(node), monitor);
				}
			});
		}
	}

	private void handleDoubleClick(GTreeNode clickedNode) {
		if (clickedNode instanceof FSBFileNode && clickedNode.isLeaf()) {
			FSBFileNode node = (FSBFileNode) clickedNode;

			if (node.getFSRL() != null && !quickShowProgram(node.getFSRL())) {
				actionManager.actionOpenPrograms.actionPerformed(getActionContext(null));
			}
		}
	}

	/*****************************************/

	@Override
	public FSBActionContext getActionContext(MouseEvent event) {
		return new FSBActionContext(this, getSelectedNodes(event), event, gTree);
	}

	private FSBNode[] getSelectedNodes(MouseEvent event) {
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		List<FSBNode> list = new ArrayList<>(selectionPaths.length);
		for (TreePath selectionPath : selectionPaths) {
			Object lastPathComponent = selectionPath.getLastPathComponent();
			if (lastPathComponent instanceof FSBNode) {
				list.add((FSBNode) lastPathComponent);
			}
		}
		if (list.isEmpty() && event != null) {
			Object source = event.getSource();
			int x = event.getX();
			int y = event.getY();
			if (source instanceof JTree) {
				JTree sourceTree = (JTree) source;
				if (gTree.isMyJTree(sourceTree)) {
					GTreeNode nodeAtEventLocation = gTree.getNodeForLocation(x, y);
					if (nodeAtEventLocation != null && nodeAtEventLocation instanceof FSBNode) {
						list.add((FSBNode) nodeAtEventLocation);
					}
				}
			}
		}
		return list.toArray(FSBNode[]::new);
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

}
