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
package ghidra.app.plugin.core.datamgr.tree;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.*;
import javax.swing.event.TreeExpansionEvent;
import javax.swing.event.TreeExpansionListener;
import javax.swing.tree.TreePath;

import docking.widgets.tree.*;
import docking.widgets.tree.internal.DefaultGTreeDataTransformer;
import docking.widgets.tree.support.GTreeRenderer;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.plugin.core.datamgr.archive.FileArchive;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.util.UniversalID;
import ghidra.util.task.TaskMonitor;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.TranslateIcon;

public class DataTypeArchiveGTree extends GTree {
	private static ImageIcon LOCAL_DELTA_ICON =
		ResourceManager.loadImage("images/smallRightArrow.png");
	private static ImageIcon SOURCE_DELTA_ICON =
		ResourceManager.loadImage("images/smallLeftArrow.png");
	private static ImageIcon CONFLICT_ICON = ResourceManager.loadImage("images/doubleArrow.png");
	private static ImageIcon MISSING_ICON = ResourceManager.loadImage("images/redQuestionMark.png");

	private DataTypeManagerPlugin plugin;
	private GTreeNode armedNode;
	private MyFolderListener folderListener;
	private DataTypeTreeExpansionListener cleanupListener = new DataTypeTreeExpansionListener();

	public DataTypeArchiveGTree(DataTypeManagerPlugin dataTypeManagerPlugin) {
		super(new ArchiveRootNode(dataTypeManagerPlugin.getDataTypeManagerHandler()));

		this.plugin = dataTypeManagerPlugin;
		setDragNDropHandler(new DataTypeDragNDropHandler(plugin, this));
		DataTypeTreeRenderer renderer = new DataTypeTreeRenderer();

		// setting the row height may provide speed improvements, as the tree does not have to
		// ask for the height for each cell from the renderer.
		setRowHeight(getHeight(getViewRoot(), renderer));
		setCellRenderer(renderer);
		Project project = plugin.getTool().getProject();
		if (project != null) {
			ProjectData projectData = project.getProjectData();
			if (projectData != null) {
				folderListener = new MyFolderListener();
				projectData.addDomainFolderChangeListener(folderListener);
			}
		}

		addTreeExpansionListener(cleanupListener);
	}

	private int getHeight(GTreeNode rootNode, DataTypeTreeRenderer renderer) {
		Component c = renderer.getTreeCellRendererComponent(getJTree(), rootNode, false, false,
			false, 0, false);
		Dimension size = c.getPreferredSize();
		return size.height;
	}

	@Override
	public void expandedStateRestored(TaskMonitor monitor) {
		// walk all of our nodes and reclaim any that aren't expanded
		GTreeNode rootNode = getViewRoot();
		if (rootNode == null) {
			return; // in a state of flux; been disposed
		}

		monitor.setMessage("Recycling unused tree nodes");
		monitor.initialize(rootNode.getLeafCount());
		reclaimClosedNodes(rootNode, monitor);
	}

	private void reclaimClosedNodes(GTreeNode node, TaskMonitor monitor) {

		if (monitor.isCancelled()) {
			return;
		}

		if (!isExpanded(node.getTreePath())) {
			int leafCount = node.getLeafCount();
			if (node instanceof GTreeLazyNode) {
				((GTreeLazyNode) node).unloadChildren();
			}
			monitor.incrementProgress(leafCount);
			return;
		}

		List<GTreeNode> children = node.getChildren();
		for (GTreeNode child : children) {
			reclaimClosedNodes(child, monitor);
		}
	}

	@Override
	public void dispose() {
		((ArchiveRootNode) getModelRoot()).dispose();
		PluginTool tool = plugin.getTool();
		if (tool == null) {
			return; // this can happen when the plugin is disposed off the swing thread
		}

		Project project = tool.getProject();
		if (project == null) {
			return;
		}

		ProjectData projectData = project.getProjectData();
		if (projectData != null) {
			projectData.removeDomainFolderChangeListener(folderListener);
		}
		super.dispose();
	}

	public void enableArrayFilter(boolean enabled) {
		ArchiveRootNode root = (ArchiveRootNode) getModelRoot();
		root.setFilterArray(enabled);
		reloadTree();
	}

	public void enablePointerFilter(boolean enabled) {
		ArchiveRootNode root = (ArchiveRootNode) getModelRoot();
		root.setFilterPointer(enabled);
		reloadTree();
	}

	public void setIncludeDataTypeMembersInSearch(boolean includeDataTypes) {
		setDataTransformer(
			includeDataTypes ? new DataTypeTransformer() : new DefaultGTreeDataTransformer());
		reloadTree();
	}

	public Program getProgram() {
		return plugin.getProgram();
	}

	private void reloadTree() {
		GTreeState treeState = getTreeState();

		ArchiveRootNode rootNode = (ArchiveRootNode) getModelRoot();
		rootNode.unloadChildren();
		updateModelFilter();
		restoreTreeState(treeState);
	}

	@Override
	public void setNodeEditable(GTreeNode node) {
		armedNode = node;
	}

	@Override
	public boolean isPathEditable(TreePath path) {
		boolean isArmed = path.getLastPathComponent() == armedNode;
		armedNode = null;
		if (isArmed) {
			return super.isPathEditable(path);
		}
		return false;
	}

	@Override
	public String getToolTipText(MouseEvent event) {
		Point point = event.getPoint();
		GTreeNode node = getNodeForLocation(point.x, point.y);
		String customTip = getToolTipTextForNode(node);
		if (customTip != null) {
			return customTip;
		}

		return super.getToolTipText(event);
	}

	private String getToolTipTextForNode(GTreeNode node) {
		if (!(node instanceof DataTypeNode)) {
			return null;
		}

		DataTypeNode dataTypeNode = (DataTypeNode) node;
		DataType dataType = dataTypeNode.getDataType();

		SourceArchive sourceArchive = dataType.getSourceArchive();
		if (!hasOtherSourceArchive(dataType, sourceArchive)) {
			return null;
		}

		DataTypeManagerHandler handler = plugin.getDataTypeManagerHandler();
		DataTypeSyncState status = DataTypeSynchronizer.getSyncStatus(handler, dataType);
		switch (status) {
			case CONFLICT:
			case UPDATE:
			case COMMIT:
				return DataTypeSynchronizer.getDiffToolTip(handler, dataType);
			case ORPHAN:
			case UNKNOWN:
			case IN_SYNC:
			default:
				return null;
		}
	}

	private boolean hasOtherSourceArchive(DataType dataType, SourceArchive sourceArchive) {
		if (sourceArchive == null) {
			return false;
		}

		if (sourceArchive.getArchiveType().isBuiltIn()) {
			return false;
		}

		UniversalID localID = dataType.getDataTypeManager().getUniversalID();
		return !sourceArchive.getSourceArchiveID().equals(localID);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class DataTypeTransformer extends DefaultGTreeDataTransformer {

		@Override
		public List<String> transform(GTreeNode node) {
			List<String> results = super.transform(node);
			if (!(node instanceof DataTypeNode)) {
				return results;
			}
			DataTypeNode dataTypeNode = (DataTypeNode) node;
			DataType dataType = dataTypeNode.getDataType();

			if (dataType instanceof Enum) {
				addEnumStrings((Enum) dataType, results);
			}
			else if (dataType instanceof Composite) {
				addCompositeStrings((Composite) dataType, results);
			}
			else if (dataType instanceof FunctionDefinition) {
				addFunctionDefinitionStrings((FunctionDefinition) dataType, results);
			}

			return results;
		}

		private void addFunctionDefinitionStrings(FunctionDefinition function,
				List<String> results) {
			// the prototype string will include name, return type and parameter 
			// data types and names...so use that, unless it turns out to be bad
			results.add(function.getPrototypeString());

		}

		private void addCompositeStrings(Composite composite, List<String> results) {
			DataTypeComponent[] components = composite.getDefinedComponents();
			for (DataTypeComponent component : components) {
				String fieldName = component.getFieldName();
				if (fieldName != null) {
					results.add(fieldName);
				}
				DataType compDataType = component.getDataType();
				results.add(compDataType.getName());
			}
		}

		private void addEnumStrings(Enum enumm, List<String> results) {
			for (String valueName : enumm.getNames()) {
				results.add(valueName);
			}

			for (long value : enumm.getValues()) {
				results.add(Long.toString(value));
				results.add("0x" + Long.toHexString(value));
			}
		}
	}

	private class DataTypeTreeExpansionListener implements TreeExpansionListener {

		@Override
		public void treeCollapsed(TreeExpansionEvent event) {
			if (isFiltered()) {
				return;
			}
			TreePath path = event.getPath();
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if ((node instanceof CategoryNode)) {
				CategoryNode categoryNode = (CategoryNode) node;
				categoryNode.setChildren(null);
			}
		}

		@Override
		public void treeExpanded(TreeExpansionEvent event) {
			// don't care
		}
	}

	private class DataTypeTreeRenderer extends GTreeRenderer {
		private static final int ICON_WIDTH = 24;
		private static final int ICON_HEIGHT = 18;

		@Override
		public Component getTreeCellRendererComponent(JTree tree, Object value, boolean isSelected,
				boolean expanded, boolean leaf, int row, boolean focus) {
			JLabel label = (JLabel) super.getTreeCellRendererComponent(tree, value, isSelected,
				expanded, leaf, row, focus);

			// Background icon uses the label's color so set it to match the 
			// tree's background. Otherwise the icon's in the tree might have a 
			// different background and look odd.
			MultiIcon multiIcon = new MultiIcon(new BackgroundIcon(ICON_WIDTH, ICON_HEIGHT, false));

			Icon icon = getIcon();
			multiIcon.addIcon(new CenterVerticalIcon(icon, ICON_HEIGHT));

			if (value instanceof DataTypeNode) {
				String displayText = ((DataTypeNode) value).getDisplayText();
				label.setText(displayText);
			}
			else if (value instanceof DomainFileArchiveNode) {
				DomainFileArchiveNode node = (DomainFileArchiveNode) value;
				String info = node.getDomainObjectInfo();
				if (info.length() > 0) {
					label.setText(label.getText() + info);
				}
			}

			decorateWithArchiveCharacteristics(value, label, multiIcon);

			if (value instanceof ArchiveNode) {
				updateIconForChangeIndicator((ArchiveNode) value, multiIcon);
			}

			setIcon(multiIcon);

			return label;
		}

		private void decorateWithArchiveCharacteristics(Object value, JLabel label,
				MultiIcon multiIcon) {

			if (value instanceof FileArchiveNode) {
				FileArchiveNode archiveNode = (FileArchiveNode) value;
				FileArchive archive = (FileArchive) archiveNode.getArchive();
				if (archive.isChanged()) {
					label.setText(label.getText() + " *");
				}

				return;
			}

			if (!(value instanceof DataTypeNode)) {
				return;
			}

			DataTypeNode dataTypeNode = (DataTypeNode) value;
			DataType dataType = dataTypeNode.getDataType();

			SourceArchive sourceArchive = dataType.getSourceArchive();
			if (!hasOtherSourceArchive(dataType, sourceArchive)) {
				return;
			}

			DataTypeManagerHandler handler = plugin.getDataTypeManagerHandler();
			DataTypeSyncState status = DataTypeSynchronizer.getSyncStatus(handler, dataType);
			switch (status) {
				case CONFLICT:
					multiIcon.addIcon(new TranslateIcon(CONFLICT_ICON, 10, 5));
					break;
				case UPDATE:
					multiIcon.addIcon(new TranslateIcon(SOURCE_DELTA_ICON, 14, 5));
					break;
				case COMMIT:
					multiIcon.addIcon(new TranslateIcon(LOCAL_DELTA_ICON, 14, 5));
					break;
				case ORPHAN:
					multiIcon.addIcon(new TranslateIcon(MISSING_ICON, 10, 4));
					break;
				case UNKNOWN:
				case IN_SYNC:
					break;
			}
		}

		private void updateIconForChangeIndicator(ArchiveNode node, MultiIcon multiIcon) {
			DataTypeManager dtm = node.getArchive().getDataTypeManager();
			if (dtm == null) {
				return; // for InvalidArchiveNodes
			}

			List<SourceArchive> sourceArchives = dtm.getSourceArchives();
			if (sourceArchives.isEmpty()) {
				return;
			}

			boolean hasLocalChanges = checkForLocalChanges(sourceArchives);
			boolean hasUpdatesAvailable = checkforUpdates(sourceArchives);
			if (hasLocalChanges && hasUpdatesAvailable) {
				multiIcon.addIcon(new TranslateIcon(CONFLICT_ICON, 6, 9));
			}
			else if (hasLocalChanges) {
				multiIcon.addIcon(new TranslateIcon(LOCAL_DELTA_ICON, 6, 9));
			}
			else if (hasUpdatesAvailable) {
				multiIcon.addIcon(new TranslateIcon(SOURCE_DELTA_ICON, 6, 9));
			}
		}

		private boolean checkforUpdates(List<SourceArchive> sourceArchives) {
			for (SourceArchive sourceArchive : sourceArchives) {
				DataTypeManager sourceDTM =
					plugin.getDataTypeManagerHandler().getDataTypeManager(sourceArchive);
				if (sourceDTM != null &&
					sourceArchive.getLastSyncTime() != sourceDTM.getLastChangeTimeForMyManager()) {
					return true;
				}
			}
			return false;
		}

		private boolean checkForLocalChanges(List<SourceArchive> sourceArchives) {
			for (SourceArchive sourceArchive : sourceArchives) {
				if (sourceArchive.isDirty()) {
					return true;
				}
			}
			return false;
		}

	}

	private class MyFolderListener extends DomainFolderListenerAdapter {

		@Override
		public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
			List<GTreeNode> archiveNodes = getModelRoot().getChildren();
			for (GTreeNode treeNode : archiveNodes) {
				if (treeNode instanceof ProjectArchiveNode) {
					ProjectArchiveNode projectArchiveNode = (ProjectArchiveNode) treeNode;
					DomainFile nodesDomainFile = projectArchiveNode.getDomainFile();
					if (file.equals(nodesDomainFile)) {
						projectArchiveNode.nodeChanged();
						return;
					}
				}
			}
		}

		@Override
		public void domainFileRemoved(DomainFolder parentFolder, String name, String fileID) {
			// DT What if anything needs to be done here?
		}
	}
}
