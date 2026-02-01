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
package ghidra.app.plugin.core.datamgr.util;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.tree.TreePath;

import org.apache.commons.lang3.StringUtils;

import docking.DialogComponentProvider;
import docking.Tool;
import docking.widgets.filter.FilterOptions;
import docking.widgets.filter.TextFilterStrategy;
import docking.widgets.label.GDLabel;
import docking.widgets.tree.*;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.program.model.data.*;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A dialog that allows the user to choose from a tree of similarly named data types.  This class
 * is meant to be used by the {@link DataTypeManagerPlugin}.  For API needs, clients should use the 
 * {@link DataTypeSelectionDialog} utility widget.
 */
public class DataTypeChooserDialog extends DialogComponentProvider {

	private DataTypeManagerPlugin plugin;
	private DataTypeArchiveGTree tree;
	private DataType selectedDataType;
	private CategoryPath selectedCategoryPath;

	private GDLabel messageLabel;
	private boolean isFilterEditable;

	private boolean categorySelectionMode;

	public DataTypeChooserDialog(DataTypeManagerPlugin plugin) {
		super("Data Type Chooser", true, true, true, false);
		this.plugin = plugin;

		tree = new DataTypeArchiveGTree(plugin);

		tree.setEditable(false);
		tree.updateFilterForChoosingDataType();

		tree.addGTreeSelectionListener(e -> setOkEnabled(isValidNodeSelected()));

		tree.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() < 2) {
					return;
				}

				if (categorySelectionMode) {
					CategoryPath path = getCurrentCategoryPath();
					if (path == null) {
						return;
					}

					selectedCategoryPath = path;
					close();
					return;
				}

				DataTypeNode selectedNode = getSelectedDtNode();
				if (selectedNode == null) {
					return;
				}

				selectedDataType = selectedNode.getDataType();
				close();
			}
		});

		setPreferredSize(400, 400);
		addWorkPanel(createWorkPanel());
		addOKButton();
		addCancelButton();
		setOkEnabled(false);

		setHelpLocation(new HelpLocation("DataTypeEditors", "browse"));
	}

	/**
	 * Signals that this chooser is intended to pick {@link CategoryPath}s instead of data types.
	 * @param categorySelectionMode true to pick category paths
	 */
	public void setCategorySelectionMode(boolean categorySelectionMode) {
		this.categorySelectionMode = categorySelectionMode;
		if (categorySelectionMode) {
			setTitle("Category Chooser");
			messageLabel.setText("Choose a category:");
		}
		else {
			setTitle("Data Type Chooser");
			messageLabel.setText("Choose a data type:");
		}
	}

	public void setShowProgramArchiveOnly(boolean programOnly) {
		DataTypeManagerHandler handler = plugin.getDataTypeManagerHandler();
		if (programOnly) {
			DataTypeManager programDtm = handler.getProgramDataTypeManager();
			if (programDtm != null) {
				ArchiveRootNode root = new ArchiveRootNode(handler, true);
				tree.setRootNode(root);
				return;
			}
		}

		ArchiveRootNode root = new ArchiveRootNode(handler);
		tree.setRootNode(root);
	}

	private boolean isValidNodeSelected() {
		TreePath[] selectionPath = tree.getSelectionPaths();
		if (selectionPath.length != 1) {
			return false;
		}

		GTreeNode node = (GTreeNode) selectionPath[0].getLastPathComponent();
		return node instanceof DataTypeTreeNode;
	}

	private DataTypeNode getSelectedDtNode() {
		TreePath[] selectionPath = tree.getSelectionPaths();
		if (selectionPath.length != 1) {
			return null;
		}

		GTreeNode node = (GTreeNode) selectionPath[0].getLastPathComponent();
		if (node instanceof DataTypeNode dtNode) {
			return dtNode;
		}
		return null;
	}

	private CategoryNode getSelectedCategoryNode() {
		TreePath[] selectionPath = tree.getSelectionPaths();
		if (selectionPath.length != 1) {
			return null;
		}

		GTreeNode node = (GTreeNode) selectionPath[0].getLastPathComponent();
		if (node instanceof CategoryNode catNode) {
			return catNode;
		}
		return null;
	}

	@Override
	public void close() {
		tree.dispose();
		super.close();
	}

	private JComponent createWorkPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		messageLabel = new GDLabel("Choose the data type you wish to use.");
		messageLabel.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 2));
		messageLabel.getAccessibleContext().setAccessibleName("Message");
		panel.add(messageLabel, BorderLayout.NORTH);
		panel.add(this.tree, BorderLayout.CENTER);
		panel.getAccessibleContext().setAccessibleName("Data Type Chooser");
		return panel;
	}

	@Override
	protected void okCallback() {

		if (categorySelectionMode) {
			selectedCategoryPath = getCurrentCategoryPath();
		}
		else {
			DataTypeNode dtNode = getSelectedDtNode();
			selectedDataType = dtNode.getDataType();
		}

		close();
	}

	private CategoryPath getCurrentCategoryPath() {

		DataTypeNode dtNode = getSelectedDtNode();

		// the user may have picked a data type node or a category node
		if (dtNode != null) {
			return dtNode.getDataType().getCategoryPath();
		}

		CategoryNode categoryNode = getSelectedCategoryNode();
		if (categoryNode != null) {
			Category category = categoryNode.getCategory();
			return category.getCategoryPath();
		}

		return null;
	}

	/**
	 * A convenience method to show this dialog with the following configuration:
	 * <ul>
	 *  <li>the tree will be filtered using the given filter text</li>
	 *  <li>the filter field will be disabled so the user cannot change the nodes available in the 
	 *  tree</li>
	 *  <li>the first child node of the root node in the tree will be selected</li>
	 * </ul>
	 * 
	 * @param tool the tool to which this dialog will be parented; cannot be null
	 * @param dataTypeText the filter text; cannot be null
	 * @throws IllegalArgumentException if the given filter text is null or empty
	 */
	public void showPrepopulatedDialog(Tool tool, String dataTypeText) {

		if (isShowing()) {
			return;
		}

		if (StringUtils.isBlank(dataTypeText)) {
			throw new IllegalArgumentException(
				"Cannot pre-populate the data type chooser dialog with blank filter text");
		}
		tree.setFilterText(dataTypeText);
		setFilterFieldEditable(false);
		installExactMatchFilter();

		setFirstNodeSelected();
		tool.showDialog(this);
	}

	/**
	 * Sets the filter text of the tree
	 * @param filterText the filter text
	 */
	public void setFilterText(String filterText) {
		tree.setFilterText(filterText);
	}

	/**
	 * Selects the first child node of the root node.  Use this method to force the tree to have
	 * focus when the dialog is shown, which allows for keyboard navigation.
	 */
	public void setFirstNodeSelected() {
		tree.runTask(new SelectFirstNodeTask(tree));
	}

	/**
	 * Selects the given tree path in the tree
	 * @param selectedPath the path
	 */
	public void setSelectedPath(TreePath selectedPath) {
		tree.setSelectedNodeByPathName(selectedPath);
	}

	/**
	 * Sets the enabled state of the filter field.  This method can be used to prevent the user 
	 * from changing the nodes displayed by the tree.  By default, the filter is enabled.
	 * 
	 * @param editable true if the field should be editable; false to disable the field
	 */
	public void setFilterFieldEditable(boolean editable) {
		this.isFilterEditable = editable;
		tree.setFilterFieldEnabled(editable);
	}

	/**
	 * Returns the filter provider currently in use by the tree in this dialog
	 * @return the filter provider
	 */
	public GTreeFilterProvider getTreeFilterProvider() {
		return tree.getFilterProvider();
	}

	/**
	 * Sets the filter provider on the tree used by this dialog
	 * @param provider the filter provider
	 */
	public void setTreeFilterProvider(GTreeFilterProvider provider) {
		tree.setFilterProvider(provider);
	}

	public CategoryPath getSelectedCategoryPath() {
		return selectedCategoryPath;
	}

	public DataType getSelectedDataType() {
		return selectedDataType;
	}

	@Override
	public Component getFocusComponent() {
		if (isFilterEditable) {
			return tree.getFilterField();
		}
		return null; // the tree will get the default focus
	}

	private void installExactMatchFilter() {
		GTreeFilterProvider filterProvider = tree.getFilterProvider();
		if (filterProvider instanceof DefaultGTreeFilterProvider) {
			DefaultGTreeFilterProvider provider = (DefaultGTreeFilterProvider) filterProvider;
			provider.setPreferredFilterOptions(
				new FilterOptions(TextFilterStrategy.MATCHES_EXACTLY, false, false, false));
		}
	}

	private class SelectFirstNodeTask extends GTreeTask {

		protected SelectFirstNodeTask(GTree tree) {
			super(tree);
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {

			GTreeNode root = tree.getViewRoot();
			List<GTreeNode> dtNodes = new ArrayList<>();
			getDataTypeNodes(root, dtNodes);

			if (dtNodes.isEmpty()) {
				// should not happen
				return;
			}

			// pick any node
			tree.setSelectedNode(dtNodes.get(0));
		}

		private void getDataTypeNodes(GTreeNode node, List<GTreeNode> dtNodes) {

			if (node instanceof DataTypeNode) {
				dtNodes.add(node);
				return;
			}

			List<GTreeNode> children = node.getChildren();
			for (GTreeNode child : children) {
				getDataTypeNodes(child, dtNodes);
			}
		}
	}

}
