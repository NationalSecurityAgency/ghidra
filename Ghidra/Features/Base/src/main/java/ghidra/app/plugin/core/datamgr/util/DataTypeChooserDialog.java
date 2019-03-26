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

import javax.swing.*;
import javax.swing.tree.TreePath;

import docking.DialogComponentProvider;
import docking.widgets.filter.FilterOptions;
import docking.widgets.filter.TextFilterStrategy;
import docking.widgets.tree.*;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.program.model.data.DataType;
import ghidra.util.HTMLUtilities;

/**
 * A dialog that allows the user to choose from a tree of similarly named data types.
 */
public class DataTypeChooserDialog extends DialogComponentProvider {
	private DataTypeArchiveGTree tree;
	private DataType selectedDataType;
	private JLabel messageLabel;

	/** when false, the user is required to pick from a restricted set */
	private boolean isEditable;

	public DataTypeChooserDialog(DataTypeManagerPlugin plugin) {
		super("Data Type Chooser", true, true, true, false);

		tree = new DataTypeArchiveGTree(plugin);
		tree.setEditable(false);

		tree.addGTreeSelectionListener(e -> setOkEnabled(getSelectedNode() != null));

		tree.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() < 2) {
					return;
				}

				DataTypeNode selectedNode = getSelectedNode();
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
	}

	private DataTypeNode getSelectedNode() {
		TreePath[] selectionPath = tree.getSelectionPaths();
		if (selectionPath.length != 1) {
			return null;
		}

		GTreeNode node = (GTreeNode) selectionPath[0].getLastPathComponent();
		if (!(node instanceof DataTypeNode)) {
			return null;
		}

		return (DataTypeNode) node;
	}

	@Override
	public void close() {
		tree.dispose();
		super.close();
	}

	private JComponent createWorkPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		String message = "Choose the data type you wish to use.";
		messageLabel = new JLabel(message);
		messageLabel.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 2));
		panel.add(messageLabel, BorderLayout.NORTH);
		panel.add(this.tree, BorderLayout.CENTER);

		return panel;
	}

	@Override
	protected void okCallback() {
		// can't be null since we control button enablement
		DataTypeNode dataTypeNode = getSelectedNode();
		selectedDataType = dataTypeNode.getDataType();
		close();
	}

	public void setFilterText(String filterText) {
		boolean editable = (filterText == null);
		if (!editable) {
			tree.setFilterText(filterText);
		}
		setEditable(editable);
		setMessageLabel();
	}

	public void setSelectedPath(TreePath selectedPath) {
		tree.setSelectedNodeByPathName(selectedPath);
	}

	private void setMessageLabel() {
		String message = "Choose the data type you wish to use.";

// TODO this message doesn't make sense in all use cases.  If we want this or other messages,
//		then we need to be able to set them.
//		if (!isEditable) {
//			message =
//				"Multiple data types exist named \"" +
//					((FilterTextField) tree.getFilterField()).getText() + "\".\n" + message;
//		}
		messageLabel.setText(HTMLUtilities.wrapAsHTML(message));
	}

	@Override
	public Component getFocusComponent() {
		return tree.getFilterField();
	}

	private void setEditable(boolean editable) {
		tree.setFilterFieldEnabled(editable);

		if (!editable) {
			GTreeFilterProvider filterProvider = tree.getFilterProvider();
			if (filterProvider instanceof DefaultGTreeFilterProvider) {
				DefaultGTreeFilterProvider provider = (DefaultGTreeFilterProvider) filterProvider;
				provider.setFilterOptions(
					new FilterOptions(TextFilterStrategy.MATCHES_EXACTLY, false, false, false));
			}
		}
	}

	public DataType getSelectedDataType() {
		return selectedDataType;
	}
}
