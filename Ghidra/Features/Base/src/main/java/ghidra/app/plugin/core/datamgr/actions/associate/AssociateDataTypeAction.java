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
package ghidra.app.plugin.core.datamgr.actions.associate;

import java.awt.BorderLayout;
import java.awt.Component;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.*;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GLabel;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.archive.*;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.plugin.core.datamgr.util.DataTypeTreeCopyMoveTask;
import ghidra.app.plugin.core.datamgr.util.DataTypeTreeCopyMoveTask.ActionType;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;
import ghidra.util.task.TaskLauncher;

/**
 * Allows the user to associate the selected action with a source archive.  An associate data type
 * allows users to push changes to the source archive and to pull updates from the source archive.
 */
public class AssociateDataTypeAction extends DockingAction {

	private DataTypeManagerPlugin plugin;

	public AssociateDataTypeAction(DataTypeManagerPlugin plugin) {
		super("Associate With Archive", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Associate With Archive" }, null, "Sync"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		return hasOnlyDtNodes(((DataTypesActionContext) context).getSelectedNodes());
	}

	private boolean hasOnlyDtNodes(List<GTreeNode> nodes) {
		if (nodes.isEmpty()) {
			return false;
		}
		for (GTreeNode node : nodes) {
			if (!(node instanceof DataTypeNode)) {
				return false;
			}
		}
		return true;
	}

	private boolean isAlreadyAssociated(DataTypesActionContext dtContext) {

		List<DataTypeNode> nodes = dtContext.getDisassociatableNodes();
		return !nodes.isEmpty();
	}

	private Archive getSingleDTArchive(List<GTreeNode> nodes) {

		Archive dtArchive = null;
		for (GTreeNode node : nodes) {
			Archive archive = findArchive(node);
			if (dtArchive == null) {
				dtArchive = archive;
				continue;
			}

			if (dtArchive != archive) {
				return null;
			}
		}
		return dtArchive;
	}

	private static Archive findArchive(GTreeNode node) {
		while (node != null) {
			if (node instanceof ArchiveNode) {
				return ((ArchiveNode) node).getArchive();
			}
			node = node.getParent();
		}
		return null;
	}

	private List<Archive> getDestinationArchives() {

		List<Archive> archives = plugin.getAllArchives();
		List<Archive> sourceArchives = archives.stream()
				.filter(a -> !(a instanceof ProgramArchive))
				.filter(a -> !(a instanceof BuiltInArchive))
				.sorted((a1, a2) -> a1.getName().compareToIgnoreCase(a2.getName()))
				.collect(Collectors.toList());

		return sourceArchives;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		List<GTreeNode> nodes = ((DataTypesActionContext) context).getSelectedNodes();

		Archive dtArchive = getSingleDTArchive(nodes);
		if (dtArchive == null) {
			Msg.showInfo(this, getProviderComponent(), "Multiple Data Type Archives",
				"The currently selected nodes are from multiple archives.\n" +
					"Please select only nodes from a single archvie.");
			return;
		}

		if (!dtArchive.isModifiable()) {
			DataTypeUtils.showUnmodifiableArchiveErrorMessage(context.getSourceComponent(),
				"Disassociate Failed", dtArchive.getDataTypeManager());
			return;
		}

		if (isAlreadyAssociated((DataTypesActionContext) context)) {
			Msg.showInfo(this, getProviderComponent(), "Already Associated",
				"One or more of the currently selected nodes are already associated\n" +
					"with a source archive.");
			return;
		}

		List<Archive> archives = getDestinationArchives();
		if (archives.isEmpty()) {
			Msg.showInfo(this, getProviderComponent(), "No Source Archives Open",
				"No source archives open.  Please open the desired source archive.");
			return;
		}

		ChooseArchiveDialog dialog = new ChooseArchiveDialog(archives);
		dialog.show();
		if (dialog.isCancelled()) {
			return;
		}

		Archive destinationArchive = dialog.getArchive();
		Category destinationCategory = dialog.getCategory();

		DataTypeTreeCopyMoveTask task =
			new DataTypeTreeCopyMoveTask(destinationArchive, destinationCategory, nodes,
				ActionType.COPY, plugin.getProvider().getGTree(), plugin.getConflictHandler());
		task.setPromptToAssociateTypes(false); // do not prompt the user; they have already decided
		TaskLauncher.launch(task);
	}

	private JComponent getProviderComponent() {
		return plugin.getProvider().getComponent();
	}

	private class ChooseArchiveDialog extends DialogComponentProvider {

		private Category category;
		private Archive archive;

		// default to true to handle the case the user presses Escape or presses the x button
		private boolean isCancelled = true;

		private GhidraComboBox<Archive> archivesBox = new GhidraComboBox<>();
		private JTextField categoryField = new JTextField(20);

		ChooseArchiveDialog(List<Archive> archives) {
			super("Choose New Source Archive", true);

			addWorkPanel(buildWorkPanel());

			archivesBox.addToModel(archives);
			categoryField.setText("/");

			addOKButton();
			addCancelButton();
		}

		private JComponent buildWorkPanel() {

			archivesBox.setRenderer(new DefaultListCellRenderer() {

				@Override
				public Component getListCellRendererComponent(JList<?> list, Object value,
						int index, boolean isSelected, boolean cellHasFocus) {

					JLabel renderer = (JLabel) super.getListCellRendererComponent(list, value,
						index, isSelected, cellHasFocus);
					Archive a = (Archive) value;
					renderer.setText(a.getName());
					return renderer;
				}

			});

			JPanel panel = new JPanel(new BorderLayout());

			JPanel archivePanel = new JPanel(new PairLayout());
			archivePanel.add(new GLabel("New Source Archive: "));
			archivePanel.add(archivesBox);

			JPanel categoryPanel = new JPanel(new PairLayout());
			categoryPanel.add(new GLabel("Destination Category: "));
			categoryPanel.add(categoryField);

			panel.add(archivePanel, BorderLayout.NORTH);
			panel.add(categoryPanel, BorderLayout.SOUTH);

			return panel;
		}

		@Override
		protected void okCallback() {

			clearStatusText();

			archive = (Archive) archivesBox.getSelectedItem();
			if (archive == null) {
				setStatusText("Please choose an archive");
				return;
			}

			if (!archive.isModifiable()) {
				setStatusText(
					"Archive is not modifiable. You must first open this archive for edit.");
				return;
			}

			if (!updateCategory()) {
				return;
			}

			isCancelled = false;
			close();
		}

		private boolean updateCategory() {

			String categoryText = categoryField.getText();
			if (StringUtils.isBlank(categoryText)) {
				setStatusText("Category must be specified.  Use '/' for the root.");
				return false;
			}

			DataTypeManager dtm = archive.getDataTypeManager();
			CategoryPath categoryPath = new CategoryPath(categoryText);
			category = dtm.getCategory(categoryPath);
			if (category != null) {
				return true;
			}

			int choice = OptionDialog.showYesNoDialog(null, "Create Category?",
				"Category '" + categoryText + "' does not exist.  Create it now?");
			if (choice != OptionDialog.YES_OPTION) {
				setStatusText("Category does not exist");
				return false;
			}

			boolean noErrors = false;
			int tx = dtm.startTransaction("Create Category");
			try {
				category = dtm.createCategory(categoryPath);
				noErrors = true;
			}
			finally {
				dtm.endTransaction(tx, noErrors);
			}

			if (category == null) {
				setStatusText("Unable to create category");
				return false;
			}
			return true;
		}

		@Override
		protected void cancelCallback() {
			super.cancelCallback();
		}

		boolean isCancelled() {
			return isCancelled;
		}

		void show() {
			JComponent parent = getProviderComponent();
			DockingWindowManager.showDialog(parent, this);
		}

		Archive getArchive() {
			return archive;
		}

		Category getCategory() {
			return category;
		}

	}

}
