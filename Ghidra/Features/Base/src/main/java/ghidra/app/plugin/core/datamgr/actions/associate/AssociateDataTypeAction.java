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
import java.util.Collection;
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
import docking.widgets.list.GComboBoxCellRenderer;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.archive.BuiltInSourceArchive;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.plugin.core.datamgr.util.DataTypesCopyMoveTask;
import ghidra.app.plugin.core.datamgr.util.DataTypesCopyMoveTask.ActionType;
import ghidra.program.model.data.*;
import ghidra.program.model.dtarchive.DataTypeStore;
import ghidra.program.model.dtarchive.PersistentDataTypeArchive;
import ghidra.program.model.listing.Program;
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

		setPopupMenuData(new MenuData(new String[] { "Associate With Archive..." }, null, "Sync"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {

		if (!(context instanceof DataTypeContext dtContext)) {
			return false;
		}

		return dtContext.hasSelectedDataTypes();
	}

	private boolean isAlreadyAssociated(DataTypeContext dtc) {
		List<DataType> types = dtc.getSelectedDataTypes();
		for (DataType dt : types) {
			if (isDisassociatable(dt)) {
				return true;
			}
		}
		return false;
	}

	private boolean isDisassociatable(DataType dt) {
		DataTypeManager dataTypeManager = dt.getDataTypeManager();
		SourceArchive sourceArchive = dt.getSourceArchive();
		if (sourceArchive == null || dataTypeManager == null ||
			sourceArchive.equals(BuiltInSourceArchive.INSTANCE) ||
			sourceArchive.getSourceArchiveID().equals(dataTypeManager.getUniversalID())) {
			return false;
		}
		return true;
	}

	private DataTypeStore getSingleDataTypeStore(Collection<DataType> types) {

		DataTypeStore store = null;
		for (DataType dt : types) {

			DataTypeManager dtm = dt.getDataTypeManager();
			DataTypeStore dataStore = dtm.getDataStore();
			if (store == null) {
				store = dataStore;
				continue;
			}

			if (store != dataStore) {
				return null;
			}
		}
		return store;
	}

	private List<PersistentDataTypeArchive> getDestinationArchives(DataTypeStore excluded) {
		ArchiveManager archiveManager = plugin.getArchiveManager();
		List<PersistentDataTypeArchive> archives = archiveManager.getOpenArchives();
		List<PersistentDataTypeArchive> destArchives = archives.stream()
				.filter(a -> !a.equals(excluded))
				.sorted((a1, a2) -> a1.getName().compareToIgnoreCase(a2.getName()))
				.collect(Collectors.toList());

		return destArchives;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		DataTypeContext dtContext = (DataTypeContext) context;

		List<DataType> types = dtContext.getSelectedDataTypes();
		DataTypeStore dtStore = getSingleDataTypeStore(types);

		// NOTE: We only support program-to-archive since other cases become rather complicated
		// when considering dependencies that must get copied and how their associations should be 
		// handled.
		if (!(dtStore instanceof Program)) {
			if (types.isEmpty()) {
				Msg.showInfo(this, null, "Cannot Associate Types",
					"Can only associate types from the program");
				return;
			}
		}

		if (!dtStore.isChangeable()) {
			DataTypeUtils.showUnmodifiableArchiveErrorMessage(context.getSourceComponent(),
				"Disassociate Failed", dtStore.getDataTypeManager());
			return;
		}

		Component component = context.getSourceComponent();
		if (isAlreadyAssociated(dtContext)) {
			Msg.showInfo(this, component, "Already Associated",
				"One or more of the currently selected nodes are already associated\n" +
					"with a source archive.");
			return;
		}

		List<PersistentDataTypeArchive> archives = getDestinationArchives(dtStore);
		if (archives.isEmpty()) {
			Msg.showInfo(this, component, "No Source Archives Open",
				"No source archives open.  Please open the desired source archive.");
			return;
		}

		ChooseArchiveDialog dialog = new ChooseArchiveDialog(archives);
		dialog.show(component);
		if (dialog.isCancelled()) {
			return;
		}

		PersistentDataTypeArchive destinationArchive = dialog.getArchive();
		Category destinationCategory = dialog.getCategory();

		DataTypesCopyMoveTask task =
			new DataTypesCopyMoveTask(plugin, destinationArchive, destinationCategory, types, null,
				ActionType.COPY);

		task.setPromptToAssociateTypes(false); // do not prompt the user; they have already decided
		TaskLauncher.launch(task);
	}

	private class ChooseArchiveDialog extends DialogComponentProvider {

		private Category category;
		private PersistentDataTypeArchive archive;

		// default to true to handle the case the user presses Escape or presses the x button
		private boolean isCancelled = true;

		private GhidraComboBox<PersistentDataTypeArchive> archivesBox = new GhidraComboBox<>();
		private JTextField categoryField = new JTextField(20);

		ChooseArchiveDialog(List<PersistentDataTypeArchive> archives) {
			super("Choose New Source Archive", true);

			addWorkPanel(buildWorkPanel());

			archivesBox.addToModel(archives);
			categoryField.setText("/");

			addOKButton();
			addCancelButton();
		}

		private JComponent buildWorkPanel() {

			archivesBox.setRenderer(new GComboBoxCellRenderer<>() {

				@Override
				public Component getListCellRendererComponent(
						JList<? extends PersistentDataTypeArchive> list,
						PersistentDataTypeArchive value, int index, boolean isSelected,
						boolean cellHasFocus) {

					JLabel renderer = (JLabel) super.getListCellRendererComponent(list, value,
						index, isSelected, cellHasFocus);
					PersistentDataTypeArchive a = value;
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

			archive = archivesBox.getSelectedItem();
			if (archive == null) {
				setStatusText("Please choose an archive");
				return;
			}

			if (!archive.isChangeable()) {
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
			String path = archive.getName() + categoryPath;
			int tx = dtm.startTransaction("Create " + path);
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

		void show(Component parent) {
			DockingWindowManager.showDialog(parent, this);
		}

		PersistentDataTypeArchive getArchive() {
			return archive;
		}

		Category getCategory() {
			return category;
		}

	}

}
