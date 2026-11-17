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
package ghidra.framework.plugintool;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import docking.DialogComponentProvider;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.list.GListCellRenderer;
import docking.widgets.list.ListPanel;
import generic.theme.GThemeDefaults.Colors;
import ghidra.framework.main.SelectPanel;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.TransactionInfo;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import resources.Icons;
import resources.ResourceManager;

/**
 * A dialog that allows users to choose which {@link PluginSaveable}s to save.
 */
public class SavePluginDataDialog extends DialogComponentProvider {

	private static final SaveableComparator COMPARATOR = new SaveableComparator();

	private List<PluginSaveable> saveables;

	private JPanel mainPanel;
	private ListPanel<SaveableRowObject> listPanel;
	private JButton saveButton;
	private JButton dontSaveButton;
	private boolean cancelled;

	/**
	 * Constructor used when multiple unrelated tools need to be queried for saveables, such as when
	 * exiting the main application.
	 * @param tools the tools
	 */
	public SavePluginDataDialog(List<PluginTool> tools) {
		super("Choose Data to Save", true);

		List<PluginSaveable> allSaveables = PluginSaveable.getSaveablesFromAllTools(tools);
		this.saveables = allSaveables;
		init();
	}

	/**
	 * Constructor for individual tools prompting the user to save, such as when closing a single 
	 * tool, but not the application.
	 * @param saveables the items to be saved
	 */
	public SavePluginDataDialog(Set<PluginSaveable> saveables) {

		super("Choose Data to Save", true);
		this.saveables = new ArrayList<>(saveables);
		init();
	}

	private void init() {
		setHelpLocation(new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Save_All"));

		mainPanel = createPanel();
		addWorkPanel(mainPanel);

		saveButton = new JButton("Save");
		saveButton.setMnemonic('S');
		addButton(saveButton);
		saveButton.addActionListener(evt -> okCallback());

		dontSaveButton = new JButton("Don't Save");
		dontSaveButton.setMnemonic('n');
		dontSaveButton.addActionListener(evt -> {
			deselectAll();
			close();
		});
		addButton(dontSaveButton);
		addCancelButton();
		setFocusComponent(saveButton);

		this.saveables.sort(COMPARATOR);

		initList();

		setMinimumSize(600, 300);
	}

	public boolean showAndSave(PluginTool tool) {

		if (saveables.isEmpty()) {
			return true; // nothing to do
		}

		tool.showDialog(this);
		if (isCancelled()) {
			return false;
		}

		List<PluginSaveable> toSave = getSelectedSaveables();
		if (toSave.isEmpty()) {
			return true; // nothing selected to save or 'Don't Save' was chosen
		}

		SaveableTask task = new SaveableTask(toSave);
		TaskLauncher.launch(task);

		if (!task.didSaveAll()) {
			return false; // could not save all selected saveables
		}

		// handle any read-only files that the user could not select
		boolean cancel = shouldCancelForReadOnlyFiles(tool, saveables);
		if (cancel) {
			return false; // cancelled on read-only prompt
		}
		return true;
	}

	public List<PluginSaveable> getAllSaveables() {
		return saveables;
	}

	private List<PluginSaveable> getSelectedSaveables() {
		List<PluginSaveable> results = new ArrayList<>();
		List<SaveableRowObject> values = listPanel.getValues();
		for (SaveableRowObject rowObject : values) {
			if (rowObject.isSelected()) {
				results.add(rowObject.getSaveable());
			}
		}
		return results;
	}

	public boolean isCancelled() {
		return cancelled;
	}

	@Override
	protected void cancelCallback() {
		cancelled = true;
		super.cancelCallback();
	}

	@Override
	protected void okCallback() {
		close();
	}

	private JPanel createPanel() {

		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		JPanel parentPanel = new JPanel(new BorderLayout());

		SelectPanel myButtonPanel = new SelectPanel(e -> selectAll(), e -> deselectAll());

		listPanel = new ListPanel<>();
		listPanel.setCellRenderer(new DataCellRenderer());
		listPanel.setMouseListener(new ListMouseListener());
		listPanel.setKeyListener(new ListKeyListener());

		parentPanel.add(myButtonPanel, BorderLayout.EAST);
		parentPanel.add(listPanel, BorderLayout.CENTER);
		parentPanel.setBorder(new TitledBorder("Data"));

		panel.add(parentPanel, BorderLayout.CENTER);
		return panel;
	}

	private void selectAll() {

		clearStatusText();

		List<SaveableRowObject> values = listPanel.getValues();
		for (SaveableRowObject rowObject : values) {
			rowObject.setSelected(true);
		}
		listPanel.repaint();
	}

	private void deselectAll() {
		List<SaveableRowObject> values = listPanel.getValues();
		for (SaveableRowObject rowObject : values) {
			rowObject.setSelected(false);
		}
		listPanel.repaint();
		listPanel.repaint();
	}

	private void updateYesButton() {
		List<SaveableRowObject> rowObjects = listPanel.getValues();
		boolean checked = rowObjects.stream().anyMatch(r -> r.isSelected());
		saveButton.setEnabled(checked);
	}

	private void initList() {

		SaveableRowObject[] array = saveables.stream()
				.map(s -> new SaveableRowObject(s))
				.toArray(SaveableRowObject[]::new);
		listPanel.setListData(array);

		updateYesButton();
	}

//=================================================================================================
// Static Methods
//=================================================================================================	

	private static boolean shouldCancelForReadOnlyFiles(PluginTool tool,
			List<PluginSaveable> allSaveables) {

		Set<PluginSaveable> readOnly = new HashSet<>();
		for (PluginSaveable saveable : allSaveables) {
			if (saveable.isReadOnly()) {
				readOnly.add(saveable);
			}
		}

		if (readOnly.isEmpty()) {
			return false;
		}

		StringBuilder sb = new StringBuilder();
		sb.append("The following files are 'read-only' and cannot be saved.\n" +
			"You must perform a manual 'Save As' for these files:\n\n");

		for (PluginSaveable saveable : readOnly) {
			sb.append(saveable.getDescription());
			sb.append("\n");
		}

		int choice =
			OptionDialog.showOptionDialog(tool.getToolFrame(), "Read-Only Files", sb.toString(),
				"Lose Changes", OptionDialog.QUESTION_MESSAGE);
		if (choice == OptionDialog.CANCEL_OPTION) {
			return true;
		}
		return false;
	}

//=================================================================================================
// Inner Classes
//=================================================================================================	

	private class SaveableRowObject {

		private PluginSaveable saveable;
		private boolean isSelected = true;
		private Icon icon;

		SaveableRowObject(PluginSaveable saveable) {
			this.saveable = saveable;
		}

		String getDescription() {
			return saveable.getDescription();
		}

		boolean isReadOnly() {
			return saveable.isReadOnly();
		}

		PluginSaveable getSaveable() {
			return saveable;
		}

		void setSelected(boolean b) {
			this.isSelected = b;
			updateYesButton();
		}

		boolean isSelected() {
			return isSelected;
		}

		@Override
		public String toString() {
			return saveable.toString();
		}

		String getToolTipText() {
			return saveable.getToolTipText();
		}

		Icon getIcon() {
			if (icon == null) {
				icon = saveable.getIcon();
				if (icon == null) {
					icon = Icons.EMPTY_ICON;
				}
				else {
					icon = ResourceManager.getScaledIcon(icon, 16, 16);
				}
			}
			return icon;
		}
	}

	// Note: there is a subtlety to the sorting that allows saveables that affect other saveables
	// to be saved first.  This allows the changed saveables to be saved after any new changes may
	// have been triggered.
	private static class SaveableComparator implements Comparator<PluginSaveable> {
		@Override
		public int compare(PluginSaveable s1, PluginSaveable s2) {

			DomainObject d1 = s1.getDependent();
			DomainObject d2 = s2.getDependent();
			if (!Objects.equals(d1, d2)) {
				// Saveables with dependents need to go above those that do not have dependents.
				// This allows changes made by saving these items to go before the affected 
				// dependent.
				if (d1 != null) {
					return -1;
				}
				return 1; // s1 does not have a dependent and s2 does; s1 goes after
			}

			String t1 = s1.getType();
			String t2 = s2.getType();
			int res = t1.compareTo(t2);
			if (res != 0) {
				return res;
			}

			String desc1 = s1.getDescription();
			String desc2 = s2.getDescription();
			return desc1.compareTo(desc2);
		}
	}

	/**
	 * Cell renderer to show the checkboxes for the changed data files.
	 */
	private class DataCellRenderer extends GListCellRenderer<SaveableRowObject> {

		private JPanel panel = new JPanel();
		private JLabel iconLabel = new JLabel();
		private GCheckBox checkBox = new GCheckBox();

		{
			panel.setLayout(new BoxLayout(panel, BoxLayout.LINE_AXIS));
			panel.add(Box.createHorizontalStrut(5));
			panel.add(iconLabel);
			panel.add(Box.createHorizontalStrut(5));
			panel.add(checkBox);
		}

		@Override
		public Component getListCellRendererComponent(JList<? extends SaveableRowObject> list,
				SaveableRowObject rowObject, int index, boolean isSelected, boolean cellHasFocus) {

			super.getListCellRendererComponent(list, rowObject, index, isSelected, cellHasFocus);

			String description = rowObject.getDescription();
			checkBox.setText(description);

			String tooltip = rowObject.getToolTipText();
			panel.setToolTipText(tooltip);

			checkBox.setSelected(rowObject.isSelected());
			checkBox.setForeground(getForeground());
			checkBox.setBackground(getBackground());

			// set color to red if file cannot be saved
			if (rowObject.isReadOnly()) {
				checkBox.setForeground(Colors.ERROR);
				Font bold = getBoldFont();
				checkBox.setFont(bold);
			}

			panel.setBackground(getBackground());

			Icon icon = rowObject.getIcon();
			iconLabel.setIcon(icon);

			return panel;
		}
	}

	private class ListMouseListener extends MouseAdapter {

		@Override
		public void mouseClicked(MouseEvent e) {

			clearStatusText();
			int index = listPanel.locationToIndex(e.getPoint());
			if (index < 0) {
				return;
			}

			SaveableRowObject rowObject = listPanel.getValueAt(index);
			if (!rowObject.isReadOnly()) {
				setStatusText("Cannot be saved here; save manually");
				return;
			}

			boolean selected = rowObject.isSelected();
			rowObject.setSelected(!selected);
			listPanel.repaint();
		}
	}

	private class ListKeyListener extends KeyAdapter {
		@Override
		public void keyPressed(KeyEvent e) {
			if (e.getKeyCode() == KeyEvent.VK_SPACE) {
				e.consume();
				JList<?> list = (JList<?>) e.getSource();
				int index = list.getSelectedIndex();
				if (index < 0) {
					return;
				}

				SaveableRowObject rowObject = listPanel.getValueAt(index);
				boolean selected = rowObject.isSelected();
				rowObject.setSelected(!selected);
				listPanel.repaint();
			}
		}
	}

	private class SaveableTask extends Task {

		private List<PluginSaveable> allSaveables;

		private boolean savedAll = true;

		public SaveableTask(List<PluginSaveable> saveables) {
			super("Save Data", true, true, true);
			this.allSaveables = saveables;
		}

		boolean didSaveAll() {
			return savedAll;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {

			// Handle orphaned transactions by attempting to lock transactions all domain objects.
			// The user will be prompted if there are active transactions. We assume that there are
			// no tasks running at this time.
			List<DomainObject> dobjs = getLockableDomainObjects();
			if (canLockDomainObjects(dobjs)) {
				return;
			}

			int n = allSaveables.size();
			monitor.initialize(n);

			for (int i = 0; i < n; i++) {
				monitor.checkCancelled();
				PluginSaveable saveable = allSaveables.get(i);
				monitor.setProgress(i);

				monitor.setMessage("Saving " + saveable.getDescription());
				if (!saveable.save(monitor)) {
					savedAll = false;
				}
			}
		}

		private List<DomainObject> getLockableDomainObjects() {

			List<DomainObject> lockable = new ArrayList<>();
			for (PluginSaveable saveable : saveables) {
				DomainObject dobj = saveable.getDomainObject();
				if (dobj != null) {
					lockable.add(dobj);
				}
			}

			return lockable;
		}

		private boolean canLockDomainObjects(List<DomainObject> files) {
			boolean canLock = true;
			List<DomainObject> locked = new ArrayList<>();
			for (DomainObject dobj : files) {
				if (dobj.lock("Save Changes")) {
					locked.add(dobj);
					continue;
				}

				boolean force = promptToForceLock(dobj);
				if (!force) { // cancelled
					canLock = false;
					break;
				}

				dobj.forceLock(true, null);
				locked.add(dobj);
			}

			// release all locked items 
			for (DomainObject lockedDobj : locked) {
				lockedDobj.unlock();
			}

			return canLock;
		}

		private boolean promptToForceLock(DomainObject dobj) {
			String filename = dobj.getPath();
			String transactions = toStringOpenTransactions(dobj);
			String msg = """
					File %s
					is currently being modified by the following actions:
					%s

					To save, you must abort these actions. Changes made by these actions
					(and all changes made since those actions started) will be lost!
					Changes made before those actions began will be saved.

					Do you want to abort the transactions?
					""".formatted(filename, transactions);

			String title = "Abort Transaction(s)?";
			String button1 = "Abort and Save";
			int result = OptionDialog.showOptionDialog(null, title, msg, button1,
				OptionDialog.WARNING_MESSAGE);
			return result == OptionDialog.OPTION_ONE;
		}

		private String toStringOpenTransactions(DomainObject dobj) {
			StringBuilder buf = new StringBuilder();
			TransactionInfo t = dobj.getCurrentTransactionInfo();
			List<String> list = t.getOpenSubTransactions();
			for (String txName : list) {
				buf.append("\n     ").append(txName);
			}
			return buf.toString();
		}
	}

}
