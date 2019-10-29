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
package ghidra.app.plugin.core.datawindow;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.*;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GHtmlCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.filter.FilterListener;
import docking.widgets.filter.FilterTextField;
import docking.widgets.label.GLabel;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.task.SwingUpdateManager;
import resources.Icons;

class FilterAction extends ToggleDockingAction {

	private static final String ENTIRE_PROGRAM = "Entire Program";
	private static final String CURRENT_VIEW = "Current View";
	private static final String SELECTION = "Current Selection";

	private DataWindowPlugin plugin;

	private boolean filterEnabled = false;
	private boolean viewMode = false;
	private boolean selectionMode = false;

	private FilterDialog dialog;

	private static class SortMapComparatorASC implements Comparator<String> {

		@Override
		public int compare(String o1, String o2) {
			if (o1 != null) {
				if (!o1.equalsIgnoreCase(o2)) {
					return o1.compareToIgnoreCase(o2);
				}
				return o1.compareTo(o2);
			}
			return -1;
		}
	}

	private SortMapComparatorASC SortMapComparatorASCObj = new SortMapComparatorASC();
	private SortedMap<String, Boolean> typeEnabledMap = new TreeMap<>(SortMapComparatorASCObj);

	FilterAction(DataWindowPlugin plugin) {
		super("Filter Data Types", plugin.getName());
		this.plugin = plugin;
		setDescription("Filters table so only specified types are displayed");
		setEnabled(true);
		setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON));
		setSelected(false);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (dialog == null) {
			dialog = new FilterDialog();
		}

		dialog.setSelectionEnabled(plugin.getSelection() != null);
		dialog.updateButtonEnabledState();
		plugin.getTool().showDialog(dialog);
	}

	synchronized void clearTypes() {
		typeEnabledMap.clear();

		if (dialog != null) {
			dialog.clearTypes();
		}
	}

	synchronized void addType(String type) {
		Boolean bool = new Boolean(!filterEnabled);
		typeEnabledMap.put(type, bool);

		if (dialog != null) {
			dialog.createCheckBox(type, type, bool.booleanValue());
		}
	}

	synchronized boolean typeEnabled(String type) {
		if (!filterEnabled) {
			return true;
		}
		Boolean bool = typeEnabledMap.get(type);
		return (bool != null && bool.booleanValue());
	}

	/**
	 * Return array list of strings that are the names of the 
	 * data types that are selected.
	 */
	synchronized ArrayList<String> getSelectedTypes() {
		ArrayList<String> list = new ArrayList<>();
		Iterator<String> iter = typeEnabledMap.keySet().iterator();
		while (iter.hasNext()) {
			String type = iter.next();
			Boolean lEnabled = typeEnabledMap.get(type);
			if (lEnabled != null && typeEnabledMap.get(type).booleanValue()) {
				list.add(type);
			}
		}
		return list;
	}

	synchronized void selectTypes(ArrayList<String> list) {
		for (int i = 0; i < list.size(); i++) {
			typeEnabledMap.put(list.get(i), Boolean.TRUE);
		}
		if (dialog != null) {
			dialog.selectTypes(list);
		}
	}

	void repaint() {
		if (dialog == null) {
			return;
		}
		dialog.repaint();
	}

	boolean getViewMode() {
		return viewMode;
	}

	boolean getSelectionMode() {
		return selectionMode;
	}

	void setTypeEnabled(String type, boolean enabled) {
		typeEnabledMap.put(type, enabled);
	}

	void setFilterEnabled(boolean filterEnabled) {
		this.filterEnabled = filterEnabled;
	}

	void programClosed() {
		typeEnabledMap = new TreeMap<>();
		filterEnabled = false;
		viewMode = false;
		selectionMode = false;
		dialog = null;
		setEnabled(false);
		clearTypes();
	}

	void programOpened(Program program) {
		setEnabled(true);
	}

	private class FilterDialog extends DialogComponentProvider {

		private JPanel mainPanel;
		private List<JCheckBox> checkboxes = new ArrayList<>();
		private JPanel checkboxPanel;
		private JRadioButton enableButton;
		private JRadioButton disableButton;
		private GhidraComboBox<String> limitComboBox;
		private JButton selectAllButton;
		private JButton selectNoneButton;
		private FilterTextField filterField;
		private List<String> filteredList = new ArrayList<>();

		private SwingUpdateManager updateManager =
			new SwingUpdateManager(250, 1000, () -> updateCheckBoxListFilter());

		private KeyListener listener = new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER && e.getModifiers() == 0) {
					e.consume();
					okCallback();
				}
			}
		};

		private ItemListener itemListener = e -> {
			JCheckBox typeCheckBox = (JCheckBox) e.getItem();
			setTypeEnabled(typeCheckBox.getName(), typeCheckBox.isSelected());
		};

		private FilterListener filterListener = new FilterActionFilterListener();

		FilterDialog() {
			super("Set Data Type Filter");

			addWorkPanel(create());
			addOKButton();
//			addCancelButton();
			setHelpLocation(new HelpLocation(plugin.getName(), "Filter_Data_Types"));
			setPreferredSize(360, 730);
		}

		void selectTypes(ArrayList<String> list) {
			for (int i = 0; i < list.size(); i++) {
				String type = list.get(i);
				selectCheckBox(type);
			}
		}

		private void selectCheckBox(String typeName) {
			for (int i = 0; i < checkboxes.size(); i++) {
				JCheckBox cb = checkboxes.get(i);
				if (cb.getText().equals(typeName)) {
					cb.setSelected(true);
					return;
				}
			}
		}

		private JComponent create() {

			mainPanel = new JPanel();
			mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

			JPanel enablePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
			ButtonGroup group = new ButtonGroup();
			enableButton = new GRadioButton("Enabled", true);
			enableButton.addKeyListener(listener);
			enablePanel.add(enableButton);
			group.add(enableButton);
			disableButton = new GRadioButton("Disabled", false);
			disableButton.addKeyListener(listener);
			enablePanel.add(disableButton);
			group.add(disableButton);
			enablePanel.setBorder(BorderFactory.createTitledBorder("Filter Enable"));
			mainPanel.add(enablePanel);

			enableButton.addChangeListener(e -> {
				boolean lenabled = enableButton.isSelected();
				Iterator<JCheckBox> itr = checkboxes.iterator();
				while (itr.hasNext()) {
					JCheckBox curCheckbox = itr.next();
					curCheckbox.setEnabled(lenabled);
				}

				selectAllButton.setEnabled(isEnabled());
				selectNoneButton.setEnabled(isEnabled());
				limitComboBox.setEnabled(isEnabled());
				filterField.setEnabled(lenabled);
			});

			JPanel limitPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
			limitComboBox = new GhidraComboBox<>();
			limitComboBox.addKeyListener(listener);
			limitComboBox.setModel(new DefaultComboBoxModel<>(
				new String[] { ENTIRE_PROGRAM, CURRENT_VIEW, SELECTION }));
			limitPanel.add(limitComboBox);
			limitPanel.setBorder(BorderFactory.createTitledBorder("Limit Data To"));
			mainPanel.add(limitPanel);

			JPanel typesPanel = new JPanel(new BorderLayout());

			JPanel typeButtonPanel = new JPanel(new GridLayout(1, 2, 5, 0));
			selectAllButton = new JButton("Select All");
			selectAllButton.setMnemonic('A');
			selectAllButton.addActionListener(evt -> {
				Iterator<JCheckBox> itr = checkboxes.iterator();
				while (itr.hasNext()) {
					itr.next().setSelected(true);
				}
			});
			typeButtonPanel.add(selectAllButton);
			selectNoneButton = new JButton("Select None");
			selectNoneButton.setMnemonic('N');
			selectNoneButton.addActionListener(evt -> {
				Iterator<JCheckBox> itr = checkboxes.iterator();
				while (itr.hasNext()) {
					itr.next().setSelected(false);
				}
			});
			typeButtonPanel.add(selectNoneButton);

			checkboxPanel = new JPanel();
			checkboxPanel.setBackground(Color.WHITE);
			checkboxPanel.setLayout(new BoxLayout(checkboxPanel, BoxLayout.Y_AXIS));

			buildCheckBoxList();

			JScrollPane scroller = new JScrollPane(checkboxPanel);
			scroller.setPreferredSize(new Dimension(checkboxPanel.getPreferredSize().width, 150));
			typesPanel.add(scroller, BorderLayout.CENTER);
			typesPanel.setBorder(BorderFactory.createTitledBorder("Enabled Data Types"));
			typesPanel.add(typeButtonPanel, BorderLayout.SOUTH);
			mainPanel.add(typesPanel);

			JPanel filterBorderPanel = new JPanel(new GridLayout(1, 2, 5, 0));
			filterBorderPanel.setBorder(
				BorderFactory.createTitledBorder("Filter Enabled Data Types List Above"));

			JPanel filterPanel = new JPanel(new BorderLayout());
			filterField = new FilterTextField(checkboxPanel);
			filterPanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
			filterPanel.add(new GLabel("Filter:"), BorderLayout.WEST);

			filterPanel.add(filterField, BorderLayout.CENTER);
			filterField.addFilterListener(filterListener);

			filterBorderPanel.add(filterPanel, BorderLayout.CENTER);
			mainPanel.add(filterBorderPanel);
			return mainPanel;
		}

		private void updateButtonEnabledState() {
			if (filteredTextExists()) {
				selectNoneButton.setEnabled(false);
				selectAllButton.setEnabled(false);
			}
			else {
				selectNoneButton.setEnabled(true);
				selectAllButton.setEnabled(true);
			}
		}

		private void buildCheckBoxList() {
			checkboxPanel.removeAll();
			checkboxes.clear();
			if (!filteredList.isEmpty()) {
				Iterator<String> itr = filteredList.iterator();
				String filteredText = getFilteredText();
				while (itr.hasNext()) {
					String curType = itr.next();
					Boolean lEnabled = typeEnabledMap.get(curType);
					StringBuffer buildMetaCurTypeBuff = new StringBuffer(curType);
					int firstIndex = StringUtils.indexOfIgnoreCase(curType, filteredText, 0);
					int lastIndex = firstIndex + filteredText.length();
					buildMetaCurTypeBuff.insert(lastIndex, "</b>");//THIS MUST ALWAYS COME BEFORE FIRST INDEX (FOR NO MATH on INDEX)
					buildMetaCurTypeBuff.insert(firstIndex, "<b>");
					buildMetaCurTypeBuff.insert(0, "<html>");
					createCheckBox(buildMetaCurTypeBuff.toString(), curType, lEnabled);
				}
			}
			else {
				if (!filteredTextExists()) {//Typed Incorrectly, so show nothing...
					Iterator<String> itr = typeEnabledMap.keySet().iterator();
					while (itr.hasNext()) {
						String curType = itr.next();
						Boolean lEnabled = typeEnabledMap.get(curType);
						createCheckBox(curType, curType, lEnabled);
					}
				}
			}
			repaint();
		}

		private String getFilteredText() {
			if (filterField != null) {
				return filterField.getText().trim();
			}
			return null;
		}

		private boolean filteredTextExists() {
			return (((getFilteredText() != null) && (getFilteredText().length() > 0)) ? true
					: false);
		}

		private void repaint() {
			checkboxPanel.invalidate();
			mainPanel.validate();
			mainPanel.repaint();
		}

		private void createCheckBox(String curTypeHtml, String curType, Boolean lEnabled) {
			JCheckBox newCheckbox = new GHtmlCheckBox(curTypeHtml, lEnabled.booleanValue());
			newCheckbox.setName(curType);
			newCheckbox.addKeyListener(listener);
			newCheckbox.addItemListener(itemListener);
			DockingUtils.setTransparent(newCheckbox);
			checkboxes.add(newCheckbox);
			checkboxPanel.add(newCheckbox);
		}

		private void updateCheckBoxListFilter() {
			ArrayList<String> checkboxNameList = new ArrayList<>();
			if (filteredTextExists()) {
				String filteredText = getFilteredText();
				Set<Entry<String, Boolean>> entrySet = typeEnabledMap.entrySet();
				Iterator<Entry<String, Boolean>> iteratorIndex = entrySet.iterator();
				while (iteratorIndex.hasNext()) {
					Entry<String, Boolean> entry = iteratorIndex.next();
					String checkboxName = entry.getKey();
					if (StringUtils.containsIgnoreCase(checkboxName, filteredText)) {
						checkboxNameList.add(checkboxName);
					}
				}
			}
			filteredList = checkboxNameList;
			buildCheckBoxList();
		}

		@Override
		public void okCallback() {
			filterEnabled = enableButton.isSelected();

			viewMode = limitComboBox.getSelectedItem() == CURRENT_VIEW;
			selectionMode = limitComboBox.getSelectedItem() == SELECTION;

			close();
			setSelected(filterEnabled);
			plugin.reload();
		}

		@Override
		public void cancelCallback() {
			okCallback();
		}

		private void clearTypes() {
			checkboxes.clear();
			checkboxPanel.removeAll();
			mainPanel.validate();
		}

		public void setSelectionEnabled(boolean enableSelection) {
			int modelSize = limitComboBox.getModel().getSize();
			if (enableSelection) {
				if (modelSize != 3) {
					limitComboBox.setModel(new DefaultComboBoxModel<>(
						new String[] { ENTIRE_PROGRAM, CURRENT_VIEW, SELECTION }));
				}
			}
			else if (modelSize != 2) {
				limitComboBox.setModel(
					new DefaultComboBoxModel<>(new String[] { ENTIRE_PROGRAM, CURRENT_VIEW }));
			}
		}

		private class FilterActionFilterListener implements FilterListener {

			@Override
			public void filterChanged(String text) {
				updateButtonEnabledState();
				updateManager.updateLater();
			}
		}
	}
}
