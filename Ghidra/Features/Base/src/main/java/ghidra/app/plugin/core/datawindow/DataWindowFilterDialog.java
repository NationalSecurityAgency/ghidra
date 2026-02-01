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

import docking.DialogComponentProvider;
import docking.DockingUtils;
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GHtmlCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.filter.FilterListener;
import docking.widgets.filter.FilterTextField;
import docking.widgets.label.GLabel;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.plugin.core.datawindow.DataWindowPlugin.Coverage;
import ghidra.util.HelpLocation;
import ghidra.util.task.SwingUpdateManager;

class DataWindowFilterDialog extends DialogComponentProvider {

	private JPanel mainPanel;
	private List<JCheckBox> checkboxes = new ArrayList<>();
	private JPanel checkboxPanel;
	private JRadioButton enabledButton;
	private JRadioButton disabledButton;
	private GhidraComboBox<Coverage> coverageCombo;
	private JButton selectAllButton;
	private JButton selectNoneButton;
	private FilterTextField filterField;
	private List<String> filteredList = new ArrayList<>();

	private SortedMap<String, Boolean> typeEnabledMap;
	private boolean isFilterEnabled = true;

	private SwingUpdateManager updateManager =
		new SwingUpdateManager(250, 1000, () -> filterCheckboxes());

	private KeyListener listener = new KeyAdapter() {
		@Override
		public void keyPressed(KeyEvent e) {
			if (e.getKeyCode() == KeyEvent.VK_ENTER && e.getModifiersEx() == 0) {
				e.consume();
				okCallback();
			}
		}
	};

	private ItemListener itemListener = e -> {
		JCheckBox checkBox = (JCheckBox) e.getItem();
		typeEnabledMap.put(checkBox.getName(), checkBox.isSelected());
	};

	private FilterListener filterListener = new FilterActionFilterListener();
	private DataWindowPlugin plugin;

	DataWindowFilterDialog(DataWindowPlugin plugin) {
		super("Set Data Type Filter");
		this.plugin = plugin;

		typeEnabledMap = new TreeMap<>(plugin.getTypeMap());

		addWorkPanel(create());
		addOKButton();
		addCancelButton();

		setSelectionEnabled(plugin.getSelection() != null);

		setHelpLocation(new HelpLocation(plugin.getName(), "Filter_Data_Types"));
		setPreferredSize(360, 730);
	}

	private JComponent create() {

		mainPanel = new JPanel();
		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.PAGE_AXIS));

		JPanel enablePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		ButtonGroup group = new ButtonGroup();
		enabledButton = new GRadioButton("Enabled", true);
		enabledButton.addKeyListener(listener);
		enablePanel.add(enabledButton);
		group.add(enabledButton);
		disabledButton = new GRadioButton("Disabled", false);
		disabledButton.addKeyListener(listener);
		enablePanel.add(disabledButton);
		group.add(disabledButton);
		enablePanel.setBorder(BorderFactory.createTitledBorder("Filter State"));
		mainPanel.add(enablePanel);

		enabledButton.addChangeListener(e -> {
			boolean enabled = enabledButton.isSelected();
			isFilterEnabled = enabled;
			for (JCheckBox cb : checkboxes) {
				cb.setEnabled(enabled);
			}

			selectAllButton.setEnabled(enabled);
			selectNoneButton.setEnabled(enabled);
			coverageCombo.setEnabled(enabled);
			filterField.setEnabled(enabled);
		});

		JPanel limitPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		coverageCombo = new GhidraComboBox<>();
		coverageCombo.addKeyListener(listener);
		coverageCombo.setModel(new DefaultComboBoxModel<>(Coverage.values()));
		limitPanel.add(coverageCombo);
		limitPanel.setBorder(BorderFactory.createTitledBorder("Limit Data To"));
		mainPanel.add(limitPanel);

		JPanel typesPanel = new JPanel(new BorderLayout());

		JPanel typeButtonPanel = new JPanel(new GridLayout(1, 2, 5, 0));
		selectAllButton = new JButton("Check All");
		selectAllButton.setMnemonic('A');
		selectAllButton.addActionListener(evt -> {
			for (JCheckBox element : checkboxes) {
				element.setSelected(true);
			}
		});
		typeButtonPanel.add(selectAllButton);
		selectNoneButton = new JButton("Check None");
		selectNoneButton.setMnemonic('N');
		selectNoneButton.addActionListener(evt -> {
			for (JCheckBox element : checkboxes) {
				element.setSelected(false);
			}
		});
		typeButtonPanel.add(selectNoneButton);

		checkboxPanel = new JPanel();
		checkboxPanel.setBackground(Colors.BACKGROUND);
		checkboxPanel.setLayout(new BoxLayout(checkboxPanel, BoxLayout.Y_AXIS));

		buildCheckBoxList();

		JScrollPane scroller = new JScrollPane(checkboxPanel);
		typesPanel.add(scroller, BorderLayout.CENTER);
		typesPanel.setBorder(BorderFactory.createTitledBorder("Enabled Data Types"));
		typesPanel.add(typeButtonPanel, BorderLayout.SOUTH);
		mainPanel.add(typesPanel);

		filterField = new FilterTextField(checkboxPanel);
		filterField.addFilterListener(filterListener);

		JPanel filterPanel = new JPanel();
		filterPanel.setLayout(new BoxLayout(filterPanel, BoxLayout.LINE_AXIS));
		filterPanel.add(new GLabel("Filter:"));
		filterPanel.add(Box.createHorizontalStrut(10));
		filterPanel.add(filterField);
		filterPanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));

		mainPanel.add(filterPanel);
		return mainPanel;
	}

	private void buildCheckBoxList() {
		checkboxPanel.removeAll();
		checkboxes.clear();
		if (!filteredList.isEmpty()) {
			String filteredText = getFilterText();
			for (String type : filteredList) {
				Boolean enabled = typeEnabledMap.get(type);
				StringBuilder html = new StringBuilder(type);
				int firstIndex = StringUtils.indexOfIgnoreCase(type, filteredText, 0);
				int lastIndex = firstIndex + filteredText.length();
				html.insert(lastIndex, "</b>"); // do before first index (for no math on index)
				html.insert(firstIndex, "<b>");
				html.insert(0, "<html>");
				createCheckBox(html.toString(), type, enabled);
			}
		}
		else {
			if (StringUtils.isBlank(getFilterText())) { // no filter text to highlight
				for (String type : typeEnabledMap.keySet()) {
					Boolean enabled = typeEnabledMap.get(type);
					createCheckBox(type, type, enabled);
				}
			}
		}
		repaint();
	}

	private String getFilterText() {
		if (filterField != null) {
			return filterField.getText().trim();
		}
		return null;
	}

	private void repaint() {
		checkboxPanel.invalidate();
		mainPanel.validate();
		mainPanel.repaint();
	}

	private void createCheckBox(String html, String typeName, Boolean enabled) {
		JCheckBox newCb = new GHtmlCheckBox(html, enabled.booleanValue());
		newCb.setName(typeName);
		newCb.addKeyListener(listener);
		newCb.addItemListener(itemListener);
		DockingUtils.setTransparent(newCb);
		checkboxes.add(newCb);
		checkboxPanel.add(newCb);
	}

	private void filterCheckboxes() {
		List<String> checkboxNameList = new ArrayList<>();
		String filterText = getFilterText();
		if (!StringUtils.isBlank(filterText)) {
			Set<Entry<String, Boolean>> entrySet = typeEnabledMap.entrySet();
			for (Entry<String, Boolean> entry : entrySet) {
				String checkboxName = entry.getKey();
				if (StringUtils.containsIgnoreCase(checkboxName, filterText)) {
					checkboxNameList.add(checkboxName);
				}
			}
		}
		filteredList = checkboxNameList;
		buildCheckBoxList();
	}

	boolean isFilterEnabled() {
		return isFilterEnabled;
	}

	@Override
	public void okCallback() {

		if (!isFilterEnabled) {
			plugin.setFilterEnabled(false);
		}
		else {
			Coverage coverage = (Coverage) coverageCombo.getSelectedItem();
			plugin.setFilter(typeEnabledMap, coverage);
		}

		typeEnabledMap.clear();
		close();
	}

	@Override
	public void cancelCallback() {
		typeEnabledMap.clear();
		close();
	}

	void setSelectionEnabled(boolean enableSelection) {
		if (enableSelection) {
			coverageCombo.setModel(new DefaultComboBoxModel<>(Coverage.values()));
		}
		else {
			coverageCombo.setModel(
				new DefaultComboBoxModel<>(new Coverage[] { Coverage.PROGRAM, Coverage.VIEW }));
		}
	}

	void setTypeEnabled(String type, boolean b) {

		for (JCheckBox cb : checkboxes) {
			String name = cb.getName();
			if (name.equals(type)) {
				cb.setSelected(b);
			}
		}
	}

	void setFilterEnabled(boolean b) {
		if (b) {
			enabledButton.setSelected(true);
		}
		else {
			disabledButton.setSelected(true);
		}
	}

	private class FilterActionFilterListener implements FilterListener {

		@Override
		public void filterChanged(String text) {
			filterCheckboxes();
			updateManager.updateLater();
		}
	}
}
