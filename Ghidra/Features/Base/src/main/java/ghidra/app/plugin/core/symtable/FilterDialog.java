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
package ghidra.app.plugin.core.symtable;

import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.*;

import javax.swing.*;

import org.jdom.Element;

import docking.ComponentProvider;
import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GHtmlLabel;
import docking.widgets.label.GIconLabel;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import ghidra.util.layout.*;
import resources.ResourceManager;

public class FilterDialog extends DialogComponentProvider {
	private NewSymbolFilter filter;
	private JPanel advancedPanel;
	private JPanel advancedFilterPanel;
	private Map<String, JCheckBox> checkBoxMap = new HashMap<>();
	private boolean ignoreCallbacks;
	private JCheckBox advancedFilterCheckbox;
	private SymbolTableModel keyModel;
	private boolean isChanged;
	private FilterCheckboxItemListener checkboxListener = new FilterCheckboxItemListener();
	private PluginTool tool;

	public FilterDialog(PluginTool tool) {
		super("Symbol Table Filter", false);
		this.tool = tool;
		filter = new NewSymbolFilter();
		addWorkPanel(buildWorkPanel());
		addOKButton();
		addApplyButton();
		addDismissButton();
		setHelpLocation(new HelpLocation(HelpTopics.SYMBOL_TABLE, "Set Filter"));
		initCheckBoxes();
		setRememberSize(false);

	}

	@Override
	public void setStatusText(String text) {
		// All status messages displayed as alerts
		super.setStatusText(text, MessageType.ALERT);
	}

	// for testing
	void setFilter(NewSymbolFilter newFilter) {
		filter = new NewSymbolFilter(newFilter);
		initCheckBoxes();
		setChanged(true);
	}

	Element saveFilter() {
		return filter.saveToXml();
	}

	void restoreFilter(Element element) {
		filter.restoreFromXml(element);
		initCheckBoxes();
	}

	private void initCheckBoxes() {
		setChanged(false);
		ignoreCallbacks = true;
		Iterator<String> it = checkBoxMap.keySet().iterator();
		while (it.hasNext()) {
			String filterName = it.next();
			JCheckBox cb = checkBoxMap.get(filterName);
			cb.setSelected(filter.isActive(filterName));
		}
		ignoreCallbacks = false;
		advancedFilterCheckbox.setSelected(filter.getActiveAdvancedFilterCount() > 0);
		update();
	}

	private JComponent buildWorkPanel() {
		advancedFilterCheckbox = new GCheckBox("Use Advanced Filters");
		advancedFilterCheckbox.setToolTipText(HTMLUtilities.toHTML(
			"Show advance filters.  Advanced filters eliminate all appropriate\n" +
				"symbols that don't match the filter.  Selecting mutually exclusive filters\n" +
				"(such as Globals and Locals) will totally eliminate entire types of symbols."));
		advancedFilterCheckbox.addItemListener(e -> {
			setStatusText("");
			JCheckBox cb = (JCheckBox) e.getSource();
			if (cb.isSelected()) {
				advancedPanel.add(advancedFilterPanel);
			}
			else {
				advancedPanel.removeAll();
				clearAdvancedFilters();
			}
			FilterDialog.this.repack();
			update();
		});

		JPanel mainPanel = new JPanel(new VerticalLayout(15));

		JPanel filterPanel = new JPanel(new BorderLayout());

		JPanel leftPanel = new JPanel(new VerticalLayout(20));
		leftPanel.add(buildSourcePanel());
		leftPanel.add(buildTypesPanel());
		filterPanel.add(leftPanel, BorderLayout.WEST);
		filterPanel.add(buildAdvancedPanel(), BorderLayout.EAST);
		mainPanel.add(filterPanel);
		mainPanel.add(advancedFilterCheckbox);
		mainPanel.add(buildResetPanel());
		mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 5, 0, 5));
		return mainPanel;
	}

	private Component buildSourcePanel() {
		ItemListener sourceItemListener = e -> {
			if (ignoreCallbacks) {
				return;
			}
			JCheckBox cb = (JCheckBox) e.getItem();
			String name = cb.getText();
			setChanged(true);
			filter.setFilter(name, cb.isSelected());
			update();
		};

		String[] sourceNames = filter.getSourceFilterNames();
		JPanel panel = new JPanel(new GridLayout(0, 2));
		for (String sourceName : sourceNames) {
			JCheckBox cb = new GCheckBox(sourceName);
			checkBoxMap.put(sourceName, cb);
			cb.addItemListener(sourceItemListener);
			cb.setToolTipText(HTMLUtilities.toHTML(filter.getFilterDescription(sourceName)));
			panel.add(cb);
		}
		panel.setBorder(BorderFactory.createTitledBorder("Symbol Source"));
		return panel;
	}

	private Component buildAdvancedPanel() {
		advancedPanel = new JPanel(new BorderLayout());

		JPanel infoPanel = new JPanel(new HorizontalLayout(20));
		Icon icon = ResourceManager.loadImage("images/information.png");

		infoPanel.add(new GIconLabel(icon));
		infoPanel.add(new GHtmlLabel(
			HTMLUtilities.toHTML("Advanced filters do not apply to all symbol types.\n" +
				"All symbols without applicable advanced filters will\n" +
				"be included. If more than one advanced filter is\n" +
				"applicable to a symbol type, then those symbols will\n" +
				"be included if any of the applicable filters match. \n" +
				"Filters that are not applicable to any of the selected\n" +
				"symbol types are disabled.")));

		JPanel filtersPanel = new JPanel(new GridLayout(0, 2));
//		Border outer = BorderFactory.createEmptyBorder(0,40,0,0);
//		Border inner = BorderFactory.createTitledBorder("Advanced Filters");
		filtersPanel.setBorder(BorderFactory.createEmptyBorder(0, 40, 0, 0));
		String[] filterNames = filter.getAdvancedFilterNames();
		for (String filterName : filterNames) {
			JCheckBox cb = new GCheckBox(filterName);
			checkBoxMap.put(filterName, cb);
			cb.addItemListener(checkboxListener);
			cb.setToolTipText(HTMLUtilities.toHTML(filter.getFilterDescription(filterName)));
			filtersPanel.add(cb);
		}
		advancedFilterPanel = new JPanel(new VerticalLayout(10));
		advancedFilterPanel.setBorder(BorderFactory.createTitledBorder("Advanced Filters"));
		advancedFilterPanel.add(filtersPanel);
		advancedFilterPanel.add(infoPanel);
		return advancedPanel;
	}

	private Component buildTypesPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createTitledBorder("Symbol Types"));
		panel.add(buildLabelTypesPanel("Label Symbols", filter.getLabelTypeFilterNames()),
			BorderLayout.WEST);
		panel.add(buildLabelTypesPanel("Non-label Symbols", filter.getNonLabelTypeFilterNames()),
			BorderLayout.EAST);
		panel.add(buildSelectButtonPanel(), BorderLayout.SOUTH);
		return panel;
	}

	private Component buildLabelTypesPanel(String title, String[] filterNames) {
		JPanel panel = new JPanel(new VerticalLayout(0));
		panel.setBorder(BorderFactory.createTitledBorder(title));
		for (String filterName : filterNames) {
			JCheckBox cb = new GCheckBox(filterName);
			cb.setName(filterName);
			checkBoxMap.put(filterName, cb);
			cb.addItemListener(checkboxListener);
			cb.setToolTipText(HTMLUtilities.toHTML(filter.getFilterDescription(filterName)));
			panel.add(cb);
		}
		return panel;
	}

	private void setTypeFiltersActive(boolean active) {
		String[] typeNames = filter.getLabelTypeFilterNames();
		for (String typeName : typeNames) {
			JCheckBox cb = checkBoxMap.get(typeName);
			cb.setSelected(active);
		}
		typeNames = filter.getNonLabelTypeFilterNames();
		for (String typeName : typeNames) {
			JCheckBox cb = checkBoxMap.get(typeName);
			cb.setSelected(active);
		}
	}

	private Component buildSelectButtonPanel() {
		JPanel panel = new JPanel(new MiddleLayout());
		JPanel innerPanel = new JPanel(new GridLayout(0, 2, 30, 30));
		panel.add(innerPanel);

		JButton b1 = new JButton("Select All");
		JButton b2 = new JButton("Clear All");
		b1.addActionListener(e -> setTypeFiltersActive(true));
		b2.addActionListener(e -> setTypeFiltersActive(false));
		innerPanel.add(b1);
		innerPanel.add(b2);
		panel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
		return panel;

	}

	private Component buildResetPanel() {
		JPanel panel = new JPanel(new MiddleLayout());
		JPanel panel2 = new JPanel(new GridLayout(1, 0, 20, 0));
		JButton button1 = new JButton("Reset Filters");
		button1.addActionListener(e -> {
			setStatusText("");
			filter.setFilterDefaults();
			initCheckBoxes();
			setChanged(true);
		});
		panel2.add(button1);
		panel.add(panel2);
		return panel;
	}

	private void clearAdvancedFilters() {
		String[] filterNames = filter.getAdvancedFilterNames();
		for (String filterName : filterNames) {
			if (filter.isActive(filterName)) {
				JCheckBox cb = checkBoxMap.get(filterName);
				cb.setSelected(false);
			}
		}
	}

	public void adjustFilter(ComponentProvider provider, SymbolTableModel model) {
		this.keyModel = model;
		filter = new NewSymbolFilter(model.getFilter());
		initCheckBoxes();
		tool.showDialog(this, provider);
		model = null;
	}

	private void update() {
		updateStatus();
		updateAdvancedFilterEnablement();
		updateOkAndApply();
	}

	private void updateStatus() {
		if (filter.getActiveSourceFilterCount() == 0) {
			setStatusText("You must have at least one source category selected!");
		}
		else if (filter.getActiveTypeFilterCount() == 0) {
			setStatusText("You must have at least one symbol type selected!");
		}
		else {
			setStatusText("");
		}
	}

	private void updateAdvancedFilterEnablement() {
		String[] filterNames = filter.getAdvancedFilterNames();
		for (String filterName : filterNames) {
			JCheckBox cb = checkBoxMap.get(filterName);
			cb.setEnabled(filter.isEnabled(filterName));
		}
	}

	private void updateOkAndApply() {
		boolean b = isChanged && filter.getActiveTypeFilterCount() > 0 &&
			filter.getActiveSourceFilterCount() > 0;
		setOkEnabled(b);
		setApplyEnabled(b);
	}

	@Override
	protected void okCallback() {
		applyCallback();
		close();
	}

	@Override
	protected void applyCallback() {
		if (keyModel == null) {
			return;
		}

		if (!isChanged) {
			return;
		}

		keyModel.setFilter(new NewSymbolFilter(filter));
		setChanged(false);

		tool.setConfigChanged(true);
	}

	private void setChanged(boolean b) {
		isChanged = b;
		updateOkAndApply();
	}

	NewSymbolFilter getFilter() {
		return filter;
	}

	class FilterCheckboxItemListener implements ItemListener {
		@Override
		public void itemStateChanged(ItemEvent e) {
			if (ignoreCallbacks) {
				return;
			}
			JCheckBox cb = (JCheckBox) e.getItem();
			String name = cb.getText();
			setChanged(true);
			filter.setFilter(name, cb.isSelected());
			update();
		}
	}
}
