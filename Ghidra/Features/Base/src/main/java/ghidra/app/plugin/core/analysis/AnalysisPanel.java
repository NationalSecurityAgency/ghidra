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
package ghidra.app.plugin.core.analysis;

import java.awt.*;
import java.beans.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.*;

import org.apache.commons.collections4.CollectionUtils;

import docking.help.Help;
import docking.help.HelpService;
import docking.options.editor.GenericOptionsComponent;
import docking.widgets.OptionDialog;
import docking.widgets.label.GLabel;
import docking.widgets.table.*;
import ghidra.GhidraOptions;
import ghidra.app.services.Analyzer;
import ghidra.framework.options.*;
import ghidra.program.model.listing.Program;
import ghidra.util.ColorUtils;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;
import ghidra.util.layout.VerticalLayout;

class AnalysisPanel extends JPanel implements PropertyChangeListener {

	public static final String PROTOTYPE = " (Prototype)";

	private final static int COLUMN_ANALYZER_IS_ENABLED = 0;
	private final static int COLUMN_ANALYZER_NAME = 1;

	private List<Program> programs;
	private PropertyChangeListener propertyChangeListener;
	private Options analysisOptions;

	private JTable table;
	private AbstractTableModel model;
	private JTextArea descriptionComponent;
	private JPanel analyzerOptionsPanel;

	private List<EditorState> editorList = new ArrayList<>();
	private List<String> analyzerNames = new ArrayList<>();
	private List<Boolean> analyzerEnablement = new ArrayList<>();
	private Set<String> prototypeAnalyzers = new HashSet<>();
	private Map<String, Component> analyzerToOptionsPanelMap = new HashMap<>();
	private Map<String, List<Component>> analyzerManagedComponentsMap = new HashMap<>();
	private EditorStateFactory editorStateFactory;

	private JPanel noOptionsPanel;

	/**
	 * Constructor
	 *
	 * @param program the programs to be analyzed
	 * @param editorStateFactory the editor factory
	 * @param propertyChangeListener subscriber for property change notifications
	 */
	AnalysisPanel(Program program, EditorStateFactory editorStateFactory,
			PropertyChangeListener propertyChangeListener) {
		this(List.of(program), editorStateFactory, propertyChangeListener);
	}

	/**
	 * Constructor
	 *
	 * @param programs list of programs that will be analyzed
	 * @param editorStateFactory the editor factory
	 * @param propertyChangeListener subscriber for property change notifications
	 */
	AnalysisPanel(List<Program> programs, EditorStateFactory editorStateFactory,
			PropertyChangeListener propertyChangeListener) {

		// Do a quick check to make sure we have at least one program. If not, we
		// shouldn't even be here (the menus should be disabled).
		if (CollectionUtils.isEmpty(programs)) {
			throw new AssertException("Must provide a program to run analysis");
		}

		this.programs = programs;
		this.propertyChangeListener = propertyChangeListener;
		this.editorStateFactory = editorStateFactory;
		analysisOptions = programs.get(0).getOptions(Program.ANALYSIS_PROPERTIES);

		setName("Analysis Panel");
		build();
		load();
	}

	private void load() {
		editorList.clear();
		analyzerNames.clear();
		analyzerEnablement.clear();
		prototypeAnalyzers.clear();
		analyzerToOptionsPanelMap.clear();
		analyzerManagedComponentsMap.clear();

		int selectedAnalyzerRow = table.getSelectedRow();

		loadAnalyzers();
		loadAnalyzerOptionsPanels();

		model.fireTableDataChanged();

		if (selectedAnalyzerRow >= 0) {
			table.setRowSelectionInterval(selectedAnalyzerRow, selectedAnalyzerRow);
		}
	}

	private void loadAnalyzers() {

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(programs.get(0));

		List<String> propertyNames = analysisOptions.getOptionNames();
		Collections.sort(propertyNames, (o1, o2) -> o1.compareToIgnoreCase(o2));
		for (String analyzerName : propertyNames) {
			if (analyzerName.indexOf('.') == -1) {
				if (analysisOptions.getType(analyzerName) != OptionType.BOOLEAN_TYPE) {
					throw new AssertException(
						"Analyzer enable property that is not boolean - " + analyzerName);
				}

				Analyzer analyzer = manager.getAnalyzer(analyzerName);
				if (analyzer != null) {
					analyzerNames.add(analyzerName);
					if (analyzer.isPrototype()) {
						prototypeAnalyzers.add(analyzerName);
					}
					analyzerEnablement.add(analysisOptions.getBoolean(analyzerName, false));
				}
			}
		}
	}

	private void build() {
		buildTableModel();
		buildTable();
		configureTableColumns();
		buildAnalyzerOptionsPanel();

		JSplitPane splitpane =
			new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildLeftPanel(), buildRightPanel());
		splitpane.setBorder(null);

		setLayout(new BorderLayout());
		setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		add(splitpane, BorderLayout.CENTER);
	}

	private void buildAnalyzerOptionsPanel() {
		analyzerOptionsPanel = new JPanel(new BorderLayout());
		configureBorder(analyzerOptionsPanel, "Options");
	}

	private Component buildRightPanel() {
		JSplitPane splitpane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buildDescriptionPanel(),
			analyzerOptionsPanel);
		splitpane.setBorder(null);
		splitpane.setDividerLocation(0.50);
		return splitpane;
	}

	private JPanel buildDescriptionPanel() {
		descriptionComponent = buildTextArea();
		JScrollPane descriptionScrollPane = new JScrollPane(descriptionComponent);
		JPanel descriptionPanel = new JPanel(new BorderLayout());
		configureBorder(descriptionScrollPane, "Description");
		descriptionPanel.add(descriptionScrollPane, BorderLayout.CENTER);
		return descriptionPanel;
	}

	private JTextArea buildTextArea() {
		JTextArea textarea = new JTextArea(3, 20);
		textarea.setEditable(false);
		textarea.setOpaque(false);
		textarea.setWrapStyleWord(true);
		textarea.setLineWrap(true);
		return textarea;
	}

	private JPanel buildLeftPanel() {
		JPanel buttonPanel = buildButtonPanel();

		JScrollPane scrollPane = new JScrollPane(table);
		scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		scrollPane.setPreferredSize(new Dimension(350, 300));

		JPanel panel = new JPanel(new BorderLayout(5, 5));
		configureBorder(panel, "Analyzers");

		panel.add(scrollPane, BorderLayout.CENTER);
		panel.add(buttonPanel, BorderLayout.SOUTH);
		return panel;
	}

	private JPanel buildButtonPanel() {
		JButton selectAllButton = new JButton("Select All");
		selectAllButton.addActionListener(e -> selectAll());
		JButton deselectAllButton = new JButton("Deselect All");
		deselectAllButton.addActionListener(e -> deselectAll());
		JButton restoreDefaultsButton = new JButton("Restore Defaults");
		restoreDefaultsButton.addActionListener(e -> restoreDefaults());
		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		buttonPanel.add(selectAllButton);
		buttonPanel.add(deselectAllButton);
		buttonPanel.add(restoreDefaultsButton);
		return buttonPanel;
	}

	private void selectAll() {
		int rowCount = model.getRowCount();
		for (int i = 0; i < rowCount; ++i) {
			model.setValueAt(true, i, COLUMN_ANALYZER_IS_ENABLED);
		}
	}

	private void deselectAll() {
		int rowCount = model.getRowCount();
		for (int i = 0; i < rowCount; ++i) {
			model.setValueAt(false, i, COLUMN_ANALYZER_IS_ENABLED);
		}
	}

	private void restoreDefaults() {
		int answer = OptionDialog.showYesNoDialog(this, "Restore Default Analysis Options",
			"Do you really want to restore the analysis options to the default values?");
		if (answer == OptionDialog.YES_OPTION) {
			AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(programs.get(0));
			manager.restoreDefaultOptions();
			editorStateFactory.clearAll();
			load();
		}
	}

	private void buildTableModel() {
		model = new AbstractTableModel() {
			private static final long serialVersionUID = 1L;

			@Override
			public Object getValueAt(int rowIndex, int columnIndex) {
				switch (columnIndex) {
					case COLUMN_ANALYZER_IS_ENABLED: {
						return analyzerEnablement.get(rowIndex);
					}
					case COLUMN_ANALYZER_NAME: {
						String analyzerName = analyzerNames.get(rowIndex);
						if (prototypeAnalyzers.contains(analyzerName)) {
							return analyzerName + PROTOTYPE;
						}
						return analyzerName;
					}
				}
				return null;
			}

			@Override
			public int getRowCount() {
				return analyzerEnablement.size();
			}

			@Override
			public int getColumnCount() {
				return 2;
			}

			@Override
			public String getColumnName(int columnIndex) {
				switch (columnIndex) {
					case COLUMN_ANALYZER_IS_ENABLED:
						return "Enabled";
					case COLUMN_ANALYZER_NAME:
						return "Analyzer Name";
				}
				return super.getColumnName(columnIndex);
			}

			@Override
			public Class<?> getColumnClass(int columnIndex) {
				switch (columnIndex) {
					case COLUMN_ANALYZER_IS_ENABLED:
						return Boolean.class;
					case COLUMN_ANALYZER_NAME:
						return String.class;
				}
				return super.getColumnClass(columnIndex);
			}

			@Override
			public boolean isCellEditable(int rowIndex, int columnIndex) {
				return columnIndex == COLUMN_ANALYZER_IS_ENABLED;
			}

			@Override
			public void setValueAt(Object value, int rowIndex, int columnIndex) {
				if (columnIndex == COLUMN_ANALYZER_IS_ENABLED) {
					Boolean enabled = (Boolean) value;
					analyzerEnablement.set(rowIndex, enabled);
					String analyzerName = analyzerNames.get(rowIndex);
					setAnalyzerEnabled(analyzerName, enabled);
					fireTableRowsUpdated(rowIndex, rowIndex);
				}
			}
		};
	}

	private void buildTable() {
		table = new GTable(model);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}

			ListSelectionModel lsm = (ListSelectionModel) e.getSource();
			int selectedRow = lsm.getMinSelectionIndex();
			if (selectedRow == -1) {
				analyzerOptionsPanel.removeAll();
				analyzerOptionsPanel.validate();
				analyzerOptionsPanel.repaint();
				descriptionComponent.setText("");
				return;
			}

			String analyzerName = analyzerNames.get(selectedRow);
			setAnalyzerSelected(analyzerName);
		});
	}

	private void setAnalyzerSelected(String analyzerName) {
		Component component = analyzerToOptionsPanelMap.get(analyzerName);
		if (component == null) {
			component = noOptionsPanel;
		}

		analyzerOptionsPanel.removeAll();
		analyzerOptionsPanel.add(component, BorderLayout.CENTER);
		analyzerOptionsPanel.validate();
		analyzerOptionsPanel.repaint();

		analyzerOptionsPanel.getParent().validate();

		String description = analysisOptions.getDescription(analyzerName);
		descriptionComponent.setText(description);
		descriptionComponent.setCaretPosition(0);
	}

	private void configureTableColumns() {
		TableColumnModel columnModel = table.getColumnModel();
		for (int i = 0; i < columnModel.getColumnCount(); ++i) {
			TableColumn column = columnModel.getColumn(i);
			int modelIndex = column.getModelIndex();
			switch (modelIndex) {
				case COLUMN_ANALYZER_IS_ENABLED: {
					configureTableColumn_IsEnabled(column, 75);
					break;
				}
				case COLUMN_ANALYZER_NAME: {
					configureTableColumn_Name(column);
					break;
				}
			}
		}
	}

	private static class AnalyzerNameTableCellRenderer extends GTableCellRenderer {
		private static final long serialVersionUID = 1L;

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			Component component = super.getTableCellRendererComponent(data);

			Object value = data.getValue();

			// Null check is necessary here; Java doesn't guarantee that the cell contents
			// passed to this method are valid.
			if (value == null) {
				return component;
			}

			String analyzerName = (String) value;

			if (analyzerName.endsWith(PROTOTYPE)) {
				component.setForeground(
					ColorUtils.deriveForeground(component.getBackground(), ColorUtils.HUE_RED));
			}

			return component;
		}
	}

	private void configureTableColumn_Name(TableColumn column) {
		column.setCellRenderer(new AnalyzerNameTableCellRenderer());
	}

	private void configureTableColumn_IsEnabled(TableColumn column, int width) {
		column.setPreferredWidth(width);
		column.setMinWidth(width);
		column.setMaxWidth(width);
		column.setResizable(false);
		column.setCellRenderer(new GBooleanCellRenderer());
	}

	/**
	 * Sets a compound border around the component consisting
	 * of a titled border and a 10 pixel wide empty border.
	 */
	private void configureBorder(JComponent component, String title) {
		Border emptyBorder = BorderFactory.createEmptyBorder(10, 10, 10, 10);
		Border titleBorder =
			BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), title);
		Border compoundBorder = BorderFactory.createCompoundBorder(titleBorder, emptyBorder);
		component.setBorder(compoundBorder);
	}

	private void setAnalyzerEnabled(String analyzerName, boolean enabled) {
		List<Component> list = analyzerManagedComponentsMap.get(analyzerName);
		if (list != null) {
			Iterator<Component> iterator = list.iterator();
			while (iterator.hasNext()) {
				Component next = iterator.next();
				next.setEnabled(enabled);
			}
		}
		propertyChange(null);
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		if (checkForDifferences()) {
			propertyChangeListener.propertyChange(
				new PropertyChangeEvent(this, GhidraOptions.APPLY_ENABLED, null, Boolean.TRUE));
		}
	}

	private boolean checkForDifferences() {
		boolean changes = false;
		for (int i = 0; i < analyzerNames.size(); ++i) {
			String analyzerName = analyzerNames.get(i);
			boolean currEnabled = analyzerEnablement.get(i);
			boolean origEnabled = analysisOptions.getBoolean(analyzerName, false);
			if (currEnabled != origEnabled) {
				changes = true;
				propertyChangeListener.propertyChange(
					new PropertyChangeEvent(this, analyzerName, origEnabled, currEnabled));
			}
		}
		if (changes) {
			return true;
		}
		for (EditorState info : editorList) {
			if (info.isValueChanged()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Updates programs with the latest option settings.
	 * <p>
	 * Details: This loops over every analyzer name in this panel and for
	 * each, updates the associated enablement for all programs being
	 * analyzed.
	 */
	void applyChanges() {

		for (int i = 0; i < analyzerNames.size(); ++i) {
			String analyzerName = analyzerNames.get(i);
			boolean enabled = analyzerEnablement.get(i);

			int id = programs.get(0).startTransaction("setting analysis options");
			boolean commit = false;
			try {
				analysisOptions.setBoolean(analyzerName, enabled);
				commit = true;
			}
			finally {
				programs.get(0).endTransaction(id, commit);
			}

			updateOptionForAllPrograms(analyzerName, enabled);
		}

		for (EditorState info : editorList) {
			info.applyValue();
		}
	}

	private void loadAnalyzerOptionsPanels() {
		List<Options> optionGroups = analysisOptions.getChildOptions();
		noOptionsPanel = new JPanel(new VerticalLayout(5));
		noOptionsPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 5));
		noOptionsPanel.add(new GLabel("No options available."));

		HelpService help = Help.getHelpService();

		for (Options optionsGroup : optionGroups) {
			String analyzerName = optionsGroup.getName();

			JPanel optionsContainer = new JPanel(new VerticalLayout(5));
			optionsContainer.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 5));

			JScrollPane scrollPane = new JScrollPane(optionsContainer);
			scrollPane.setBorder(null);

			analyzerToOptionsPanelMap.put(analyzerName, scrollPane);
			analyzerManagedComponentsMap.put(analyzerName, new ArrayList<Component>());

			List<String> optionNames = getOptionNames(optionsGroup);
			Collections.sort(optionNames);

			List<GenericOptionsComponent> optionComponents = new ArrayList<>();

			for (String childOptionName : optionNames) {

				EditorState childState =
					editorStateFactory.getEditorState(optionsGroup, childOptionName, this);
				GenericOptionsComponent comp =
					GenericOptionsComponent.createOptionComponent(childState);

				HelpLocation helpLoc = analysisOptions
						.getHelpLocation(analyzerName + Options.DELIMITER_STRING + childOptionName);
				if (helpLoc != null) {
					help.registerHelp(comp, helpLoc);
				}

				optionsContainer.add(comp);
				optionComponents.add(comp);
				analyzerManagedComponentsMap.get(analyzerName).add(comp);
				editorList.add(childState);
			}

			GenericOptionsComponent.alignLabels(optionComponents);
			Object value = analysisOptions.getObject(analyzerName, null);
			boolean enabled = true;
			if (value instanceof Boolean) {
				enabled = (Boolean) value;
			}
			setAnalyzerEnabled(analyzerName, enabled);
		}
	}

	private List<String> getOptionNames(Options optionsGroup) {
		List<String> subOptions = optionsGroup.getLeafOptionNames();
		Iterator<String> it = subOptions.iterator();
		while (it.hasNext()) {
			String next = it.next();
			if (!isEditable(optionsGroup, next)) {
				it.remove();
			}
		}
		return subOptions;
	}

	private boolean isEditable(Options options, String optionName) {
		PropertyEditor editor = options.getPropertyEditor(optionName);
		return options.getObject(optionName, null) != null || editor != null;
	}

	/**
	 * Updates the enablement of the given analyzer for all programs being analyzed.
	 * <p>
	 * A couple notes about this:
	 * 	<OL>
	 * 		<LI>
	 *	   	When a user toggles the status of an analyzer we need to update that status for
	 *	    EVERY open program. We don't want a situation where a user turns a particular
	 *		analyzer off, but it's only turned off for the selected program.
	 *		</LI>
	 *		<LI>
	 *		Programs with different architectures may have different available analyzers, but we
	 *		don't worry about that here because this class is only handed programs with
	 *		similar architectures. If this were to ever change we would need to revisit this.
	 *		</LI>
	 * </OL>
	 *
	 * @param analyzerName the name of the analyzer to update
	 * @param enabled if true, enable the analyzer; otherwise disable it
	 */
	public void updateOptionForAllPrograms(String analyzerName, boolean enabled) {
		for (Program program : programs) {

			// Check to make sure we're only handling events that relate to analyzers. If we
			// receive something else (eg: "analyze.apply") ignore it.
			Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
			if (!options.getOptionNames().contains(analyzerName)) {
				continue;
			}

			boolean commit = false;
			int id = program.startTransaction("Setting analysis property " + analyzerName);
			try {
				options.setBoolean(analyzerName, enabled);
				commit = true;
			}
			finally {
				program.endTransaction(id, commit);
			}
		}
	}
}
