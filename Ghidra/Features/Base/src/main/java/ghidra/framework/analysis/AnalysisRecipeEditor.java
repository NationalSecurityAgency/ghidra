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
package ghidra.framework.analysis;

import java.awt.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.ChangeListener;

import docking.DockingUtils;
import docking.options.editor.ScrollableOptionsEditor;
import docking.widgets.label.GDLabel;
import generic.jar.ResourceFile;
import ghidra.app.services.Analyzer;
import ghidra.framework.analysis.gui.AnalyzerListPanel;
import ghidra.framework.analysis.gui.GhidraScriptSelectionDialog;
import ghidra.framework.options.EditorStateFactory;
import ghidra.framework.options.Options;
import ghidra.util.layout.MiddleLayout;

public class AnalysisRecipeEditor {
	private JComponent mainComponent;
	private AnalysisRecipe recipe;
	private JTextArea descriptionComponent;
	private JPanel analyzerOptionsPanel;
	private Analyzer selectedAnalyzer;
	private JPanel noOptionsPanel;

	private ChangeListener changeListener = e -> refresh();
	private JTabbedPane tabbedPane;
	private ChangeListener tabListener;

	public AnalysisRecipeEditor(AnalysisRecipe recipe) {
		this.recipe = recipe;
		mainComponent = buildComponent();
		recipe.setChangeListener(changeListener);

		buildNoOptionsPanel();

	}

	private void buildNoOptionsPanel() {
		noOptionsPanel = new JPanel(new MiddleLayout());
		noOptionsPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 5));
		JLabel label = new GDLabel("No options available.");
		label.setFont(label.getFont().deriveFont(20f));
		noOptionsPanel.add(label);
	}

	private void refresh() {
		refreshAnalyzerPanel();
	}

	private JComponent buildComponent() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(buildLeftPanel(), BorderLayout.WEST);
		panel.add(buildRightPanel(), BorderLayout.CENTER);
		panel.add(buildButtonPanel(), BorderLayout.SOUTH);
		return panel;
	}

	private Component buildButtonPanel() {
		JPanel panel = new JPanel(new FlowLayout());

		JButton addScriptButton = new JButton("Add script");
		JButton addPhaseButton = new JButton("Add Phase");
		JButton removePhaseButton = new JButton("Remove Phase");

		addPhaseButton.addActionListener(e -> {
			if (recipe.getAnalysisPhases().size() < 9) {
				recipe.createPhase();
			}
		});
		removePhaseButton.addActionListener(e -> recipe.deletePhase());
		addScriptButton.addActionListener(e -> {
			GhidraScriptSelectionDialog dialog = new GhidraScriptSelectionDialog();
			ResourceFile file = dialog.show(mainComponent);
			if (file != null) {
				recipe.addScriptAnalyzer(file, dialog.getAnalyzerType(), dialog.getPriority());
			}
		});
		panel.add(addScriptButton);
		panel.add(addPhaseButton);
		panel.add(removePhaseButton);

		return panel;
	}

	private Component buildRightPanel() {
		analyzerOptionsPanel = new JPanel(new BorderLayout());
		configureBorder(analyzerOptionsPanel, "Analyzer Options");
		/*
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(buildDescriptionPanel(), BorderLayout.NORTH);
		panel.add(analyzerOptionsPanel, BorderLayout.CENTER);
		return panel;
		*/
		JSplitPane splitpane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buildDescriptionPanel(),
			analyzerOptionsPanel);
		splitpane.setResizeWeight(.2);
		splitpane.setBorder(BorderFactory.createEmptyBorder(10, 6, 8, 6));
		splitpane.setDividerLocation(0.50);
		return splitpane;
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

	private JPanel buildDescriptionPanel() {
		descriptionComponent = buildTextArea();
		JScrollPane descriptionScrollPane = new JScrollPane(descriptionComponent);
		DockingUtils.setTransparent(descriptionScrollPane);
		JPanel descriptionPanel = new JPanel(new BorderLayout());
		configureBorder(descriptionScrollPane, "Analyzer Description");
		descriptionPanel.add(descriptionScrollPane, BorderLayout.CENTER);
		return descriptionPanel;
	}

	private JTextArea buildTextArea() {
		JTextArea textarea = new JTextArea(3, 60);
		textarea.setEditable(false);
		textarea.setWrapStyleWord(true);
		textarea.setLineWrap(true);
		textarea.setFont(textarea.getFont().deriveFont(18f));
		return textarea;
	}

	private Component buildLeftPanel() {
		tabbedPane = new JTabbedPane();
		tabListener = e -> {
			AnalyzerListPanel panel = (AnalyzerListPanel) tabbedPane.getSelectedComponent();
			List<Analyzer> selectedAnalyzers = panel.getSelectedAnalyzers();
			setSelectedAnalyzer(selectedAnalyzers.size() == 1 ? selectedAnalyzers.get(0) : null);
		};
		populateTabs();
		tabbedPane.addChangeListener(tabListener);
		return tabbedPane;
	}

	private void populateTabs() {
		tabbedPane.addTab("All", new AnalyzerListPanel(this, recipe, null));

		List<AnalysisPhase> phases = recipe.getAnalysisPhases();
		for (int i = 0; i < phases.size(); i++) {
			AnalysisPhase phase = phases.get(i);
			tabbedPane.addTab("Phase " + (i + 1), new AnalyzerListPanel(this, recipe, phase));
		}
		tabbedPane.setSelectedIndex(0);
	}

	private void refreshAnalyzerPanel() {
		tabbedPane.removeChangeListener(tabListener);
		List<AnalysisPhase> phases = recipe.getAnalysisPhases();
		int tabCount = tabbedPane.getTabCount();
		if (tabCount != phases.size() + 1) {
			tabbedPane.removeAll();
			populateTabs();
			return;
		}
		for (int i = 0; i < tabCount; i++) {
			AnalyzerListPanel comp = (AnalyzerListPanel) tabbedPane.getComponentAt(i);
			comp.refresh();
		}
		tabbedPane.addChangeListener(tabListener);
		mainComponent.validate();
		mainComponent.repaint();
	}

	public JComponent getComponent() {
		return mainComponent;
	}

	public void setSelectedAnalyzer(Analyzer analyzer) {

		selectedAnalyzer = analyzer;
		String description = analyzer != null ? analyzer.getDescription() : "";
		descriptionComponent.setText(description);
		descriptionComponent.setCaretPosition(0);
		updateOptionsPanel();
		mainComponent.validate();
		analyzerOptionsPanel.repaint();
	}

	private void updateOptionsPanel() {
		analyzerOptionsPanel.removeAll();
		analyzerOptionsPanel.invalidate();
		if (selectedAnalyzer == null) {
			return;
		}
		Options options = recipe.getOptions(selectedAnalyzer);
		List<String> optionNames = options.getLeafOptionNames();
		if (optionNames.isEmpty()) {
			analyzerOptionsPanel.add(noOptionsPanel);
			return;
		}
		ScrollableOptionsEditor editorPanel =
			new ScrollableOptionsEditor("Options For " + selectedAnalyzer.getName(), options,
				optionNames, new EditorStateFactory());
		editorPanel.setBorder(BorderFactory.createEmptyBorder());
		analyzerOptionsPanel.add(editorPanel);
	}

}
