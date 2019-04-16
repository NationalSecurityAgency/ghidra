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
package ghidra.framework.analysis.gui;

import java.awt.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.Border;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GDLabel;
import ghidra.app.services.Analyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.framework.analysis.AnalysisPhase;
import ghidra.framework.analysis.AnalysisRecipe;
import ghidra.util.layout.MiddleLayout;
import resources.ResourceManager;

public class AnalyzerPanel extends JPanel {

	/**
	 * A raised beveled border that works with a white background.
	 */
	private static final Border RAISED_BUTTON_BORDER = BorderFactory.createCompoundBorder(
		BorderFactory.createBevelBorder(BevelBorder.RAISED, Color.LIGHT_GRAY, Color.DARK_GRAY),
		BorderFactory.createEmptyBorder(1, 1, 1, 1));

	/**
	 * A lowered beveled border that works with a white background.
	 */
	private static final Border LOWERED_BUTTON_BORDER = BorderFactory.createCompoundBorder(
		BorderFactory.createBevelBorder(BevelBorder.LOWERED, Color.LIGHT_GRAY, Color.DARK_GRAY),
		BorderFactory.createEmptyBorder(1, 1, 1, 1));

	public static final Icon DELAYED_ICON = ResourceManager.loadImage("images/ledyellow.png");
	public static final Icon DISABLED_ICON = ResourceManager.loadImage("images/ledred.png");
	public static final Icon ENABLED_ICON = ResourceManager.loadImage("images/ledgreen.png");

	private Analyzer analyzer;
	private AnalysisRecipe recipe;
	private JCheckBox enabledCheckbox;
	private JLabel analyzerNameLabel;
	private JLabel priorityLabel;
	private JLabel iconLabel;
	private JPanel phasePanel;
	private JLabel phaseLabel;
	private AnalysisPhase relevantPhase;

	public AnalyzerPanel(Analyzer analyzer, AnalysisRecipe recipe, AnalysisPhase relevantPhase) {
		super(new BorderLayout());
		this.analyzer = analyzer;
		this.recipe = recipe;
		this.relevantPhase = relevantPhase;
		add(buildInfoPanel(), BorderLayout.CENTER);
		add(buildPhasePanel(), BorderLayout.EAST);
		setBackground(Color.WHITE);
	}

	public int getPhasePanelWidth() {
		return phasePanel.getPreferredSize().width;
	}

	private Component buildInfoPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setOpaque(false);
		panel.setBorder(BorderFactory.createEtchedBorder());

		panel.add(buildCheckboxAndIconPanel(), BorderLayout.WEST);
		panel.add(buildLabelPanel(), BorderLayout.CENTER);

		return panel;
	}

	private Component buildCheckboxAndIconPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setOpaque(false);
		panel.setBorder(BorderFactory.createEmptyBorder(2, 10, 2, 10));
		enabledCheckbox = new GCheckBox();
		enabledCheckbox.addActionListener(
			e -> recipe.setAnalyzerEnablement(analyzer, enabledCheckbox.isSelected()));

		enabledCheckbox.setSelected(recipe.isAnalyzerEnabled(analyzer));
		panel.add(enabledCheckbox, BorderLayout.WEST);

		iconLabel = new GDLabel();
		updateIconLabel();
		iconLabel.setBorder(BorderFactory.createEmptyBorder(2, 15, 2, 5));
		panel.add(iconLabel, BorderLayout.EAST);

		return panel;
	}

	private Component buildLabelPanel() {
		JPanel panel = new JPanel(new BorderLayout());
//		panel.setBorder(BorderFactory.createEtchedBorder());
		panel.setBorder(BorderFactory.createEmptyBorder(4, 10, 2, 5));
		panel.setOpaque(false);

		analyzerNameLabel = new GDLabel(analyzer.getName());
		analyzerNameLabel.setFont(analyzerNameLabel.getFont().deriveFont(18f));
		panel.add(analyzerNameLabel, BorderLayout.CENTER);

		priorityLabel = new GDLabel(analyzer.getPriority().toString());
		priorityLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		priorityLabel.setFont(priorityLabel.getFont().deriveFont(10f));
		priorityLabel.setForeground(Color.GRAY);
		panel.add(priorityLabel, BorderLayout.SOUTH);
		return panel;
	}

	private void updateIconLabel() {
		AnalyzerType analyzerType = analyzer.getAnalysisType();
		iconLabel.setToolTipText(analyzerType.getDescription());
		iconLabel.setIcon(AnalyzerUtil.getIcon(analyzerType));
	}

	private Component buildPhasePanel() {
		phasePanel = new JPanel(new MiddleLayout());
		Border empty = BorderFactory.createEmptyBorder(0, 20, 0, 20);
		Border etched = BorderFactory.createEtchedBorder();
		phasePanel.setBorder(BorderFactory.createCompoundBorder(etched, empty));
		phasePanel.setOpaque(false);
		phasePanel.setPreferredSize(new Dimension(60, 0));
		phaseLabel = new GDLabel("");

		//@formatter:off
		String text = analyzer.getAnalysisType() == AnalyzerType.ONE_SHOT_ANALYZER ? 
			  "Phase when this analyzer runs. (Select and press number to change)"
			: "Phase when this analyzer first becomes active. (Select and press number to change)";
		//@formatter:on

		phaseLabel.setToolTipText(text);
		phasePanel.setToolTipText(text);
		updatePhaseLabel();
		phasePanel.add(phaseLabel);
		return phasePanel;
	}

	public void setAnalyzer(Analyzer analyzer) {
		if (this.analyzer != analyzer) {
			this.analyzer = analyzer;
			updateInfoFields();
		}
		updateAnalyzerStatus();
		updateLabelColor();
	}

	private void updateLabelColor() {
		boolean enabled = recipe.isAnalyzerEnabled(analyzer);
		Color foreground = Color.BLACK;
		if (!enabled) {
			foreground = Color.LIGHT_GRAY;
		}
		else if (relevantPhase != null) {
			if (recipe.getAnalyzerStartPhase(analyzer) == relevantPhase) {
				foreground = Color.blue;
			}
		}
		analyzerNameLabel.setForeground(foreground);
		phaseLabel.setForeground(foreground);
	}

	private void updateAnalyzerStatus() {
		boolean enabled = recipe.isAnalyzerEnabled(analyzer);
		enabledCheckbox.setSelected(enabled);
		List<AnalysisPhase> analysisPhases = recipe.getAnalysisPhases();
		int nPhases = analysisPhases.size();
		int nPanels = phasePanel.getComponentCount();
		// if too many panels, remove extras
		for (int i = nPanels; i > nPhases; i--) {
			phasePanel.remove(i - 1);
		}
		updatePhaseLabel();
	}

	private void updatePhaseLabel() {
		if (recipe.isAnalyzerEnabled(analyzer)) {
			phaseLabel.setText(recipe.getAnalyzerStartPhase(analyzer).toString());
		}
		else {
			phaseLabel.setText("");
		}
	}

	private void updateInfoFields() {
		analyzerNameLabel.setText(analyzer.getName());
		priorityLabel.setText(analyzer.getPriority().toString());
		updateIconLabel();
	}

	public void setSelected(boolean b) {
		setBackground(b ? Color.YELLOW : Color.WHITE);
		repaint();
	}

}
