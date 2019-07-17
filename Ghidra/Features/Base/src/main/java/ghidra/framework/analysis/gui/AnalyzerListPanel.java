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
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GLabel;
import ghidra.app.services.Analyzer;
import ghidra.framework.analysis.*;

public class AnalyzerListPanel extends JPanel {

	private AnalysisRecipe recipe;
	private AnalysisPhase relevantPhase;
	private JList<Analyzer> jList;
	private AnalysisRecipeEditor editor;
	private AnalyzerListModel model;

	public AnalyzerListPanel(AnalysisRecipeEditor editor, AnalysisRecipe recipe,
			AnalysisPhase phase) {
		super(new BorderLayout());
		this.editor = editor;
		this.recipe = recipe;
		this.relevantPhase = phase;

		setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		JScrollPane jScrollPane = new JScrollPane(buildAnalyzerList());
		jScrollPane.setColumnHeaderView(buildHeader());
		jScrollPane.setCorner("UPPER_RIGHT_CORNER", new JPanel());
		//		jScrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		add(jScrollPane, BorderLayout.CENTER);
		if (phase != null) {
			GCheckBox checkbox =
				new GCheckBox("Create Checkpoint When Phase Completed", phase.isCheckPoint());
			checkbox.addActionListener(e -> relevantPhase.setIsCheckPoint(checkbox.isSelected()));
			add(checkbox, BorderLayout.SOUTH);
			if (phase == recipe.getLastPhase()) {
				checkbox.setEnabled(false);
			}
		}
	}

	public List<Analyzer> getSelectedAnalyzers() {
		int[] selectedIndices = jList.getSelectedIndices();
		List<Analyzer> analyzers = new ArrayList<>();
		for (int i : selectedIndices) {
			analyzers.add(model.getElementAt(i));
		}
		return analyzers;
	}

	private JList<Analyzer> buildAnalyzerList() {

		model = new AnalyzerListModel(recipe.getAnalyzers(relevantPhase));
		jList = new JList<>(model) {
			@Override
			public String getToolTipText(MouseEvent e) {
				Point p = e.getPoint();
				int row = jList.locationToIndex(p);
				Rectangle b = jList.getCellBounds(row, row);
				p.x -= b.x;
				p.y -= b.y;

				ListCellRenderer<? super Analyzer> cellRenderer = jList.getCellRenderer();
				Analyzer analyzer = jList.getModel().getElementAt(row);
				JComponent comp = (JComponent) cellRenderer.getListCellRendererComponent(jList,
					analyzer, row, true, true);
				comp.setBounds(b.x, b.y, b.width, b.height);
				JComponent c = (JComponent) SwingUtilities.getDeepestComponentAt(comp, p.x, p.y);
				return c.getToolTipText();

			}
		};
		jList.setCellRenderer(new AnalyzerCellRenderer());
		jList.setPrototypeCellValue(getAnalyzerWithLongestName());
		jList.setVisibleRowCount(14);
		jList.addMouseListener(new AnalyzerListMouseListener());
		jList.getSelectionModel().addListSelectionListener(new ListSelectionListener() {

			@Override
			public void valueChanged(ListSelectionEvent e) {
				List<Analyzer> selectedValues = jList.getSelectedValuesList();
				if (selectedValues.size() == 1) {
					editor.setSelectedAnalyzer(selectedValues.iterator().next());
				}
				else {
					editor.setSelectedAnalyzer(null);
				}
			}
		});
		jList.addKeyListener(new KeyAdapter() {

			@Override
			public void keyPressed(KeyEvent e) {
				char keyChar = e.getKeyChar();
				if (keyChar == ' ') {
					List<Analyzer> selectedValues = jList.getSelectedValuesList();
					if (selectedValues.size() == 1) {
						Analyzer analyzer = selectedValues.iterator().next();
						recipe.setAnalyzerEnablement(analyzer, !recipe.isAnalyzerEnabled(analyzer));
					}
				}
				else if (keyChar >= '1' && keyChar <= '9') {
					setPhaseForSelectedAnalyzers(keyChar - '1');
				}
			}
		});
		return jList;
	}

	private Component buildHeader() {
		JPanel panel = new JPanel(new BorderLayout());
		//	panel.setBackground(HEADER_COLOR);
		//panel.setBorder(BorderFactory.createLineBorder(Color.GRAY));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0));
		panel.add(new GLabel("ANALYZERS", SwingConstants.CENTER), BorderLayout.CENTER);
		panel.add(buildPhaseHeader(), BorderLayout.EAST);
		return panel;
	}

	private Component buildPhaseHeader() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(6, 0, 0, 0));
//		panel.add(new GLabel("START", SwingConstants.CENTER), BorderLayout.NORTH);
		panel.add(new GLabel("PHASE", SwingConstants.CENTER), BorderLayout.SOUTH);
		Dimension dim = panel.getPreferredSize();
		dim.width = getAnalysisPanelPhaseWidth();
		panel.setPreferredSize(dim);
		return panel;
	}

	private int getAnalysisPanelPhaseWidth() {

		AnalyzerPanel panel = new AnalyzerPanel(recipe.getAnalyzers().get(0), recipe, null);

		return panel.getPhasePanelWidth();
	}

	private Analyzer getAnalyzerWithLongestName() {
		List<Analyzer> analyzers = recipe.getAnalyzers();
		Analyzer longestAnalyzer = analyzers.get(0);

		AnalyzerPanel panel = new AnalyzerPanel(longestAnalyzer, recipe, null);
		int longestWidth = panel.getPreferredSize().width;
		for (Analyzer analyzer : analyzers) {
			panel.setAnalyzer(analyzer);
			if (panel.getPreferredSize().width > longestWidth) {
				longestWidth = panel.getPreferredSize().width;
				longestAnalyzer = analyzer;
			}
		}
		return longestAnalyzer;
	}

	protected void popupMenu(Point p) {
		JPopupMenu menu = new JPopupMenu("Set Phase");
		List<AnalysisPhase> phases = recipe.getAnalysisPhases();
		for (AnalysisPhase analysisPhase : phases) {
			menu.add(createMenuItem(analysisPhase));
		}
		addMenuItemToDeleteWrappedAnalyzerScripts(menu);
		menu.show(jList, p.x, p.y);
	}

	private void addMenuItemToDeleteWrappedAnalyzerScripts(JPopupMenu menu) {
		List<Analyzer> selectedValues = jList.getSelectedValuesList();
		if (selectedValues.size() != 1) {
			return;
		}
		final Analyzer analyzer = selectedValues.iterator().next();
		if (analyzer instanceof GhidraScriptAnalyzerAdapter) {
			JMenuItem jMenuItem = new JMenuItem("Delete Script Analyzer: " + analyzer.getName());
			jMenuItem.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					recipe.deleteScriptAnalyzer(analyzer);
				}
			});
			menu.addSeparator();
			menu.add(jMenuItem);
		}
	}

	private JMenuItem createMenuItem(final AnalysisPhase analysisPhase) {
		JMenuItem jMenuItem = new JMenuItem("Set Start Phase to " + analysisPhase);
		jMenuItem.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setPhaseForSelectedAnalyzers(analysisPhase.getIndex());
			}
		});
		return jMenuItem;
	}

	public void refresh() {
		model.setAnalyzers(recipe.getAnalyzers(relevantPhase));

	}

	protected void setPhaseForSelectedAnalyzers(int phaseIndex) {
		List<AnalysisPhase> phases = recipe.getAnalysisPhases();
		if (phaseIndex >= phases.size()) {
			return;
		}
		AnalysisPhase phase = phases.get(phaseIndex);
		for (Object object : jList.getSelectedValuesList()) {
			Analyzer analyzer = (Analyzer) object;
			recipe.setAnalyzerStartPhase(analyzer, phase);
		}

	}

	private class AnalyzerCellRenderer implements ListCellRenderer<Analyzer> {
		private AnalyzerPanel analyzerPanel;

		AnalyzerCellRenderer() {
			analyzerPanel = new AnalyzerPanel(recipe.getAnalyzers().get(0), recipe, relevantPhase);
		}

		@Override
		public Component getListCellRendererComponent(JList<? extends Analyzer> list,
				Analyzer value, int index, boolean isSelected, boolean cellHasFocus) {
			Analyzer analyzer = value;
			analyzerPanel.setAnalyzer(analyzer);
			analyzerPanel.setSelected(isSelected);
			return analyzerPanel;
		}

	}

	private static class AnalyzerListModel extends AbstractListModel<Analyzer> {
		private List<Analyzer> list;

		AnalyzerListModel(List<Analyzer> list) {
			this.list = list;
		}

		public void setAnalyzers(List<Analyzer> analyzers) {
			if (analyzersChanged(analyzers)) {
				list = analyzers;
				fireContentsChanged(this, 0, list.size());
			}
		}

		private boolean analyzersChanged(List<Analyzer> analyzers) {
			if (analyzers.size() != list.size()) {
				return true;
			}
			for (int i = 0; i < list.size(); i++) {
				if (analyzers.get(i) != list.get(i)) {
					return true;
				}
			}
			return false;
		}

		@Override
		public int getSize() {
			return list.size();
		}

		@Override
		public Analyzer getElementAt(int index) {
			return (list.get(index));
		}
	}

	private class AnalyzerListMouseListener extends MouseAdapter {

		@Override
		public void mouseClicked(MouseEvent e) {
			Point p = e.getPoint();
			int row = jList.locationToIndex(p);
			if (e.getButton() == MouseEvent.BUTTON1) {
				Rectangle b = jList.getCellBounds(row, row);
				p.x -= b.x;
				p.y -= b.y;
				ListCellRenderer<? super Analyzer> cellRenderer = jList.getCellRenderer();
				Analyzer analyzer = jList.getModel().getElementAt(row);
				Component comp =
					cellRenderer.getListCellRendererComponent(jList, analyzer, row, true, true);
				comp.setBounds(0, 0, b.width, b.height);
				Component c = SwingUtilities.getDeepestComponentAt(comp, p.x, p.y);
				if (c instanceof JCheckBox) {
					((JCheckBox) c).doClick();
					jList.repaint();
				}
			}
			else if (e.getButton() == MouseEvent.BUTTON3) {
				if (jList.isSelectedIndex(row)) {
					popupMenu(p);
				}
			}
		}
	}

}
