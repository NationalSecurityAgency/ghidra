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
package ghidra.plugin.importer;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GDLabel;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.table.*;

public class NewLanguagePanel extends JPanel {
	private static final String DEFAULT_DESCRIPTION_TEXT = " ";

	private LanguageSortedTableModel tableModel;
	private GhidraTable table;
	private GhidraTableFilterPanel<LanguageCompilerSpecPair> tableFilterPanel;
	private JLabel descriptionLabel;
	private JCheckBox recommendedCheckbox;
	private JLabel formatLabel;

	private void setDescriptionLabelText(String text) {
		if (text == null || "".equals(text)) {
			text = " ";
		}
		descriptionLabel.setText(text);
	}

	public NewLanguagePanel() {
		constructEverything();
		layoutEverything();
		wireEverything();
		populateDefaultAllLcsPairsList();
		setVisible(true);
	}

	private void constructEverything() {
		tableModel = new LanguageSortedTableModel();

		table = new GhidraTable(tableModel);
		GhidraTableCellRenderer renderer = new GhidraTableCellRenderer();
		table.setDefaultRenderer(Processor.class, renderer);
		table.setDefaultRenderer(Endian.class, renderer);
		table.setDefaultRenderer(CompilerSpecDescription.class, renderer);

		tableFilterPanel = new GhidraTableFilterPanel<>(table, tableModel);

		descriptionLabel = new GDLabel(DEFAULT_DESCRIPTION_TEXT);
		descriptionLabel.setFont(descriptionLabel.getFont().deriveFont(Font.ITALIC));

		recommendedCheckbox = new GCheckBox("Show Only Recommended Language/Compiler Specs");
		recommendedCheckbox.addItemListener(e -> {
			switch (e.getStateChange()) {
				case ItemEvent.SELECTED:
					switchToRecommendedList();
					break;
				case ItemEvent.DESELECTED:
					switchToAllList();
					break;
				default:
					throw new RuntimeException("unknown checkbox state: " + e.getStateChange());
			}
		});

		formatLabel = new GDLabel();
		formatLabel.setHorizontalAlignment(SwingConstants.CENTER);
		formatLabel.setForeground(Messages.NORMAL);
	}

	private void layoutEverything() {
		JScrollPane scrollPane = new JScrollPane(table) {
			@Override
			public Dimension getPreferredSize() {
				// this makes us a bit smaller in height, as the preferred height can be excessive

				Dimension preferredSize = super.getPreferredSize();
				if (preferredSize.width == 0) {
					return preferredSize; // no size yet, don't change anything
				}

				preferredSize.height = 150;
				return preferredSize;
			}

		};

		JPanel descriptionPanel = new JPanel();
		Border titledBorder = BorderFactory.createTitledBorder("Description");
		descriptionPanel.setBorder(titledBorder);
		descriptionPanel.setLayout(new BorderLayout());
		descriptionPanel.add(descriptionLabel, BorderLayout.CENTER);

		JPanel innerPanel = new JPanel();
		innerPanel.setLayout(new BorderLayout());
		innerPanel.add(scrollPane, BorderLayout.CENTER);
		innerPanel.add(tableFilterPanel, BorderLayout.SOUTH);

		JPanel middlePanel = new JPanel();
		middlePanel.setLayout(new BorderLayout());
		middlePanel.add(innerPanel, BorderLayout.CENTER);
		middlePanel.add(descriptionPanel, BorderLayout.SOUTH);

		JPanel outerPanel = new JPanel();
		outerPanel.setLayout(new BorderLayout());
		outerPanel.add(middlePanel, BorderLayout.CENTER);
		outerPanel.add(recommendedCheckbox, BorderLayout.SOUTH);

		setLayout(new BorderLayout());
		add(outerPanel, BorderLayout.CENTER);
		add(formatLabel, BorderLayout.SOUTH);
	}

	private void wireEverything() {
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			notifyListeners(LcsSelectionListener.EventType.VALUE_CHANGED);
		});
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				if (e.getClickCount() == 2) {
					notifyListeners(LcsSelectionListener.EventType.VALUE_CHOSEN);
				}
			}
		});
		table.addKeyListener(new KeyListener() {
			@Override
			public void keyTyped(KeyEvent e) {
			}

			@Override
			public void keyPressed(KeyEvent e) {
				// Digits, letters, and dashes are appended to the filter text box.
				if (Character.isLetterOrDigit(e.getKeyChar()) || e.getKeyChar() == '-') {
					e.consume();
					String filterText = tableFilterPanel.getFilterText();
					tableFilterPanel.setFilterText(filterText + e.getKeyChar());
					return;
				}

				switch (e.getKeyCode()) {
					// Enter commits the selection if there is any.
					case KeyEvent.VK_ENTER:
						e.consume();

						if (table.getSelectedRows().length > 0) {
							notifyListeners(LcsSelectionListener.EventType.VALUE_CHOSEN);
						}
						break;

					// Backspace removes the last character from the filter text box.
					case KeyEvent.VK_BACK_SPACE:
						e.consume();

						String filterText = tableFilterPanel.getFilterText();
						if (!filterText.isEmpty()) {
							tableFilterPanel.setFilterText(filterText.substring(0, filterText.length() - 1));
						}
						break;

					// Left and right cursor movement events are ignored, as columns don't need to be individually
					// selected anyway.
					//
					// TODO: The proper fix for this is to add single-line selection to TableModel and GhidraTable,
					//       let's do it later.
					case KeyEvent.VK_LEFT:
					case KeyEvent.VK_RIGHT:
						e.consume();
						break;

					// TODO: Fix handling of TAB/focus change events.  Right now all focus change events are used to
					//       change the currently selected cell, which in this specific dialog does not really matter.
					//       All it has to do instead is to transfer focus to the next eligible UI element.
					default:
						break;
				}
			}

			@Override
			public void keyReleased(KeyEvent e) {
			}
		});
	}

	public void setFormatText(String text) {
		formatLabel.setText(text);
	}

	public void setShowRecommendedCheckbox(boolean show) {
		recommendedCheckbox.setVisible(show);
	}

	private boolean isOnShowAll = true;

	private boolean isAllLcsPairsTableShowing() {
		return isOnShowAll;
	}

	private boolean isRecommendedLcsPairsTableShowing() {
		return !isOnShowAll;
	}

	public void setShowAllLcsPairs(boolean show) {
		recommendedCheckbox.setSelected(!show);
	}

	private void setLanguages(List<LanguageCompilerSpecPair> lcsPairList) {
		tableModel.setLanguages(lcsPairList);
		notifyListeners(LcsSelectionListener.EventType.VALUE_CHANGED);
	}

	private void switchToAllList() {
		if (isRecommendedLcsPairsTableShowing()) {
			LanguageCompilerSpecPair selectedLcsPair = getSelectedLcsPair();
			isOnShowAll = true;
			setLanguages(allLcsPairsList);
			if (selectedLcsPair != null) {
				setSelectedLcsPair(selectedLcsPair);
			}

		}
	}

	private void switchToRecommendedList() {
		if (isAllLcsPairsTableShowing()) {
			LanguageCompilerSpecPair selectedLcsPair = getSelectedLcsPair();
			isOnShowAll = false;
			setLanguages(recommendedLcsPairsList);
			if (recommendedLcsPair != null) {
				setSelectedLcsPair(recommendedLcsPair);
			}
			else if (selectedLcsPair != null) {
				setSelectedLcsPair(selectedLcsPair);
			}
		}
	}

	private List<LanguageCompilerSpecPair> allLcsPairsList;
	private List<LanguageCompilerSpecPair> recommendedLcsPairsList;

	private LanguageCompilerSpecPair recommendedLcsPair;

	private void notifyListeners(LcsSelectionListener.EventType eventType) {
		LanguageCompilerSpecPair selectedLcsPair = getSelectedLcsPair();
		if (selectedLcsPair == null) {
			descriptionLabel.setText(DEFAULT_DESCRIPTION_TEXT);
			descriptionLabel.setFont(descriptionLabel.getFont().deriveFont(Font.ITALIC));
		}
		else {
			try {
				setDescriptionLabelText(selectedLcsPair.getLanguageDescription().getDescription());
			}
			catch (LanguageNotFoundException e) {
				descriptionLabel.setText("<LanguageNotFound>");
			}
			descriptionLabel.setFont(descriptionLabel.getFont().deriveFont(Font.PLAIN));
		}

		if (!listeners.isEmpty()) {
			LcsSelectionEvent e = new LcsSelectionEvent(selectedLcsPair);

			switch (eventType) {
				case VALUE_CHANGED: {
					for (LcsSelectionListener listener : listeners) {
						listener.valueChanged(e);
					}
					break;
				}

				case VALUE_CHOSEN: {
					for (LcsSelectionListener listener : listeners) {
						listener.valueChosen(e);
					}
					break;
				}

				default:
					break;
			}
		}
	}

	private void populateDefaultAllLcsPairsList() {
		List<LanguageCompilerSpecPair> allPairs = new ArrayList<>();
		List<LanguageDescription> languageDescriptions =
			DefaultLanguageService.getLanguageService().getLanguageDescriptions(false);
		if (languageDescriptions != null) {
			for (LanguageDescription description : languageDescriptions) {
				Collection<CompilerSpecDescription> csDescriptions =
					description.getCompatibleCompilerSpecDescriptions();
				if (csDescriptions != null) {
					for (CompilerSpecDescription csDescription : csDescriptions) {
						allPairs.add(new LanguageCompilerSpecPair(description.getLanguageID(),
							csDescription.getCompilerSpecID()));
					}
				}
			}
		}
		setAllLcsPairsList(allPairs);
	}

	public void setAllLcsPairsList(List<LanguageCompilerSpecPair> allLcsPairsList) {
		this.allLcsPairsList = allLcsPairsList;
		if (isAllLcsPairsTableShowing()) {
			setLanguages(allLcsPairsList);
		}
	}

	public void setRecommendedLcsPairsList(List<LanguageCompilerSpecPair> recommendedLcsPairsList) {
		this.recommendedLcsPairsList = recommendedLcsPairsList;
		if (isRecommendedLcsPairsTableShowing()) {
			setLanguages(recommendedLcsPairsList);
		}
	}

	public LanguageCompilerSpecPair getSelectedLcsPair() {
		LanguageCompilerSpecPair selectedLcsPair = null;
		int index = table.getSelectedRow();
		if (index != -1) {
			int selectedRow = tableFilterPanel.getModelRow(index);
			if (selectedRow != -1) {
				selectedLcsPair = tableModel.getLcsPairAtRow(selectedRow);
			}
		}
		return selectedLcsPair;
	}

	private void scrollToViewRow(int viewRow) {
		// make sure the script row is in the view (but don't scroll the x
		// coordinate)
		Rectangle visibleRect = table.getVisibleRect();
		Rectangle cellRect = table.getCellRect(viewRow, 0, true);
		cellRect.width = 0;
		cellRect.x = visibleRect.x;
		if (visibleRect.contains(cellRect)) {
			return; // already in view
		}
		table.scrollRectToVisible(cellRect);
	}

	public void clearSelection() {
		table.getSelectionModel().clearSelection();
	}

	public void setRecommendedLcsPair(LanguageCompilerSpecPair lcsPair) {
		recommendedLcsPair = lcsPair;
		setSelectedLcsPair(recommendedLcsPair);
	}

	public boolean setSelectedLcsPair(LanguageCompilerSpecPair lcsPair) {
		int index = tableModel.getFirstLcsPairIndex(lcsPair);
		if (index == -1) {
			return false;
		}
		int viewRow = tableFilterPanel.getViewRow(index);
		if (viewRow == -1) {
			return false;
		}
		table.selectRow(viewRow);
		scrollToViewRow(viewRow);
		return true;
	}

	private final Set<LcsSelectionListener> listeners = new HashSet<>();

	public void addSelectionListener(LcsSelectionListener listener) {
		listeners.add(listener);
	}

	public void removeSelectionListener(LcsSelectionListener listener) {
		listeners.remove(listener);
	}

	public void dispose() {
		tableFilterPanel.dispose();
		table.dispose();
		listeners.clear();
	}
}
