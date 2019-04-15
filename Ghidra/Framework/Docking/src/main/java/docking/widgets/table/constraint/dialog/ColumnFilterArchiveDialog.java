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
/**
 *
 */
package docking.widgets.table.constraint.dialog;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Objects;

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.DialogComponentProvider;
import docking.widgets.label.GDHtmlLabel;
import docking.widgets.table.columnfilter.ColumnBasedTableFilter;
import docking.widgets.table.columnfilter.ColumnFilterSaveManager;
import ghidra.util.HTMLUtilities;
import resources.Icons;

/**
 * Dialog for loading saved ColumnFilters.
 *
 * @param <R> the row type of the table being filtered.
 */
public class ColumnFilterArchiveDialog<R> extends DialogComponentProvider {

	private ColumnFilterSaveManager<R> manager;
	private JLabel previewLabel;
	private JButton removeSelectedFiltersButton;
	private ColumnBasedTableFilter<R> selectedColumnFilter = null;
	private JList<ColumnBasedTableFilter<R>> jList;

	private ColumnFilterDialog<R> filterDialog;

	protected ColumnFilterArchiveDialog(ColumnFilterDialog<R> filterDialog,
			ColumnFilterSaveManager<R> manager, String tableName) {

		super(getDialogTitle(tableName), true /*modal*/, false /*includeStatus*/,
			true /*includeButtons*/, false /*canRunTasks*/);
		this.filterDialog = filterDialog;

		Objects.requireNonNull(manager, "ColumnFilterSaveManager must be non-null");
		this.manager = manager;

		addWorkPanel(buildComponent());
		addOKButton();
		addCancelButton();
		setOkButtonText("Load");
		okButton.setMnemonic('L');
		setOkEnabled(true);
		setPreferredSize(800, 300);
		setRememberSize(true);
	}

	private static String getDialogTitle(String tableName) {
		StringBuilder sb = new StringBuilder("Saved Table Column Filters");
		if (!StringUtils.isBlank(tableName)) {
			sb.append(" for '").append(tableName).append("'");
		}
		return sb.toString();
	}

	private JComponent buildComponent() {

		JComponent component = buildFilterTable();
		component.setPreferredSize(new Dimension(100, 200));

		JSplitPane splitter =
			new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, component, buildPreviewPanel());
		splitter.setResizeWeight(.25);

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(splitter, BorderLayout.CENTER);
		return panel;
	}

	ColumnBasedTableFilter<R> getSelectedColumnFilter() {
		return selectedColumnFilter;
	}

	@Override
	public void okCallback() {
		close();
	}

	@Override
	public void cancelCallback() {
		selectedColumnFilter = null;
		super.cancelCallback();
	}

	private JComponent buildFilterTable() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(buildFilterList(), BorderLayout.CENTER);
		panel.add(buildActionPanel(), BorderLayout.SOUTH);
		return panel;
	}

	private JComponent buildFilterList() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createTitledBorder(
			BorderFactory.createEmptyBorder(19, 0, 0, 5), "Filter Names"));

		jList = new JList<>();
		jList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		jList.addListSelectionListener(e -> listSelectionChanged(jList.getSelectedValue()));
		jList.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() > 1) {
					okCallback();
				}
			}
		});
		updateList();

		panel.add(new JScrollPane(jList));
		return panel;
	}

	private JComponent buildActionPanel() {
		ImageIcon icon = Icons.DELETE_ICON;

		removeSelectedFiltersButton = new JButton("Remove", icon);
		removeSelectedFiltersButton.setEnabled(false);
		removeSelectedFiltersButton.addActionListener(e -> removeSelectedFilter());

		JPanel buttonPanel = new JPanel(new BorderLayout());
		buttonPanel.add(removeSelectedFiltersButton, BorderLayout.EAST);

		return buttonPanel;
	}

	private Component buildPreviewPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createTitledBorder(
			BorderFactory.createEmptyBorder(19, 0, 26, 5), "Preview"));

		previewLabel = new GDHtmlLabel();
		previewLabel.setVerticalAlignment(SwingConstants.TOP);
		panel.add(new JScrollPane(previewLabel));
		return panel;
	}

	private void updateList() {
		jList.setModel(new AbstractListModel<ColumnBasedTableFilter<R>>() {

			@Override
			public int getSize() {
				return manager.getSavedFilters().size();
			}

			@Override
			public ColumnBasedTableFilter<R> getElementAt(int index) {
				return manager.getSavedFilters().get(index);
			}
		});
	}

	private void listSelectionChanged(ColumnBasedTableFilter<R> selectedFilter) {
		this.selectedColumnFilter = selectedFilter;
		updatePreview();
		removeSelectedFiltersButton.setEnabled(selectedFilter != null);
		setOkEnabled(selectedFilter != null);
	}

	private void removeSelectedFilter() {
		ColumnBasedTableFilter<R> filter = selectedColumnFilter;
		manager.removeFilter(filter);
		manager.save();
		updateList();
		filterDialog.filterRemoved(filter);
	}

	private void updatePreview() {
		if (selectedColumnFilter != null) {
			previewLabel.setText(
				HTMLUtilities.wrapAsHTML(selectedColumnFilter.getHtmlRepresentation()));
		}
		else {
			previewLabel.setText("");
		}
	}
}
