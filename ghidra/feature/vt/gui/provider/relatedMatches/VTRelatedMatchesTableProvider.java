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
package ghidra.feature.vt.gui.provider.relatedMatches;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableCellRenderer;

import docking.ActionContext;
import docking.widgets.table.GTable;
import docking.widgets.table.RowObjectTableModel;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.feature.vt.api.util.VTRelatedMatch;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.table.*;
import resources.ResourceManager;

public class VTRelatedMatchesTableProvider extends ComponentProviderAdapter {

	private static final Icon ICON = ResourceManager.loadImage("images/user-online.png");

	private JComponent component;

	private MarkupItemThreadedTablePanel tablePanel;
	private GhidraTable relatedMatchesTable;
	private ListSelectionListener matchSelectionListener;
	private VTRelatedMatchTableModel relatedMatchesTableModel;
	private GhidraTableFilterPanel<VTRelatedMatch> markupFilterPanel;
	private Set<VTRelatedMatchSelectionListener> relatedMatchListeners =
		new HashSet<VTRelatedMatchSelectionListener>();

	private final VTController controller;

	public VTRelatedMatchesTableProvider(PluginTool tool, VTController controller) {
		super(tool, "Version Tracking Related Matches", VTPlugin.OWNER);
		this.controller = controller;

		component = createComponent();

		setWindowGroup(VTPlugin.WINDOW_GROUP);
		setIcon(ICON);

		createActions();
		addToTool();
	}

	private JComponent createComponent() {

		relatedMatchesTable = createRelatedMatchTable();
		markupFilterPanel =
			new GhidraTableFilterPanel<VTRelatedMatch>(relatedMatchesTable,
				relatedMatchesTableModel);
		JPanel markupItemsTablePanel = new JPanel(new BorderLayout());
		markupItemsTablePanel.add(tablePanel, BorderLayout.CENTER);
		markupItemsTablePanel.add(markupFilterPanel, BorderLayout.SOUTH);

		return markupItemsTablePanel;
	}

	private GhidraTable createRelatedMatchTable() {
		relatedMatchesTableModel = new VTRelatedMatchTableModel(controller);
		tablePanel = new MarkupItemThreadedTablePanel(relatedMatchesTableModel);
		final GhidraTable table = tablePanel.getTable();

		matchSelectionListener = new ListSelectionListener() {
			@Override
			@SuppressWarnings("unchecked")
			// it's our model, it must be our type
			public void valueChanged(ListSelectionEvent e) {
				if (e.getValueIsAdjusting()) {
					return;
				}

				// we get out the model here in case it has been wrapped by one of the filters
				RowObjectTableModel<VTRelatedMatch> model =
					(RowObjectTableModel<VTRelatedMatch>) table.getModel();
				int selectedRow = table.getSelectedRow();
				VTRelatedMatch relatedMatch = model.getRowObject(selectedRow);
				if (relatedMatch == null) {
					return; // this can happen due to threaded table loading
				}

				notifyContextChanged();
				fireRelatedMatchSelected(relatedMatch);
			}
		};
		ListSelectionModel selectionModel = table.getSelectionModel();
		selectionModel.addListSelectionListener(matchSelectionListener);

		// override the default behavior so we see our columns in their preferred size
		Dimension size = table.getPreferredScrollableViewportSize();
		Dimension preferredSize = table.getPreferredSize();

		// ...account for the scroll bar width
		JScrollBar scrollBar = new JScrollBar(Adjustable.VERTICAL);
		Dimension scrollBarSize = scrollBar.getMinimumSize();
		size.width = preferredSize.width + scrollBarSize.width;
		table.setPreferredScrollableViewportSize(size);

		return table;
	}

	private void createActions() {
//        addLocalAction( new AddMarkupItemAction( this ) );
//        addLocalAction( new IgnoreMarkupItemAction( this ) );
	}

	private void notifyContextChanged() {
		tool.contextChanged(this);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
//		List<VTRelatedMatch> selectedItems = getSelectedMatches();
//      return new MarkupItemContext( this, selectedItems );
		return null;
	}

	private List<VTRelatedMatch> getSelectedMatches() {
		List<VTRelatedMatch> list = new ArrayList<VTRelatedMatch>();
		int[] selectedRows = relatedMatchesTable.getSelectedRows();
		for (int row : selectedRows) {
			list.add(relatedMatchesTableModel.getRowObject(row));
		}
		return list;
	}

	public void refresh() {
		relatedMatchesTableModel.reload();
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	public void dispose() {
		// must remove the listener first to avoid callback whilst we are dipsosing
		ListSelectionModel selectionModel = relatedMatchesTable.getSelectionModel();
		selectionModel.removeListSelectionListener(matchSelectionListener);

		relatedMatchesTableModel.dispose();
		markupFilterPanel.dispose();
		removeFromTool();
	}

	public void addRelatedMatchSelectionListener(VTRelatedMatchSelectionListener listener) {
		relatedMatchListeners.add(listener);
	}

	private void fireRelatedMatchSelected(VTRelatedMatch relatedMatch) {
		for (VTRelatedMatchSelectionListener listener : relatedMatchListeners) {
			listener.relatedMatchSelected(relatedMatch);
		}
	}

	@Override
	public void componentShown() {
		reload();
	}

	public void reload() {
		if (!isVisible()) {
			return;
		}
		relatedMatchesTableModel.reload();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class MarkupItemThreadedTablePanel extends GhidraThreadedTablePanel<VTRelatedMatch> {
		MarkupItemThreadedTablePanel(ThreadedTableModel<VTRelatedMatch, ?> model) {
			super(model);
		}

		@Override
		protected GTable createTable(ThreadedTableModel<VTRelatedMatch, ?> model) {
			return new GhidraTable(relatedMatchesTableModel) {

				private TableCellRenderer renderer = new RelatedMatchRenderer();

				@Override
				public TableCellRenderer getCellRenderer(int row, int col) {
					return renderer;
				}
			};
		}
	}

}
