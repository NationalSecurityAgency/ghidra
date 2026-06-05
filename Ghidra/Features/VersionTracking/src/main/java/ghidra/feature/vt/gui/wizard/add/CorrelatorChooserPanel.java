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
package ghidra.feature.vt.gui.wizard.add;

import java.awt.*;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.feature.vt.api.impl.VTProgramCorrelatorInfo;
import ghidra.feature.vt.api.main.*;
import ghidra.util.table.GhidraTable;
import utility.function.Callback;

/**
 * Panel for displaying and choosing from a list of version tracking correlators. Used by the
 * {@link CorrelatorChooserStep} of the "add to version tracking session" wizard.
 */
public class CorrelatorChooserPanel extends JPanel {

	private VTProgramTableCorrelatorModel model;
	private GhidraTable table;
	private Callback statusChangedCallback;

	CorrelatorChooserPanel(VTSession session, Callback statusChangedCallback) {
		setLayout(new BorderLayout());
		table = createBasicTable(getPreviouslyRunAlgorithms(session));
		add(new JScrollPane(table), BorderLayout.CENTER);
		this.statusChangedCallback = statusChangedCallback;
	}

	private GhidraTable createBasicTable(Set<String> previouslyRunCorrelators) {
		// default model with no cell editing
		model = new VTProgramTableCorrelatorModel(this, previouslyRunCorrelators);
		table = new GhidraTable(model);
		table.setRowSelectionAllowed(false);
		table.setColumnSelectionAllowed(false);
		table.setColumnHeaderPopupEnabled(false);
		table.setDefaultRenderer(Icon.class, new PreviouslyRunColumnRenderer());

		setColumnSizes();

		return table;
	}

	@Override
	public Dimension getPreferredSize() {
		return new Dimension(1000, 400);
	}

	void notifyStatusChanged() {
		statusChangedCallback.call();

	}

	private void setColumnSizes() {
		TableColumnModel columnModel = table.getColumnModel();
		int width = 0;
		for (int col = 0; col < columnModel.getColumnCount(); col++) {
			TableColumn column = columnModel.getColumn(col);
			if (VTProgramTableCorrelatorModel.SELECT_NAME.equals(column.getHeaderValue())) {
				width = 30;
				column.setMinWidth(width);
			}
			else if (VTProgramTableCorrelatorModel.NAME_COLUMN_NAME.equals(
				column.getHeaderValue())) {
				width = 250;
			}
			else if (VTProgramTableCorrelatorModel.PREVIOUS_NAME.equals(column.getHeaderValue())) {
				width = 30;
				column.setMinWidth(width);
			}
			else if (VTProgramTableCorrelatorModel.DESCRIPTION_COLUMN_NAME.equals(
				column.getHeaderValue())) {
				width = 650;
			}

			column.setPreferredWidth(width);
		}
	}

	private Set<String> getPreviouslyRunAlgorithms(VTSession session) {
		Set<String> set = new HashSet<>();
		java.util.List<VTMatchSet> matchSets = session.getMatchSets();
		for (VTMatchSet vtMatchSet : matchSets) {
			VTProgramCorrelatorInfo info = vtMatchSet.getProgramCorrelatorInfo();
			set.add(info.getName());
		}
		return set;
	}

	public List<VTProgramCorrelatorFactory> getSelectedCorrelators() {
		return model.getSelectedFactories();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class PreviouslyRunColumnRenderer extends GTableCellRenderer {

		PreviouslyRunColumnRenderer() {
			setHorizontalAlignment(SwingConstants.CENTER);
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

			Object value = data.getValue();

			renderer.setIcon((Icon) value);
			renderer.setText(null);
			renderer.setToolTipText(
				value == null ? null : "Correlator has already been run at least once.");
			return renderer;
		}
	}

}
