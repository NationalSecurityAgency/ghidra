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
package ghidra.feature.vt.gui.wizard;

import java.util.*;

import javax.swing.Icon;

import docking.widgets.table.AbstractGTableModel;
import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.AssertException;
import resources.ResourceManager;

public class VTProgramTableCorrelatorModel extends AbstractGTableModel<VTProgramCorrelatorFactory> {

	static final String NAME_COLUMN_NAME = "Name";
	static final String DESCRIPTION_COLUMN_NAME = "Description";
	static final String PREVIOUS_NAME = "Previous";
	static final String SELECT_NAME = "Select";

	private static final Comparator<VTProgramCorrelatorFactory> comparator =
		new Comparator<VTProgramCorrelatorFactory>() {
			@Override
			public int compare(VTProgramCorrelatorFactory o1, VTProgramCorrelatorFactory o2) {
				return o1.getPriority() - o2.getPriority();
			}
		};
	private static final Icon ALREADY_RUN_ICON = ResourceManager.loadImage("images/flag-green.png");

	private List<VTProgramCorrelatorFactory> list;
	private Set<String> previouslyRunCorrelators;
	private Set<VTProgramCorrelatorFactory> selectedFactories =
		new HashSet<>();
	private CorrelatorPanel panel;

	public VTProgramTableCorrelatorModel(CorrelatorPanel panel,
			Set<String> previouslyRunCorrelators) {
		this.panel = panel;
		this.previouslyRunCorrelators = previouslyRunCorrelators;
		list = generateList();
	}

	public List<VTProgramCorrelatorFactory> getSelectedFactories() {
		return new ArrayList<>(selectedFactories);
	}

	private static List<VTProgramCorrelatorFactory> generateList() {
		List<VTAbstractProgramCorrelatorFactory> instances =
			ClassSearcher.getInstances(VTAbstractProgramCorrelatorFactory.class);

		List<VTProgramCorrelatorFactory> list = new ArrayList<>(instances);

		Collections.sort(instances, comparator);

		return list;
	}

	@Override
	public String getName() {
		return "Correlators";
	}

	@Override
	public String getColumnName(int column) {
		switch (column) {
			case 0:
				return SELECT_NAME;
			case 1:
				return NAME_COLUMN_NAME;
			case 2:
				return PREVIOUS_NAME;
			case 3:
				return DESCRIPTION_COLUMN_NAME;
		}
		throw new AssertException("Update the column name for the newly added column");
	}

	@Override
	public Object getColumnValueForRow(VTProgramCorrelatorFactory t, int columnIndex) {
		switch (columnIndex) {
			case 0:
				return selectedFactories.contains(t);
			case 1:
				return t.getName();
			case 2:
				if (previouslyRunCorrelators.contains(t.getName())) {
					return ALREADY_RUN_ICON;
				}
				return null;
			case 3:
				return t.getDescription();
			default:
				return t;
		}
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		switch (columnIndex) {
			case 0:
				return Boolean.class;
			case 2:
				return Icon.class;
			default:
				return String.class;
		}
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return columnIndex == 0;
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		VTProgramCorrelatorFactory factory = list.get(rowIndex);
		if (((Boolean) aValue).booleanValue()) {
			selectedFactories.add(factory);
		}
		else {
			selectedFactories.remove(factory);
		}
		panel.notifyListenersOfValidityChanged();
	}

	@Override
	public List<VTProgramCorrelatorFactory> getModelData() {
		return list;
	}

	@Override
	public int getColumnCount() {
		return 4;
	}

	@Override
	public VTProgramCorrelatorFactory getRowObject(int row) {
		if (row < 0 || row >= list.size()) {
			return null;
		}
		return list.get(row);
	}
}
