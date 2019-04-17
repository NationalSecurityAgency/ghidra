/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.debug.propertymanager;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.PropertyMap;
import ghidra.program.model.util.PropertyMapManager;

import java.util.*;

import javax.swing.table.AbstractTableModel;

/*
 * PropertyManagerTableModel
 */
class PropertyManagerTableModel extends AbstractTableModel {
	private static final long serialVersionUID = 1L;

	static final int PROPERTY_NAME_COLUMN = 0;

	String[] propertyNames;

	/**
	 * @param currentProgram
	 * @param currentSelection
	 * @param searchMarks
	 */
	public synchronized void update(Program program, AddressSetView addrSet) {
		boolean restrictedView = (addrSet != null && !addrSet.isEmpty()); 
		ArrayList<String> list = new ArrayList<String>();

		if (program != null) {
			PropertyMapManager propMgr = program.getUsrPropertyManager();
			Iterator<String> iter = propMgr.propertyManagers();
			while (iter.hasNext()) {
				String name = iter.next();
				if (restrictedView) {
					PropertyMap map = propMgr.getPropertyMap(name);
					if (map.intersects(addrSet)) {
						list.add(name);
					}
				}
				else {
					list.add(name);	
				}
			}
		}
		propertyNames = new String[list.size()];
		list.toArray(propertyNames);
		Arrays.sort(propertyNames);

		fireTableDataChanged();
	}

	/*
	 * @see javax.swing.table.TableModel#getColumnCount()
	 */
	public int getColumnCount() {
		return 1;
	}

	/*
	 * @see javax.swing.table.TableModel#getRowCount()
	 */
	public synchronized int getRowCount() {
		if (propertyNames != null) {
			return propertyNames.length;	
		}
		return 0;
	}
	
	/*
	 * @see javax.swing.table.TableModel#getColumnName(int)
	 */
	@Override
    public String getColumnName(int column) {
		return "Property Name";
	}

	/*
	 * @see javax.swing.table.TableModel#getValueAt(int, int)
	 */
	public synchronized Object getValueAt(int rowIndex, int columnIndex) {
		if (propertyNames != null && rowIndex < propertyNames.length) {	
			return propertyNames[rowIndex];
		}
		return null;
	}

	/**
	 * @param row
	 */
	protected synchronized void removeRow(int row) {
		if (propertyNames == null || row >= propertyNames.length) {
			return;
		}
		String[] newList = new String[propertyNames.length-1];
		System.arraycopy(propertyNames, 0, newList, 0, row);
		System.arraycopy(propertyNames, row+1, newList, row, newList.length-row);
		propertyNames = newList;
		fireTableDataChanged();
	}

}



