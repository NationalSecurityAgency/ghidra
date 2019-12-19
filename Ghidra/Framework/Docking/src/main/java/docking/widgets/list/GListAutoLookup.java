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
package docking.widgets.list;

import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.ListCellRenderer;

import docking.widgets.AutoLookup;

/**
 * {@link AutoLookup} implementation for {@link GList}s
 *
 * @param <T> the row type
 */
public class GListAutoLookup<T> extends AutoLookup {

	private GList<T> list;

	public GListAutoLookup(GList<T> list) {
		this.list = list;
	}

	@Override
	public int getCurrentRow() {
		return list.getSelectedIndex();
	}

	@Override
	public int getRowCount() {
		return list.getModel().getSize();
	}

	@Override
	public String getValueString(int row, int col) {
		ListCellRenderer<? super T> renderer = list.getCellRenderer();
		T value = list.getModel().getElementAt(row);
		if (!(renderer instanceof JLabel)) {
			return value.toString();
		}

		Component c = renderer.getListCellRendererComponent(list, value, row, false, false);
		return ((JLabel) c).getText();
	}

	@Override
	public boolean isSorted(int column) {
		return true;
	}

	@Override
	public boolean isSortedAscending() {
		return true;
	}

	@Override
	public void matchFound(int row) {
		list.setSelectedIndex(row);
	}

}
