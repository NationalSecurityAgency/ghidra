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
package ghidra.app.plugin.core.debug.utils;

import java.util.function.Function;

import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import docking.widgets.table.RowWrappedEnumeratedColumnTableModel;
import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.util.Swing;

public class DebouncedRowWrappedEnumeratedColumnTableModel<C extends Enum<C> & EnumeratedTableColumn<C, R>, K, R, T>
		extends RowWrappedEnumeratedColumnTableModel<C, K, R, T> {

	AsyncDebouncer<Void> debouncer = new AsyncDebouncer<Void>(AsyncTimer.DEFAULT_TIMER, 100);

	public DebouncedRowWrappedEnumeratedColumnTableModel(String name, Class<C> colType,
			Function<T, K> keyFunc, Function<T, R> wrapper) {
		super(name, colType, keyFunc, wrapper);

		debouncer.addListener(this::settled);
	}

	@Override
	public void fireTableDataChanged() {
		debouncer.contact(null);
	}

	@Override
	public void fireTableCellUpdated(int row, int column) {
		debouncer.contact(null);
	}

	@Override
	public void fireTableRowsDeleted(int firstRow, int lastRow) {
		debouncer.contact(null);
	}

	@Override
	public void fireTableRowsInserted(int firstRow, int lastRow) {
		debouncer.contact(null);
	}

	@Override
	public void fireTableRowsUpdated(int firstRow, int lastRow) {
		debouncer.contact(null);
	}

	// NB. Let structure changes get processed immediately

	private void settled(Void __) {
		// Just refresh the whole thing
		Swing.runLater(() -> super.fireTableDataChanged());
	}
}
