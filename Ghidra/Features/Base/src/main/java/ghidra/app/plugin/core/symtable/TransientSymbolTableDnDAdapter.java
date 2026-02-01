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
package ghidra.app.plugin.core.symtable;

import java.util.ArrayList;
import java.util.List;

import docking.widgets.table.TableUtils;
import docking.widgets.table.threaded.ThreadedTableModelListenerAdapter;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.TaskLauncher;

/**
 * A class to enable drag and drop for temporary symbol tables.
 */
public class TransientSymbolTableDnDAdapter extends SymbolTableDnDAdapter {

	private TransientSymbolTableModel model;

	public TransientSymbolTableDnDAdapter(GhidraTable table, TransientSymbolTableModel model) {
		super(table, model);
		this.model = model;
	}

	@Override
	protected void addSymbols(List<Symbol> symbols) {

		List<SymbolRowObject> rowObjects = new ArrayList<>();
		for (Symbol s : symbols) {
			rowObjects.add(new SymbolRowObject(s));
		}

		model.addInitialLoadListener(new ThreadedTableModelListenerAdapter() {
			@Override
			public void loadingFinished(boolean wasCancelled) {
				TableUtils.setSelectedItems(table, rowObjects);
			}
		});

		TaskLauncher.launchModal("Copying Symbols", () -> model.addSymbols(rowObjects));
	}
}
