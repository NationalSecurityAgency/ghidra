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

import static ghidra.framework.model.DomainObjectEvent.*;
import static ghidra.program.util.ProgramEvent.*;

import java.util.HashSet;
import java.util.List;

import ghidra.framework.model.DomainObjectListenerBuilder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.SwingUpdateManager;
import ghidra.util.task.TaskMonitor;

/**
 * A symbol table model meant to show a temporary table of symbols.  The symbols in the table can
 * be removed from the table by the user.
 */
public class TransientSymbolTableModel extends AbstractSymbolTableModel {

	private HashSet<SymbolRowObject> rowObjects;

	private SwingUpdateManager updater = new SwingUpdateManager(this::fireTableDataChanged);

	public TransientSymbolTableModel(PluginTool tool, Program program,
			HashSet<SymbolRowObject> rowObjects) {
		super(tool);
		this.rowObjects = rowObjects;
		setProgram(program);
		symbolTable = program.getSymbolTable();

		//@formatter:off
		program.addListener(
			new DomainObjectListenerBuilder(this)
					.any(RESTORED, MEMORY_BLOCK_ADDED, MEMORY_BLOCK_REMOVED)
						.terminate(this::handleRemovedSymbols)
					.with(ProgramChangeRecord.class)
						/*
						.each(SYMBOL_REMOVED)
							.call(this::symbolRemoved)
						*/
						.any(SYMBOL_REMOVED) 
							.call(() -> symbolChanged())
						.any(CODE_ADDED, CODE_REMOVED,
							 SYMBOL_RENAMED, SYMBOL_SCOPE_CHANGED, SYMBOL_DATA_CHANGED,
							 SYMBOL_SOURCE_CHANGED,
							 SYMBOL_PRIMARY_STATE_CHANGED,
							 REFERENCE_ADDED, REFERENCE_REMOVED,
							 EXTERNAL_ENTRY_ADDED, EXTERNAL_ENTRY_REMOVED)
							     .call(() -> symbolChanged())
					.build());
		//@formatter:on
	}

	private void handleRemovedSymbols() {
		// Note: we could remove symbols from this model when they are removed from the program.
		// But, by leaving them in the table, if the users presses undo, they will still be in the
		// table.  For now, leave the deleted symbols in the table.  The user can remove them if
		// they choose.
		updater.update();
	}

	private void symbolChanged() {
		updater.update();
	}

	@Override
	protected void doLoad(Accumulator<SymbolRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {

		for (SymbolRowObject ro : rowObjects) {
			monitor.checkCancelled();
			accumulator.add(ro);
		}
	}

	/**
	 * Adds the given rows to this table
	 * @param symbolRowObjects the rows to add
	 */
	public void addSymbols(List<SymbolRowObject> symbolRowObjects) {
		for (SymbolRowObject ro : symbolRowObjects) {
			addObject(ro);
		}
		super.reload();
	}

	@Override
	public void addObject(SymbolRowObject obj) {
		rowObjects.add(obj);
		super.addObject(obj);
	}

	@Override
	public void removeObject(SymbolRowObject obj) {
		rowObjects.remove(obj);
		super.removeObject(obj);
	}

	@Override
	protected void clearData() {
		// don't allow; this will erase all table data
	}

	@Override
	public void dispose() {
		super.dispose();
		rowObjects.clear();
	}
}
