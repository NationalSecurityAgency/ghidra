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
package ghidra.app.plugin.core.strings;

import java.util.List;
import java.util.function.Predicate;

import docking.ActionContext;
import ghidra.app.context.DataLocationListContext;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.GhidraTable;

public class ViewStringsContext extends ActionContext implements DataLocationListContext {

	private ViewStringsProvider viewStringsProvider;

	ViewStringsContext(ViewStringsProvider provider, GhidraTable stringsTable) {
		super(provider, stringsTable);
		viewStringsProvider = provider;
	}

	GhidraTable getStringsTable() {
		return (GhidraTable) getContextObject();
	}

	@Override
	public int getCount() {
		return viewStringsProvider.getSelectedRowCount();
	}

	@Override
	public Program getProgram() {
		return viewStringsProvider.getProgram();
	}

	@Override
	public List<ProgramLocation> getDataLocationList() {
		return viewStringsProvider.getSelectedDataLocationList(null);
	}

	@Override
	public List<ProgramLocation> getDataLocationList(Predicate<Data> filter) {
		return viewStringsProvider.getSelectedDataLocationList(filter);
	}
}
