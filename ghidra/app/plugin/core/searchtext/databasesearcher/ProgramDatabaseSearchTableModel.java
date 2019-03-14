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
package ghidra.app.plugin.core.searchtext.databasesearcher;

import ghidra.app.plugin.core.searchtext.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Table model for showing results of "Search All" in a program database Text search.
 */
public class ProgramDatabaseSearchTableModel extends AbstractSearchTableModel {

	/**
	 * Constructs a program database text search table model.
	 * @param tool the tool
	 * @param p the program 
	 * @param set address set to search
	 * @param options search options
	 */
	public ProgramDatabaseSearchTableModel(PluginTool tool, Program p, AddressSetView set,
			SearchOptions options) {
		super(tool, p, set, options);
	}

	@Override
	public Searcher getSearcher(PluginTool tool, TaskMonitor monitor) {
		return new ProgramDatabaseSearcher(tool, getProgram(), null, set, options, monitor);
	}
}
