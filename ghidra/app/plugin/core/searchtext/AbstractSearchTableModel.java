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
package ghidra.app.plugin.core.searchtext;

import ghidra.GhidraOptions;
import ghidra.app.util.PluginConstants;
import ghidra.app.util.query.ProgramLocationPreviewTableModel;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Table model for showing the results of a "Search All"
 */
public abstract class AbstractSearchTableModel extends ProgramLocationPreviewTableModel {

	private final static int DEFAULT_SEARCH_LIMIT = 500;
	final static String TITLE = "Text Search";

	protected SearchOptions options;
	protected int searchLimit;
	protected AddressSetView set;
	protected boolean showBlockName;

	private PluginTool tool;

	public AbstractSearchTableModel(PluginTool tool, Program p, AddressSetView set,
			SearchOptions options) {

		super(TITLE, tool, p, null, true);
		this.tool = tool;
		this.set = set;
		this.options = options;
		Options opt = tool.getOptions(PluginConstants.SEARCH_OPTION_NAME);
		searchLimit = opt.getInt(GhidraOptions.OPTION_SEARCH_LIMIT, DEFAULT_SEARCH_LIMIT);
	}

	@Override
	protected void doLoad(Accumulator<ProgramLocation> accumulator, TaskMonitor monitor)
			throws CancelledException {
		Searcher searcher = getSearcher(tool, monitor);
		monitor.checkCanceled();
		ProgramLocation loc = searcher.search();
		while (loc != null && accumulator.size() < searchLimit) {
			accumulator.add(loc);
			monitor.checkCanceled();
			loc = searcher.search();
		}
	}

	/**
	 * Get the Searcher that does the text search
	 * 
	 * @param pluginTool the tool
	 * @param monitor the monitor
	 * @return the searcher to use for searching
	 */
	protected abstract Searcher getSearcher(PluginTool pluginTool, TaskMonitor monitor);
}
