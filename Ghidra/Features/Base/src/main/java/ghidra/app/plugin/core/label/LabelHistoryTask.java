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
package ghidra.app.plugin.core.label;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.LabelHistory;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.UserSearchUtils;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.SwingUtilities;

public class LabelHistoryTask extends Task {
	private Pattern regexp;
	private String dialogTitle;
	private List<LabelHistory> historyList;
	private Program program;
	private final PluginTool tool;

	LabelHistoryTask(PluginTool tool, Program program, String matchStr) {
		super("Get All Label History", true, false, true);
		this.tool = tool;
		this.program = program;
		if (matchStr != null) {
			regexp = UserSearchUtils.createSearchPattern(matchStr, false);
			dialogTitle = "Label History Matching " + matchStr;
		}
		else {
			dialogTitle = "All Label History";
		}
	}

	@Override
	public void run(final TaskMonitor monitor) {
		SymbolTable st = program.getSymbolTable();
		historyList = new ArrayList<LabelHistory>();
		Iterator<LabelHistory> iter = st.getLabelHistory();
		int count = 0;
		while (iter.hasNext()) {
			LabelHistory h = iter.next();
			if (regexp != null) {
				Matcher matcher = regexp.matcher(h.getLabelString());
				if (matcher.find()) {
					historyList.add(h);
				}
			}
			else {
				historyList.add(h);
			}
			++count;
			if (count == 50) {
				count = 0;
				if (monitor.isCancelled()) {
					break;
				}
			}
		}

		super.notifyTaskListeners(monitor.isCancelled());

		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				if (!monitor.isCancelled()) {
					if (historyList.size() > 0) {
						LabelHistoryDialog dialog =
							new LabelHistoryDialog(tool, program, dialogTitle, historyList);
						tool.showDialog(dialog);
					}
				}
			}
		});
	}

	boolean labelsFound() {
		return historyList.size() > 0;
	}
}
