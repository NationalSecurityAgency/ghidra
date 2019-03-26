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

import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.LabelHistory;
import ghidra.program.util.CodeUnitLocation;
import ghidra.util.HelpLocation;

import java.util.List;

import docking.DialogComponentProvider;

public class LabelHistoryDialog extends DialogComponentProvider implements LabelHistoryListener {
	private final PluginTool tool;

	public LabelHistoryDialog(PluginTool tool, Program program, Address addr,
			List<LabelHistory> list) {
		super((addr != null) ? "Show Label History for " + addr : "Show Label History", true);
		this.tool = tool;
		addWorkPanel(new LabelHistoryPanel(program, list, null));
		initialize();
	}

	public LabelHistoryDialog(PluginTool tool, Program program, String title,
			List<LabelHistory> list) {
		super(title, true);
		this.tool = tool;
		addWorkPanel(new LabelHistoryPanel(program, list, this));
		initialize();
	}

	private void initialize() {
		addDismissButton();
		setHelpLocation(new HelpLocation(HelpTopics.LABEL, "Show_Label_History"));
	}

	@Override
	public void addressSelected(Program program, Address addr) {
		GoToService service = tool.getService(GoToService.class);
		if (service != null) {
			service.goTo(new CodeUnitLocation(program, addr, null, 0, 0, 0));
		}
	}
}
