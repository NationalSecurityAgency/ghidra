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
package ghidra.app.plugin.core.label;

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.LabelHistory;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import docking.action.KeyBindingData;
import docking.action.MenuData;

public class LabelHistoryAction extends ListingContextAction {

	private final PluginTool tool;

	public LabelHistoryAction(PluginTool tool, String owner) {
		super("Show Label History", owner);
		this.tool = tool;
		setPopupMenuData(new MenuData(new String[] { "Show Label History..." }, null, "Label"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_H, 0));

	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		return context.getAddress() != null;
	}

	@Override
	protected void actionPerformed(ListingActionContext context) {
		Address addr = context.getAddress();
		ProgramLocation location = context.getLocation();
		if (location instanceof OperandFieldLocation) {
			Address a = ((OperandFieldLocation) location).getRefAddress();
			if (a != null) {
				addr = a;
			}
		}
		List<LabelHistory> list = getHistoryList(context.getProgram(), addr);
		if (list.size() > 0) {
			LabelHistoryDialog dialog =
				new LabelHistoryDialog(tool, context.getProgram(), addr, getHistoryList(
					context.getProgram(), addr));
			tool.showDialog(dialog);
		}
		else {
			Msg.showInfo(getClass(), tool.getToolFrame(), "History Not Found",
				"No Label History was found at address: " + addr);
		}
	}

	private List<LabelHistory> getHistoryList(Program program, Address addr) {
		List<LabelHistory> list = new ArrayList<LabelHistory>();
		LabelHistory[] history = program.getSymbolTable().getLabelHistory(addr);
		for (int i = 0; i < history.length; i++) {
			list.add(history[i]);
		}
		return list;
	}

}
