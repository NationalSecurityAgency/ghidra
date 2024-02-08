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
package ghidra.app.plugin.core.debug.disassemble;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.core.debug.disassemble.CurrentPlatformTraceDisassembleCommand.Reqs;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;

public class CurrentPlatformTraceDisassembleAction extends DockingAction {
	private static final String NAME = "Disassemble";
	private static final String MENU_GROUP = "Disassembly";
	private static final KeyBindingData KEY_BINDING = new KeyBindingData("D");

	private final PluginTool tool;

	public CurrentPlatformTraceDisassembleAction(DebuggerDisassemblerPlugin plugin) {
		super(NAME, plugin.getName());
		this.tool = plugin.getTool();

		setPopupMenuData(new MenuData(new String[] { NAME }, MENU_GROUP));
		setKeyBindingData(KEY_BINDING);
		setHelpLocation(new HelpLocation(plugin.getName(), "disassemble"));
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		Reqs reqs = Reqs.fromContext(tool, context);
		return reqs != null;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		Reqs reqs = Reqs.fromContext(tool, context);
		if (reqs == null) {
			return false;
		}
		return super.isEnabledForContext(context);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Reqs reqs = Reqs.fromContext(tool, context);
		if (reqs == null) {
			return;
		}
		ListingActionContext lac = (ListingActionContext) context;
		Address address = lac.getAddress();
		AddressSpace space = address.getAddressSpace();
		AddressSetView set;
		ProgramSelection selection = lac.getSelection();
		if (selection != null && !selection.isEmpty()) {
			set = selection;
		}
		else {
			set = reqs.view()
					.getAddressFactory()
					.getAddressSet(space.getMinAddress(), space.getMaxAddress());
		}
		CurrentPlatformTraceDisassembleCommand cmd =
			new CurrentPlatformTraceDisassembleCommand(tool, set, reqs, address);
		cmd.run(tool, reqs.view());
	}
}
