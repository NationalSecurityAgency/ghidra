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
/*
 * Created on Feb 1, 2005
 *
 */
package ghidra.app.plugin.core.disassembler;

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import docking.action.MenuData;

/**
 * Action for static disassembly
 */

class StaticDisassembleAction extends ListingContextAction {
	private DisassemblerPlugin plugin;

	public StaticDisassembleAction(DisassemblerPlugin plugin, String groupName) {
		super("Disassemble Static", plugin.getName());

		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Disassemble (Static)" }, null, groupName));
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		plugin.disassembleStaticCallback(context);
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {
		return plugin.checkDisassemblyEnabled(context, context.getAddress(), true);
	}

}
