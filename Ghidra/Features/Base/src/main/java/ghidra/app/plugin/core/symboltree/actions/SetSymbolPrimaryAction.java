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
package ghidra.app.plugin.core.symboltree.actions;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.context.ProgramSymbolActionContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskLauncher;

public class SetSymbolPrimaryAction extends DockingAction {

	private static final String NAME = "Set Label Primary";

	public SetSymbolPrimaryAction() {
		super(NAME, ToolConstants.SHARED_OWNER);

		// Note: the group '2' is that of the PinSymbolAction.  That group seems like a nice place.
		setPopupMenuData(new MenuData(new String[] { "Set Primary" }, "2"));
		setHelpLocation(new HelpLocation("SymbolTablePlugin", "Set_Primary"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {

		if (!(context instanceof ProgramSymbolActionContext psac)) {
			return false;
		}

		int n = psac.getSymbolCount();
		if (n != 1) {
			return false;
		}

		Symbol s = psac.getFirstSymbol();
		return !s.isPrimary();
	}

	@Override
	public void actionPerformed(ActionContext context) {

		ProgramSymbolActionContext psac = (ProgramSymbolActionContext) context;
		Symbol s = psac.getFirstSymbol();
		Namespace ns = s.getParentNamespace();
		String name = s.getName();
		Address addr = s.getAddress();
		SetLabelPrimaryCmd cmd = new SetLabelPrimaryCmd(addr, name, ns);
		TaskLauncher.launchModal(NAME, () -> {

			Program p = psac.getProgram();
			p.withTransaction(NAME, () -> {
				cmd.applyTo(p);
			});

		});

		String errorMessage = cmd.getStatusMsg();
		if (!StringUtils.isBlank(errorMessage)) {
			Msg.showError(getClass(), null, "Unable to Set Label Primary", errorMessage);
		}
	}

}
