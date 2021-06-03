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
package ghidra.app.plugin.core.codebrowser.actions;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.util.HelpLocation;

public class GotoNextFunctionAction extends NavigatableContextAction {

	private PluginTool tool;

	public GotoNextFunctionAction(PluginTool tool, String owner) {
		super("Go To Next Function", owner);
		this.tool = tool;

		MenuData menuData =
			new MenuData(new String[] { ToolConstants.MENU_NAVIGATION, "Go To Next Function" },
				null, "GoTo");
		menuData.setMenuSubGroup("za");
		setMenuBarData(menuData);
		KeyStroke keyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_DOWN, InputEvent.CTRL_DOWN_MASK);
		setKeyBindingData(new KeyBindingData(keyStroke));
		setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, "Next_Previous_Function"));
		addToWindowWhen(NavigatableActionContext.class);
	}

	private Function getNextFunction(Program program, Address address) {
		FunctionIterator functionIterator = program.getListing().getFunctions(address, true);
		if (!functionIterator.hasNext()) {
			return null;
		}
		Function nextFunction = functionIterator.next();
		if (!nextFunction.getEntryPoint().equals(address)) {
			return nextFunction;
		}
		if (!functionIterator.hasNext()) {
			return null;
		}
		return functionIterator.next();
	}

	@Override
	protected void actionPerformed(NavigatableActionContext context) {
		Address address = context.getAddress();
		Program program = context.getProgram();
		Function function = getNextFunction(program, address);
		if (function == null) {
			return;
		}

		GoToService service = tool.getService(GoToService.class);
		if (service != null) {
			FunctionSignatureFieldLocation location =
				new FunctionSignatureFieldLocation(program, function.getEntryPoint(), null, 0,
					function.getPrototypeString(false, false));

			Navigatable navigatable = context.getNavigatable();
			service.goTo(navigatable, location, navigatable.getProgram());
		}
		else {
			tool.setStatusInfo("Can't find Go To Service!");
		}
	}

}
