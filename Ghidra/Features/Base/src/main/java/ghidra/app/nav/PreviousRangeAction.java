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
package ghidra.app.nav;

import ghidra.app.context.*;
import ghidra.app.plugin.core.navigation.NavigationOptions;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.util.ProgramSelection;

public abstract class PreviousRangeAction extends NavigatableContextAction {

	private PluginTool tool;
	private NavigationOptions navOptions;

	public PreviousRangeAction(PluginTool tool, String name, String owner,
			NavigationOptions navOptions) {
		super(name, owner);
		this.tool = tool;
		this.navOptions = navOptions;
		setEnabled(false);
		addToWindowWhen(NavigatableActionContext.class);
	}

	@Override
	public void actionPerformed(NavigatableActionContext context) {
		Address goToAddress = getGoToAddress(context);
		GoToService service = tool.getService(GoToService.class);
		if (service != null) {
			service.goTo(context.getNavigatable(), goToAddress);
		}
	}

	private Address getGoToAddress(NavigatableActionContext context) {
		ProgramSelection selection = getSelection(context);
		Address currentAddress = context.getAddress();

		AddressRangeIterator it = selection.getAddressRanges(currentAddress, false);
		if (!it.hasNext()) {
			return currentAddress;   // no next address, just return current address - should never hit this
		}
		// see if we are inside a range now (range >= 0)...
		AddressRange range = it.next();
		if (range.contains(currentAddress)) {

			// ...if so, go to the top
			Address startOfRangeAddress = range.getMinAddress();
			if (!startOfRangeAddress.equals(currentAddress)) {
				return startOfRangeAddress;
			}

			// ... we are at the top...go to previous range
			if (!it.hasNext()) {
				return currentAddress;
			}
			range = it.next();
		}

		// ...but where in the previous range?
		if (navOptions.isGotoTopAndBottomOfRangeEnabled()) {
			return range.getMaxAddress();
		}
		return range.getMinAddress();

	}

	@Override
	public boolean isEnabledForContext(NavigatableActionContext context) {
		Address currentAddress = context.getAddress();
		ProgramSelection selection = getSelection(context);
		if (selection == null || selection.isEmpty() || currentAddress == null) {
			return false;
		}

		return currentAddress.compareTo(selection.getMinAddress()) > 0;
	}

	abstract protected ProgramSelection getSelection(ProgramLocationActionContext context);
}
