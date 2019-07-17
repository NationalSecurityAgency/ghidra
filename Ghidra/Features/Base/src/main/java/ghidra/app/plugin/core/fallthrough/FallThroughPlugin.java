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
package ghidra.app.plugin.core.fallthrough;

import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.util.AddressFieldLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Changes the \"fall-through\" addresses",
	description = "Provides actions for changing an instructions \"fall-through\" address.  " +
			"Normally an instructions \"fall-through\" address is the address of the " +
			"instruction that immediately follows it (except for jmp).  This plugin allows " +
			"a user to overide this behaviour on specific situations.",
	eventsConsumed = { ProgramLocationPluginEvent.class, ProgramActivatedPluginEvent.class, ProgramSelectionPluginEvent.class }
)
//@formatter:on
public class FallThroughPlugin extends Plugin {

	private DockingAction clearFallthroughAction;
	private DockingAction autoFallthroughAction;
	private DockingAction setFallthroughAction;
	private Program currentProgram;

	public FallThroughPlugin(PluginTool tool) {
		super(tool);

		setupActions();
	}

	@Override
	public void processEvent(ghidra.framework.plugintool.PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			currentProgram = ((ProgramActivatedPluginEvent) event).getActiveProgram();
		}
	}

	Instruction getInstruction(ListingActionContext context) {
		Address address = context.getAddress();
		if (address != null) {
			return context.getProgram().getListing().getInstructionAt(address);
		}
		return null;
	}

	private void setupActions() {

		tool.setMenuGroup(new String[] { "Fallthrough" }, "references");

		autoFallthroughAction = new ListingContextAction("Auto Set Fallthroughs", getName()) {
			@Override
			public void actionPerformed(ListingActionContext context) {
				autoOverride(context);
			}

			@Override
			protected boolean isEnabledForContext(ListingActionContext context) {
				if (context.hasSelection()) {
					return true;
				}
				Instruction instruction = getInstruction(context);
				return instruction != null && !instruction.isFallThroughOverridden();
			}
		};
		autoFallthroughAction.setPopupMenuData(new MenuData(new String[] { "Fallthrough",
			"Auto Override" }, null, "Fallthrough"));

		tool.addAction(autoFallthroughAction);

		clearFallthroughAction = new ListingContextAction("Clear Fallthroughs", getName()) {
			@Override
			public void actionPerformed(ListingActionContext context) {
				clearOverrides(context);
			}

			@Override
			protected boolean isEnabledForContext(ListingActionContext context) {
				if (context.hasSelection()) {
					return true;
				}
				Instruction instruction = getInstruction(context);
				return instruction != null && instruction.isFallThroughOverridden();
			}
		};
		clearFallthroughAction.setPopupMenuData(new MenuData(new String[] { "Fallthrough",
			"Clear Overrides" }, null, "Fallthrough"));

		tool.addAction(clearFallthroughAction);

		setFallthroughAction = new ListingContextAction("Set Fallthrough", getName()) {
			@Override
			public void actionPerformed(ListingActionContext context) {
				showDialog(context);
			}

			@Override
			protected boolean isEnabledForContext(ListingActionContext context) {
				Instruction instruction = getInstruction(context);
				return instruction != null;
			}
		};
		setFallthroughAction.setPopupMenuData(new MenuData(
			new String[] { "Fallthrough", "Set..." }, null, "Fallthrough"));

		tool.addAction(setFallthroughAction);
	}

	private void showDialog(ListingActionContext context) {
		FallThroughModel model =
			new FallThroughModel(tool, context.getProgram(), context.getAddress());
		FallThroughDialog fallThroughDialog = new FallThroughDialog(this, model);
		tool.showDialog(fallThroughDialog);
		model.dispose();
	}

	private void autoOverride(ListingActionContext context) {
		FallThroughModel model =
			new FallThroughModel(tool, context.getProgram(), context.getAddress());
		if (context.hasSelection()) {
			model.autoOverride(context.getSelection());
		}
		else {
			Address addr = context.getAddress();
			model.autoOverride(new AddressSet(addr, addr));
		}
		model.dispose();
	}

	private void clearOverrides(ListingActionContext context) {
		FallThroughModel model =
			new FallThroughModel(tool, context.getProgram(), context.getAddress());
		if (context.hasSelection()) {
			model.clearOverride(context.getSelection());
		}
		else {
			Address addr = context.getAddress();
			model.clearOverride(new AddressSet(addr, addr));
		}
		model.dispose();
	}

	@Override
	public void dispose() {
		clearFallthroughAction.dispose();
		autoFallthroughAction.dispose();
	}

	void goTo(Address address) {
		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			goToService.goTo(new AddressFieldLocation(currentProgram, address));
		}
	}

}
