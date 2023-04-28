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
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.disassemble.DebuggerDisassemblerPlugin.Reqs;
import ghidra.app.plugin.core.debug.mapping.DebuggerPlatformMapper;
import ghidra.app.plugin.core.debug.mapping.DisassemblyResult;
import ghidra.framework.cmd.TypedBackgroundCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;

public class CurrentPlatformTraceDisassembleAction extends DockingAction {
	private static final String NAME = "Disassemble";
	private static final String MENU_GROUP = "Disassembly";
	private static final KeyBindingData KEY_BINDING = new KeyBindingData("D");

	private final DebuggerDisassemblerPlugin plugin;

	public CurrentPlatformTraceDisassembleAction(DebuggerDisassemblerPlugin plugin) {
		super(NAME, plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { NAME }, MENU_GROUP));
		setKeyBindingData(KEY_BINDING);
		setHelpLocation(new HelpLocation(plugin.getName(), "disassemble"));
	}

	protected Reqs getReqs(ActionContext context) {
		if (plugin.platformService == null) {
			return null;
		}
		if (!(context instanceof ListingActionContext)) {
			return null;
		}
		ListingActionContext lac = (ListingActionContext) context;
		Program program = lac.getProgram();
		if (!(program instanceof TraceProgramView)) {
			return null;
		}
		TraceProgramView view = (TraceProgramView) program;
		Trace trace = view.getTrace();
		DebuggerCoordinates current = plugin.traceManager == null ? DebuggerCoordinates.NOWHERE
				: plugin.traceManager.getCurrentFor(trace);
		TraceThread thread = current.getThread();
		TraceObject object = current.getObject();
		DebuggerPlatformMapper mapper =
			plugin.platformService.getMapper(trace, object, view.getSnap());
		return new Reqs(mapper, thread, object, view);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		Reqs reqs = getReqs(context);
		return reqs != null;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		Reqs reqs = getReqs(context);
		if (reqs == null) {
			return false;
		}
		return super.isEnabledForContext(context);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Reqs reqs = getReqs(context);
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
			set = reqs.view.getAddressFactory()
					.getAddressSet(space.getMinAddress(), space.getMaxAddress());
		}
		TypedBackgroundCommand<TraceProgramView> cmd =
			new TypedBackgroundCommand<>(NAME, true, true, false) {
				@Override
				public boolean applyToTyped(TraceProgramView view, TaskMonitor monitor) {
					DisassemblyResult result = reqs.mapper.disassemble(
						reqs.thread, reqs.object, address, set, view.getSnap(), monitor);
					if (!result.isSuccess()) {
						plugin.getTool().setStatusInfo(result.getErrorMessage(), true);
					}
					return true;
				}
			};
		cmd.run(plugin.getTool(), reqs.view);
	}
}
