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
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingActionContext;
import ghidra.app.services.DebuggerPlatformService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.platform.DebuggerPlatformMapper;
import ghidra.debug.api.platform.DisassemblyResult;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.task.TaskMonitor;

public final class CurrentPlatformTraceDisassembleCommand
		extends BackgroundCommand<TraceProgramView> {
	public static final String NAME = "Disassemble";

	public record Reqs(DebuggerPlatformMapper mapper, TraceThread thread, TraceObject object,
			TraceProgramView view) {

		public static Reqs fromView(PluginTool tool, TraceProgramView view) {
			DebuggerTraceManagerService traceManager =
				tool.getService(DebuggerTraceManagerService.class);
			DebuggerPlatformService platformService =
				tool.getService(DebuggerPlatformService.class);
			if (platformService == null) {
				return null;
			}
			Trace trace = view.getTrace();
			DebuggerCoordinates current = traceManager == null ? DebuggerCoordinates.NOWHERE
					: traceManager.getCurrentFor(trace);
			TraceThread thread = current.getThread();
			TraceObject object = current.getObject();
			DebuggerPlatformMapper mapper =
				platformService.getMapper(trace, object, view.getSnap());
			if (mapper == null) {
				return null;
			}
			return new Reqs(mapper, thread, object, view);
		}

		public static Reqs fromContext(PluginTool tool, ActionContext context) {
			if (!(context instanceof DebuggerListingActionContext lac)) {
				return null;
			}
			return fromView(tool, lac.getProgram());
		}
	}

	private final PluginTool tool;
	private final AddressSetView set;
	private final Reqs reqs;
	private final Address address;

	public CurrentPlatformTraceDisassembleCommand(PluginTool tool, AddressSetView set, Reqs reqs,
			Address address) {
		super(NAME, true, true, false);
		this.tool = tool;
		this.set = set;
		this.reqs = reqs;
		this.address = address;
	}

	@Override
	public boolean applyTo(TraceProgramView view, TaskMonitor monitor) {
		DisassemblyResult result = reqs.mapper.disassemble(reqs.thread, reqs.object, address, set,
			view.getSnap(), monitor);
		if (!result.isSuccess()) {
			tool.setStatusInfo(result.getErrorMessage(), true);
		}
		return true;
	}
}
