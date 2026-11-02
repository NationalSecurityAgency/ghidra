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
package ghidra.app.plugin.core.debug.service.emulation;

import java.util.List;

import docking.ActionContext;
import docking.action.MenuData;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.HelpLocation;

public class EmulateAddThreadAction extends AbstractEmulateAction {

	public EmulateAddThreadAction(DebuggerEmulationServicePlugin plugin) {
		super(plugin, plugin.ADD_THREAD, null);
	}

	@Override
	MenuData computeMenuData() {
		return new MenuData(
			prependMenuPath("Add an emulated thread", List.of()),
			DebuggerResources.ICON_THREAD, DebuggerResources.GROUP_GENERAL, 0, "c");
	}

	@Override
	String getTopGroup(Program currentProgram) {
		return "4";
	}

	@Override
	String getTopOrder(Program currentProgram) {
		return program == currentProgram ? "1" : "2";
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof ProgramLocationActionContext plctx)) {
			return false;
		}
		Program programOrView = plctx.getProgram();
		if (programOrView instanceof TraceProgramView view) {
			if (!ProgramEmulationUtils.isEmulatedProgram(view.getTrace())) {
				return false;
			}
			/*MemoryBlock block = view.getMemory().getBlock(ctx.getAddress());
			return block.isExecute();*/
			return true;
		}

		DebuggerTraceManagerService traceManager = plugin.getTraceManager();
		DebuggerStaticMappingService staticMappings = plugin.getStaticMappings();
		if (traceManager == null || staticMappings == null) {
			return false;
		}

		// Action was probably activated in a static listing.
		// Bail if current trace is not emulated. Otherwise map and check region.
		DebuggerCoordinates current = traceManager.getCurrent();
		if (current.getTrace() == null ||
			!ProgramEmulationUtils.isEmulatedProgram(current.getTrace())) {
			return false;
		}
		ProgramLocation programLoc = getCurrentLocation();
		if (programLoc == null) {
			return false;
		}
		TraceLocation traceLoc = staticMappings.getOpenMappedLocation(
			current.getTrace(), programLoc, current.getSnap());
		if (traceLoc == null) {
			return false;
		}
		/*TraceMemoryRegion region = current.getTrace()
				.getMemoryManager()
				.getRegionContaining(current.getSnap(), traceLoc.getAddress());
		return region != null && region.isExecute();*/
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!(context instanceof ProgramLocationActionContext plctx)) {
			return;
		}
		Program programOrView = plctx.getProgram();
		DebuggerTraceManagerService traceManager = plugin.getTraceManager();
		DebuggerStaticMappingService staticMappings = plugin.getStaticMappings();
		if (traceManager == null || staticMappings == null) {
			return;
		}

		ProgramLocation loc = getCurrentLocation();
		Address pc = getCurrentAddress();
		if (pc == null) {
			return;
		}

		if (programOrView instanceof TraceProgramView view) {
			Trace trace = view.getTrace();

			/*MemoryBlock block = view.getMemory().getBlock(tracePc);
			if (!block.isExecute()) {
				return;
			}*/

			long snap = view.getViewport()
					.getOrderedSnaps()
					.stream()
					.filter(s -> s >= 0)
					.findFirst()
					.orElse(0L);
			ProgramLocation progLoc = staticMappings.getOpenMappedLocation(
				new DefaultTraceLocation(trace, null, Lifespan.at(snap), pc));
			Program program = progLoc == null ? null : progLoc.getProgram();
			Address programPc = progLoc == null ? null : progLoc.getAddress();

			TraceThread thread = ProgramEmulationUtils.launchEmulationThread(trace, snap, program,
				pc, programPc);
			traceManager.activateThread(thread);
		}
		else {
			DebuggerCoordinates current = traceManager.getCurrent();
			long snap = current.getSnap();
			Trace trace = current.getTrace();
			TraceLocation traceLoc =
				staticMappings.getOpenMappedLocation(trace, loc, snap);
			if (traceLoc == null) {
				return;
			}
			Address tracePc = traceLoc.getAddress();
			/*TraceMemoryRegion region =
				trace.getMemoryManager().getRegionContaining(snap, tracePc);
			if (region == null || !region.isExecute()) {
				return;
			}*/
			TraceThread thread = ProgramEmulationUtils.launchEmulationThread(trace, snap,
				programOrView, tracePc, pc);
			traceManager.activateThread(thread);
		}
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation(plugin.getName(), "add_emulated_thread");
	}

}
