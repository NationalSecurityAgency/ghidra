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
package ghidra.app.core.debug.service.taint;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.services.*;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.program.TraceProgramView;

@PluginInfo(
	shortDescription = "Emulation Taint Injection Service Plugin",
	description = "Manages emulator taint",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.UNSTABLE,
	servicesRequired = {
		DebuggerEmulationService.class
	},
	servicesProvided = {
		EmulationTaintInjectionService.class
	}
)
public class EmulationTaintInjectionServicePlugin extends Plugin implements EmulationTaintInjectionService {

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerStaticMappingService staticMappings;
	@AutoServiceConsumed
	private DebuggerEmulationService emuService;
	@SuppressWarnings("unused")
	private AutoService.Wiring autoServiceWiring;

	private Map<Address, String> taintMap = new HashMap<>();

	protected EmulatorTaintAction emulatorInjectAction;
	protected EmulatorTaintAction emulatorInjectArrayAction;

	protected SaveState toolLaunchConfigs = new SaveState();

	public EmulationTaintInjectionServicePlugin(PluginTool tool) {
		super(tool);
		autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
	}

	@Override
	protected void init() {
		super.init();
		createActions();
	}

	protected void createActions() {
		emulatorInjectAction = new EmulatorTaintAction(this, false);
		emulatorInjectArrayAction = new EmulatorTaintAction(this, true);
		tool.addAction(emulatorInjectAction);
		tool.addAction(emulatorInjectArrayAction);
	}

	@Override
	public void injectTaint(PcodeMachine<?> emu) {
		for (Entry<Address, String> entry : taintMap.entrySet()) {
			emu.inject(entry.getKey(), entry.getValue());
		}
	}

	public String getTaint(ProgramLocationActionContext plctx) {
		Address targetPc = getPcFromContext(plctx);
		return targetPc == null ? null : taintMap.get(targetPc);
	}

	public void toggleTaint(ProgramLocationActionContext plctx, String sleigh) {
		Address targetPc = getPcFromContext(plctx);
		if (taintMap.containsKey(targetPc) || sleigh == null) {
			taintMap.remove(targetPc);
		}
		else {
			taintMap.put(targetPc, sleigh);
		}
	}

	Address getPcFromContext(ProgramLocationActionContext plctx) {
		Program programOrView = plctx.getProgram();
		Address targetPc = null;
		if (programOrView instanceof TraceProgramView view) {
			Trace trace = view.getTrace();
			long snap = view.getViewport()
					.getOrderedSnaps()
					.stream()
					.filter(s -> s >= 0)
					.findFirst()
					.orElse(0L);
			ProgramLocation progLoc = staticMappings.getOpenMappedLocation(
				new DefaultTraceLocation(trace, null, Lifespan.at(snap), plctx.getAddress()));
			targetPc = progLoc == null ? null : progLoc.getAddress();
		}
		else {
			DebuggerCoordinates current = traceManager.getCurrent();
			long snap = current.getSnap();
			Trace trace = current.getTrace();
			TraceLocation traceLoc =
				staticMappings.getOpenMappedLocation(trace, plctx.getLocation(), snap);
			if (traceLoc == null) {
				return null;
			}
			targetPc = traceLoc.getAddress();
		}
		return targetPc;
	}

	public boolean usingEmulator() {
		return emuService.getEmulatorFactory() != null;
	}

}
