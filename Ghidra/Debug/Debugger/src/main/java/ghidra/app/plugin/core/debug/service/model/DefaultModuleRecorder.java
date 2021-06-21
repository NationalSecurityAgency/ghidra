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
package ghidra.app.plugin.core.debug.service.model;

import ghidra.app.plugin.core.debug.service.model.interfaces.ManagedModuleRecorder;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetSection;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Trace;
import ghidra.trace.model.modules.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class DefaultModuleRecorder implements ManagedModuleRecorder {

	private final DefaultTraceRecorder recorder;
	private final Trace trace;
	private final TraceModuleManager moduleManager;

	public DefaultModuleRecorder(DefaultTraceRecorder recorder) {
		this.recorder = recorder;
		this.trace = recorder.getTrace();
		this.moduleManager = trace.getModuleManager();
	}

	protected TraceModule doRecordProcessModule(long snap, TargetModule module) {
		String path = module.getJoinedPath(".");
		if (recorder.getMemoryMapper() == null) {
			Msg.error(this, "Got module before memory mapper: " + path);
			return null;
		}

		// Short-circuit the DuplicateNameException for efficiency?
		TraceModule exists = moduleManager.getLoadedModuleByPath(snap, path);
		if (exists != null) {
			return exists;
		}

		try {
			AddressRange targetRange = module.getRange();
			if (targetRange == null) {
				Msg.error(this, "Range not found for " + module);
				return null;
			}
			AddressRange traceRange = recorder.getMemoryMapper().targetToTrace(targetRange);
			return moduleManager.addLoadedModule(path, module.getModuleName(), traceRange, snap);
		}
		catch (DuplicateNameException e) {
			// This resolves the race condition, since DB access is synchronized
			return moduleManager.getLoadedModuleByPath(snap, path);
		}
	}

	@Override
	public void offerProcessModule(TargetModule module) {
		long snap = recorder.getSnap();
		String path = module.getJoinedPath(".");
		recorder.parTx.execute("Module " + path + " loaded", () -> {
			doRecordProcessModule(snap, module);
		}, path);
	}

	protected TraceSection doRecordProcessModuleSection(long snap, TargetSection section) {
		String path = section.getJoinedPath(".");
		if (recorder.getMemoryMapper() == null) {
			Msg.error(this, "Got module section before memory mapper: " + path);
			return null;
		}
		TraceModule traceModule = doRecordProcessModule(snap, section.getModule());
		if (traceModule == null) {
			return null; // Failure should already be logged
		}
		try {
			AddressRange targetRange = section.getRange();
			AddressRange traceRange = recorder.getMemoryMapper().targetToTrace(targetRange);
			return traceModule.addSection(path, section.getIndex(), traceRange);
		}
		catch (DuplicateNameException e) {
			Msg.warn(this, path + " already recorded");
			return moduleManager.getLoadedSectionByPath(snap, path);
		}
	}

	@Override
	public void offerProcessModuleSection(TargetSection section) {
		long snap = recorder.getSnap();
		String path = section.getJoinedPath(".");
		recorder.parTx.execute("Section " + path + " added", () -> {
			doRecordProcessModuleSection(snap, section);
		}, section.getModule().getJoinedPath("."));
	}

	protected void doRemoveProcessModule(long snap, TargetModule module) {
		String path = module.getJoinedPath(".");
		//TraceThread eventThread = recorder.getSnapshot().getEventThread();
		TraceModule traceModule = moduleManager.getLoadedModuleByPath(snap, path);
		if (traceModule == null) {
			Msg.warn(this, "unloaded " + path + " is not in the trace");
			return;
		}
		try {
			if (traceModule.getLoadedSnap() == snap) {
				Msg.warn(this, "Observed module unload in the same snap as its load");
				//recorder.createSnapshot("WARN: Module removed", eventThread, tid);
			}
			traceModule.setUnloadedSnap(snap);
		}
		catch (DuplicateNameException e) {
			Msg.error(this, "Could not record process module removed: " + e);
		}
	}

	@Override
	public void removeProcessModule(TargetModule module) {
		long snap = recorder.getSnap();
		String path = module.getJoinedPath(".");
		recorder.parTx.execute("Module " + path + " unloaded", () -> {
			doRemoveProcessModule(snap, module);
		}, path);
	}

	@Override
	public TraceModule getTraceModule(TargetModule module) {
		String path = module.getJoinedPath(".");
		return moduleManager.getLoadedModuleByPath(recorder.getSnap(), path);
	}

	@Override
	public TraceSection getTraceSection(TargetSection section) {
		String path = section.getJoinedPath(".");
		return moduleManager.getLoadedSectionByPath(recorder.getSnap(), path);
	}
}
