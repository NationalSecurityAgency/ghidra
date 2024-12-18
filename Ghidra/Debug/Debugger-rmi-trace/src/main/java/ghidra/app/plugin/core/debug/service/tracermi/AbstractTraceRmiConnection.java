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
package ghidra.app.plugin.core.debug.service.tracermi;

import ghidra.app.services.DebuggerControlService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.DebuggerTraceManagerService.ActivationCause;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.Swing;

public abstract class AbstractTraceRmiConnection implements TraceRmiConnection {

	protected abstract DebuggerTraceManagerService getTraceManager();

	protected abstract DebuggerControlService getControlService();

	protected abstract boolean ownsTrace(Trace trace);

	protected boolean followsPresent(Trace trace) {
		DebuggerControlService controlService = getControlService();
		if (controlService == null) {
			return true;
		}
		return controlService.getCurrentMode(trace).followsPresent();
	}

	protected void doActivate(TraceObject object, Trace trace, TraceSnapshot snapshot) {
		DebuggerCoordinates coords = getTraceManager().getCurrent();
		if (coords.getTrace() != trace) {
			coords = DebuggerCoordinates.NOWHERE;
		}
		if (snapshot != null && followsPresent(trace)) {
			coords = coords.snap(snapshot.getKey());
		}
		DebuggerCoordinates finalCoords = object == null ? coords : coords.object(object);
		Swing.runLater(() -> {
			DebuggerTraceManagerService traceManager = getTraceManager();
			if (traceManager == null) {
				// Can happen during tear down.
				return;
			}
			if (!traceManager.getOpenTraces().contains(trace)) {
				traceManager.openTrace(trace);
				traceManager.activate(finalCoords, ActivationCause.SYNC_MODEL);
			}
			else {
				Trace currentTrace = traceManager.getCurrentTrace();
				if (currentTrace == null || ownsTrace(currentTrace)) {
					traceManager.activate(finalCoords, ActivationCause.SYNC_MODEL);
				}
			}
		});
	}

}
