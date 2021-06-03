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

import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;

public class DefaultTimeRecorder {

	private DefaultTraceRecorder recorder;
	private Trace trace;
	private TraceSnapshot snapshot = null;

	public DefaultTimeRecorder(DefaultTraceRecorder recorder) {
		this.recorder = recorder;
		this.trace = recorder.getTrace();
	}

	public TraceSnapshot getSnapshot() {
		return snapshot;
	}

	public long getSnap() {
		return snapshot.getKey();
	}

	protected synchronized void doAdvanceSnap(String description, TraceThread eventThread) {
		snapshot = trace.getTimeManager().createSnapshot(description);
		snapshot.setEventThread(eventThread);
	}

	public TraceSnapshot forceSnapshot() {
		createSnapshot("User-forced snapshot", null, null);
		return snapshot;
	}

	public void createSnapshot(String description, TraceThread eventThread,
			RecorderPermanentTransaction tid) {
		if (tid != null) {
			doAdvanceSnap(description, eventThread);
			recorder.getListeners().fire.snapAdvanced(recorder, getSnap());
			return;
		}
		// NB. The also serves as the snap counter, so it must be on the service thread
		try (RecorderPermanentTransaction tid2 =
			RecorderPermanentTransaction.start(trace, description)) {
			doAdvanceSnap(description, eventThread);
		}
		recorder.getListeners().fire.snapAdvanced(recorder, getSnap());
	}
}
