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
package ghidra.app.plugin.core.debug.service.model.record;

import ghidra.app.plugin.core.debug.service.model.RecorderPermanentTransaction;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;

class TimeRecorder {
	protected final ObjectBasedTraceRecorder recorder;

	protected TraceSnapshot snapshot = null;

	protected TimeRecorder(ObjectBasedTraceRecorder recorder) {
		this.recorder = recorder;
	}

	protected TraceSnapshot getSnapshot() {
		return snapshot;
	}

	protected long getSnap() {
		return snapshot.getKey();
	}

	protected synchronized TraceSnapshot doCreateSnapshot(String description,
			TraceThread eventThread) {
		snapshot = recorder.trace.getTimeManager().createSnapshot(description);
		snapshot.setEventThread(eventThread);
		return snapshot;
	}

	protected TraceSnapshot createSnapshot(String description, TraceThread eventThread,
			RecorderPermanentTransaction tid) {
		TraceSnapshot snapshot;
		if (tid != null) {
			snapshot = doCreateSnapshot(description, eventThread);

		}
		else {
			try (RecorderPermanentTransaction tid2 =
				RecorderPermanentTransaction.start(recorder.trace, description)) {
				snapshot = doCreateSnapshot(description, eventThread);
			}
		}
		recorder.fireSnapAdvanced(snapshot.getKey());
		return snapshot;
	}

	protected TraceSnapshot forceSnapshot() {
		return createSnapshot("User-forced snapshot", null, null);
	}
}
