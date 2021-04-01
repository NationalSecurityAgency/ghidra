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

import java.util.*;

import ghidra.app.plugin.core.debug.service.model.interfaces.ManagedThreadRecorder;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetThread;
import ghidra.trace.model.thread.TraceThread;

public class RecorderThreadMap {

	protected final NavigableSet<Integer> observedThreadPathLengths = new TreeSet<>();
	protected final Map<TargetThread, ManagedThreadRecorder> byTargetThread = new HashMap<>();
	protected final Map<TraceThread, ManagedThreadRecorder> byTraceThread = new HashMap<>();

	public void put(ManagedThreadRecorder rec) {
		observedThreadPathLengths.add(rec.getTargetThread().getPath().size());
		byTargetThread.put(rec.getTargetThread(), rec);
		byTraceThread.put(rec.getTraceThread(), rec);
	}

	/*
	public ManagedThreadRecorder getForSuccessor(TargetObject successor) {
		while (successor != null) {
			ManagedThreadRecorder rec = byTargetThread.get(successor);
			if (rec != null) {
				return rec;
			}
			successor = successor.getParent();
		}
		return null;
	}
	*/

	public ManagedThreadRecorder get(TargetThread thread) {
		return byTargetThread.get(thread);
	}

	public ManagedThreadRecorder get(TargetObject maybeThread) {
		return byTargetThread.get(maybeThread);
	}

	public ManagedThreadRecorder get(TraceThread thread) {
		return byTraceThread.get(thread);
	}

	public void remove(ManagedThreadRecorder rec) {
		ManagedThreadRecorder rByTarget = byTargetThread.remove(rec.getTargetThread());
		ManagedThreadRecorder rByTrace = byTraceThread.remove(rec.getTraceThread());
		assert rec == rByTarget;
		assert rec == rByTrace;
	}

	public Collection<ManagedThreadRecorder> recorders() {
		return byTargetThread.values();
	}
}
