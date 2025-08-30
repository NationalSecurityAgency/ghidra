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
package ghidra.trace.util;

import generic.util.AbstractPeekableIterator;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Lifespan.DefaultLifeSet;
import ghidra.trace.model.Lifespan.MutableLifeSet;
import ghidra.trace.model.Trace;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.trace.model.time.schedule.TraceSchedule;

public class TraceViewportSpanIterator extends AbstractPeekableIterator<Lifespan> {
	private final TraceTimeManager timeManager;
	private final MutableLifeSet set = new DefaultLifeSet();
	private long snap;
	private boolean done = false;

	public TraceViewportSpanIterator(Trace trace, long snap) {
		this.timeManager = trace.getTimeManager();
		this.snap = snap;
	}

	protected TraceSnapshot locateMostRecentFork(long from) {
		while (true) {
			TraceSnapshot prev = timeManager.getMostRecentSnapshot(from);
			if (prev == null) {
				return null;
			}
			TraceSchedule prevSched = prev.getSchedule();
			long prevKey = prev.getKey();
			if (prevSched == null) {
				if (prevKey == Long.MIN_VALUE) {
					return null;
				}
				from = prevKey - 1;
				continue;
			}
			long forkedSnap = prevSched.getSnap();
			if (forkedSnap == prevKey - 1) {
				// Schedule is notational without forking
				from--;
				continue;
			}
			return prev;
		}
	}

	@Override
	protected Lifespan seekNext() {
		if (done) {
			return null;
		}
		long curSnap = snap;
		TraceSnapshot fork = locateMostRecentFork(snap);
		long prevSnap = fork == null ? Long.MIN_VALUE : fork.getKey();
		if (fork == null) {
			done = true;
		}
		else if (set.contains(prevSnap)) {
			done = true;
			return null;
		}
		else {
			snap = fork.getSchedule().getSnap();
		}
		Lifespan range = Lifespan.span(prevSnap, curSnap);
		set.add(range);
		return range;
	}
}
