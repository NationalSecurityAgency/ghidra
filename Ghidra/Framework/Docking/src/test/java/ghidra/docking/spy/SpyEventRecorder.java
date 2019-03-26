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
package ghidra.docking.spy;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.time.FastDateFormat;

import ghidra.util.Msg;

/**
 * Records messages for later playback.  This can be useful for tracking the order of sequences/
 * callbacks.
 */
public class SpyEventRecorder {

	private volatile int globalId = 0;

	private String recorderName;
	private List<SpyEvent> events = new ArrayList<>();

	public SpyEventRecorder(String recorderName) {
		this.recorderName = recorderName;
	}

	// synchronized because we spy on multiple threads (like Test and Swing)
	public synchronized void record(String message) {
		SpyEvent event = new SpyEvent(message);
		events.add(event);
	}

	// synchronized because we spy on multiple threads (like Test and Swing)
	public synchronized void dumpEvents() {
		StringBuilder buffy = new StringBuilder("Recorded Events - " + recorderName + '\n');
		for (SpyEvent event : events) {
			buffy.append(event.toString()).append('\n');
		}
		Msg.debug(this, buffy.toString());
	}

	private class SpyEvent {

		private FastDateFormat dateFormat = FastDateFormat.getInstance("'T'HH:mm:ssZZ");

		private int id;
		private String message;
		private long time = System.currentTimeMillis();

		SpyEvent(String message) {
			this.message = message;
			this.id = ++globalId;
		}

		@Override
		public String toString() {
			return "(" + id + ") " + dateFormat.format(time) + " " + message;
		}
	}
}
