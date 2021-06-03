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
import java.util.concurrent.atomic.AtomicBoolean;

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

	private AtomicBoolean buffered = new AtomicBoolean(true);

	public SpyEventRecorder(String recorderName) {
		this.recorderName = recorderName;
	}

	public void setBuffered(boolean buffered) {
		this.buffered.set(buffered);
	}

	// synchronized because we spy on multiple threads (like Test and Swing)
	public synchronized void record(String message) {
		SpyEvent event = new SpyEvent(message);

		if (buffered.get()) {
			events.add(event);
		}
		else {
			// System.err intentional here for aesthetics
			System.err.println(event.toString(0));
		}
	}

	// synchronized because we spy on multiple threads (like Test and Swing)
	public synchronized void record(String message, Object... args) {
		record(String.format(message, args));
	}

	private synchronized String eventsToString() {

		int size = events.size();
		int length = Integer.toString(size).length();

		StringBuilder buffy = new StringBuilder("Recorded Events - " + recorderName + '\n');
		for (SpyEvent event : events) {
			buffy.append(event.toString(length)).append('\n');
		}
		return buffy.toString();
	}

	// synchronized because we spy on multiple threads (like Test and Swing)
	public void dumpEvents() {
		Msg.debug(this, eventsToString());
	}

	@Override
	public String toString() {
		return eventsToString();
	}

	private class SpyEvent {

		private static final String PADDING = "          ";
		private FastDateFormat dateFormat = FastDateFormat.getInstance("'T'HH:mm:ss:SSS");

		private int id;
		private String message;
		private long time = System.currentTimeMillis();

		SpyEvent(String message) {
			this.message = message;
			this.id = ++globalId;
		}

		String toString(int idPad) {

			int myLength = Integer.toString(id).length();
			int delta = Math.max(0, idPad - myLength);
			String pad = PADDING.substring(0, delta);

			return "(" + id + ") " + pad + dateFormat.format(time) + " " + message;
		}
	}
}
