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
package docking.widgets.table.threaded;

import java.util.*;

import org.junit.Assert;

import ghidra.docking.spy.SpyEventRecorder;
import ghidra.util.task.TaskMonitorAdapter;

public class SpyTaskMonitor extends TaskMonitorAdapter {
	private List<String> messages = new ArrayList<>();
	private SpyEventRecorder recorder;

	SpyTaskMonitor() {
		this.recorder = new SpyEventRecorder("Stub");
	}

	SpyTaskMonitor(SpyEventRecorder recorder) {
		this.recorder = recorder;
	}

	@Override
	public void setMessage(String message) {
		messages.add(message);
		recorder.record("Monitor - " + message);
	}

	@Override
	public synchronized boolean isCancelEnabled() {
		return true;
	}

	void clearMessages() {
		messages.clear();
	}

	boolean hasFilterMessage() {
		ListIterator<String> li = messages.listIterator(messages.size());
		while (li.hasPrevious()) {
			String message = li.previous();
			if (message.contains("Filtering")) {
				return true;
			}
		}
		return false;
	}

	String getLastSortMessage() {
		ListIterator<String> li = messages.listIterator(messages.size());
		while (li.hasPrevious()) {
			String message = li.previous();
			if (message.contains("Sorting")) {
				return message;
			}
		}

		Assert.fail("No sorting messages found");
		return null;// can't get here
	}

	// for debug
	String messagesToString() {
		return messages.toString();
	}
}
