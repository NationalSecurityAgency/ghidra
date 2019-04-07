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
package docking.widgets;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import utilities.util.reflection.ReflectionUtilities;

/**
 * A spy that tracks window shown and hidden events from the {@link DropDownSelectionTextField}.
 * 
 * <P>Synchronization Policy: the event storage of this class is synchronized to prevent 
 * concurrent modification exceptions between reading and writing.
 */
public class SpyDropDownWindowVisibilityListener<T> extends DropDownWindowVisibilityListener<T> {

	private List<WindowShownInfo> events = new ArrayList<>();

	@Override
	public synchronized void windowShown(DropDownTextField<T> field) {
		events.add(new WindowShownInfo(field, true));
	}

	@Override
	public synchronized void windowHidden(DropDownTextField<T> field) {
		events.add(new WindowShownInfo(field, false));
	}

	public synchronized boolean wasWindowShown() {
		if (!events.isEmpty()) {
			WindowShownInfo info = events.get(events.size() - 1);
			return info.wasShown;
		}

		return false;
	}

	public synchronized boolean wasWindowHidden() {
		if (!events.isEmpty()) {
			WindowShownInfo info = events.get(events.size() - 1);
			return !info.wasShown;
		}

		return false;
	}

	public synchronized void reset() {
		events = new ArrayList<>();
	}

	@Override
	public synchronized String toString() {
		if (events.isEmpty()) {
			return "<no window events>";
		}
		return StringUtils.join(events, "\n");
	}

	private class WindowShownInfo {
		private boolean wasShown;
		private Throwable source;
		private String text;

		WindowShownInfo(DropDownTextField<T> field, boolean wasShown) {
			this.wasShown = wasShown;
			this.source = ReflectionUtilities.createThrowableWithStackOlderThan(
				SpyDropDownWindowVisibilityListener.class);
			this.text = field.getText();
		}

		@Override
		public String toString() {
			//@formatter:off
			return "{\n" +
				"\twasShown: " + wasShown + "\n" +
				"\ttext: "  + text + "\n" + 
				"\ttrace: " + ReflectionUtilities.stackTraceToString(source)+ "\n" +
			"}";
			//@formatter:on
		}
	}
}
