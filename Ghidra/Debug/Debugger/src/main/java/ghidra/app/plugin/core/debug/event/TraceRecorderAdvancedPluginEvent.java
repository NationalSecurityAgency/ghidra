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
package ghidra.app.plugin.core.debug.event;

import ghidra.app.services.TraceRecorder;
import ghidra.framework.plugintool.PluginEvent;

public class TraceRecorderAdvancedPluginEvent extends PluginEvent {
	static final String NAME = "Recorder Advanced";

	private final TraceRecorder recorder;
	private final long snap;

	/**
	 * Construct a new plugin event.
	 * 
	 * @param source name of the plugin that created this event
	 * @param recorder the recorder that has advanced to its next snap
	 * @param snap the snap to which the recorder advanced
	 */
	public TraceRecorderAdvancedPluginEvent(String source, TraceRecorder recorder, long snap) {
		super(source, NAME);
		this.recorder = recorder;
		this.snap = snap;
	}

	/**
	 * Get the recorder that has advanced to its next snap
	 * 
	 * @return the recorder
	 */
	public TraceRecorder getRecorder() {
		return recorder;
	}

	/**
	 * Get the snap to which the recorder advanced
	 * 
	 * @return the snap
	 */
	public long getSnap() {
		return snap;
	}
}
