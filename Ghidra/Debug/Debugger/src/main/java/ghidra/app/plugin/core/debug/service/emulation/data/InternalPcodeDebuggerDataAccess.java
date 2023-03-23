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
package ghidra.app.plugin.core.debug.service.emulation.data;

import ghidra.app.services.TraceRecorder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.lifecycle.Internal;
import ghidra.pcode.exec.trace.data.InternalPcodeTraceDataAccess;
import ghidra.trace.model.TraceTimeViewport;

@Internal
public interface InternalPcodeDebuggerDataAccess extends InternalPcodeTraceDataAccess {
	PluginTool getTool();

	TraceRecorder getRecorder();

	default boolean isLive() {
		TraceRecorder recorder = getRecorder();
		if (recorder == null || !recorder.isRecording()) {
			return false;
		}
		TraceTimeViewport viewport = getViewport();
		for (long s : viewport.getReversedSnaps()) {
			if (recorder.getSnap() == s) {
				return true;
			}
		}
		return false;
	}
}
