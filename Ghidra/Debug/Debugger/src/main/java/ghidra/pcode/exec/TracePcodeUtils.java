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
package ghidra.pcode.exec;

import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.trace.TraceBytesPcodeExecutorState;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.Trace;

public enum TracePcodeUtils {
	;
	public static AsyncPcodeExecutor<byte[]> executorForCoordinates(
			DebuggerCoordinates coordinates) {
		Trace trace = coordinates.getTrace();
		if (trace == null) {
			throw new IllegalArgumentException("Coordinates have no trace");
		}
		Language language = trace.getBaseLanguage();
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalArgumentException("Given trace does not use a Sleigh language");
		}
		SleighLanguage slang = (SleighLanguage) language;
		PcodeExecutorState<CompletableFuture<byte[]>> state;
		if (coordinates.getRecorder() == null) {
			state = new AsyncWrappedPcodeExecutorState<>(
				new TraceBytesPcodeExecutorState(trace, coordinates.getViewSnap(),
					coordinates.getThread(), coordinates.getFrame()));
		}
		else {
			state = new TraceRecorderAsyncPcodeExecutorState(coordinates.getRecorder(),
				coordinates.getSnap(), coordinates.getThread(), coordinates.getFrame());
		}
		return new AsyncPcodeExecutor<>(slang, AsyncWrappedPcodeArithmetic.forLanguage(slang),
			state);
	}
}
