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
package ghidra.app.plugin.core.debug.mapping;

import ghidra.app.plugin.core.debug.service.model.DebuggerModelServicePlugin;
import ghidra.app.services.TraceRecorder;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.Trace;

// TODO: Could probably just have Offer.take() go straight to recording....
public interface DebuggerTargetTraceMapper {
	Language getTraceLanguage();

	CompilerSpec getTraceCompilerSpec();

	TraceRecorder startRecording(DebuggerModelServicePlugin service, Trace trace);
}
