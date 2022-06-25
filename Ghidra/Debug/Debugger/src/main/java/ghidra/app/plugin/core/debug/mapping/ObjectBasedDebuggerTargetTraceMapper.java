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

import java.util.Collection;

import ghidra.app.plugin.core.debug.service.model.DebuggerModelServicePlugin;
import ghidra.app.plugin.core.debug.service.model.record.ObjectBasedTraceRecorder;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.target.*;
import ghidra.program.model.lang.*;
import ghidra.trace.model.Trace;

public class ObjectBasedDebuggerTargetTraceMapper extends DefaultDebuggerTargetTraceMapper {

	protected ObjectBasedDebuggerMemoryMapper memoryMapper;

	public ObjectBasedDebuggerTargetTraceMapper(TargetObject target, LanguageID langID,
			CompilerSpecID csID, Collection<String> extraRegNames)
			throws LanguageNotFoundException, CompilerSpecNotFoundException {
		super(target, langID, csID, extraRegNames);
	}

	@Override
	protected DebuggerMemoryMapper createMemoryMapper(TargetMemory memory) {
		// TODO: Validate regions to not overlap?
		// Could probably do that in unit testing of model instead
		return memoryMapper;
	}

	@Override
	protected DebuggerRegisterMapper createRegisterMapper(TargetRegisterContainer registers) {
		throw new UnsupportedOperationException();
	}

	@Override
	public TraceRecorder startRecording(DebuggerModelServicePlugin service, Trace trace) {
		this.memoryMapper = new ObjectBasedDebuggerMemoryMapper(trace);
		return new ObjectBasedTraceRecorder(service, trace, target, this);
	}
}
