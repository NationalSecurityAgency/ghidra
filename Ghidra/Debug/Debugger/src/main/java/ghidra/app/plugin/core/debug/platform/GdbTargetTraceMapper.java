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
package ghidra.app.plugin.core.debug.platform;

import java.util.Collection;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.dbg.target.*;
import ghidra.program.model.lang.*;

public class GdbTargetTraceMapper extends AbstractDebuggerTargetTraceMapper {
	public GdbTargetTraceMapper(TargetObject target, LanguageID langID, CompilerSpecID csId,
			Collection<String> extraRegNames)
			throws LanguageNotFoundException, CompilerSpecNotFoundException {
		super(target, langID, csId, extraRegNames);
	}

	@Override
	protected DebuggerMemoryMapper createMemoryMapper(TargetMemory memory) {
		return new DefaultDebuggerMemoryMapper(language, memory.getModel());
	}

	@Override
	protected DebuggerRegisterMapper createRegisterMapper(
			TargetRegisterContainer registers) {
		return new DefaultDebuggerRegisterMapper(cSpec, registers, false);
	}
}
