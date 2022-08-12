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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.task.TaskMonitor;

/**
 * An object for interpreting a trace according to a chosen platform
 */
public interface DebuggerPlatformMapper {

	/**
	 * Get the compiler for a given object
	 * 
	 * @param object the object
	 * @return the compiler spec
	 */
	CompilerSpec getCompilerSpec(TraceObject object);

	/**
	 * Get the language for a given object
	 * 
	 * @param object the object
	 * @return the language
	 */
	default Language getLangauge(TraceObject object) {
		CompilerSpec cSpec = getCompilerSpec(object);
		return cSpec == null ? null : cSpec.getLanguage();
	}

	/**
	 * Prepare the given trace for interpretation under this mapper
	 * 
	 * <p>
	 * Likely, this will need to modify the trace database. It must start its own transaction for
	 * doing so.
	 * 
	 * @param trace the trace
	 * @param snap the snap
	 */
	void addToTrace(long snap);

	/**
	 * When focus changes, decide if this mapper should remain active
	 * 
	 * @param newFocus the newly-focused object
	 * @param snap the snap, usually the current snap
	 * @return true to remain active, false to select a new mapper
	 */
	boolean canInterpret(TraceObject newFocus, long snap);

	/**
	 * Disassemble starting at a given address and snap, limited to a given address set
	 * 
	 * @param thread the thread if applicable
	 * @param object the object for platform context
	 * @param start the starting address
	 * @param restricted the limit of disassembly
	 * @param snap the snap, usually the current snap
	 * @param monitor a monitor for the disassembler
	 * @return the result
	 */
	DisassemblyResult disassemble(TraceThread thread, TraceObject object,
			Address start, AddressSetView restricted, long snap, TaskMonitor monitor);
}
