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
package ghidra.debug.api.platform;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.task.TaskMonitor;

/**
 * An object for interpreting a trace according to a chosen platform
 * 
 * <p>
 * Platform selection is a bit of a work in progress, but the idea is to allow the mapper to choose
 * relevant languages, compiler specifications, data organization, etc., based on the current
 * debugger context. Most of these are fairly straightforward and relatively static. If the back-end
 * creates the trace with an actual language (non-DATA), then there's a default mapper for "known
 * hosts," (but this can be out prioritized by more complex mappers). If the back-end creates a
 * trace with a DATA language (usually indicating it doesn't recognize the target architecture),
 * then some pluggable examine the name of the debugger and its reported architecture to try to map
 * it on the front end. There may not be any good opinions, in which case, the user can override
 * with any language. That's the "simple" cases.
 * 
 * <p>
 * In more complex cases, e.g., WoW64, the mapper may need to adjust the recommended language based
 * on, e.g., the current program counter and loaded modules. Essentially, it must determine the CPUs
 * current ISA mode and adjust accordingly. There are currently two known situations: 1)
 * Disassembly, and 2) Data (namely pointer) Organization, controlled by the Compiler Spec. The
 * selection logic differs slightly between the two. For disassembly, we allow the mapper specific
 * control of the selected platform, based on the starting address. For data placement, we allow the
 * mapper specific control of the selected platform, based on the current PC. Note that the starting
 * address of the data itself may not always be relevant. At the moment, because of limitations in
 * the {@link Program} API, we actually cannot support selection based on placement address.
 * Instead, at the time we ask the mapper to add a platform to the trace
 * ({@link #addToTrace(TraceObject, long)}), we provide the current focus and snap, so that it can
 * derive the PC or whatever other context is necessary to make its decision. The returned platform
 * is immediately set as current, so that data actions heed the chosen platform.
 */
public interface DebuggerPlatformMapper {

	/**
	 * Get the compiler for a given object
	 * 
	 * @param object the object
	 * @param snap the snap
	 * @return the compiler spec
	 */
	CompilerSpec getCompilerSpec(TraceObject object, long snap);

	/**
	 * Get the language for a given object
	 * 
	 * @param object the object
	 * @param snap the snap
	 * @return the language
	 */
	default Language getLangauge(TraceObject object, long snap) {
		CompilerSpec cSpec = getCompilerSpec(object, snap);
		return cSpec == null ? null : cSpec.getLanguage();
	}

	/**
	 * Prepare the given trace for interpretation under this mapper
	 * 
	 * <p>
	 * Likely, this will need to modify the trace database. It must start its own transaction for
	 * doing so.
	 * 
	 * @param newFocus the newly-focused object
	 * @param snap the snap
	 * @return the resulting platform, which may have already existed
	 */
	TracePlatform addToTrace(TraceObject newFocus, long snap);

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
	 * <p>
	 * Note that the mapper may use an alternative platform than that returned by
	 * {@link #addToTrace(TraceObject, long)}.
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
