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
package ghidra.pcode.exec.trace.data;

import ghidra.pcode.emu.PcodeThread;

/**
 * A data-access shim for a trace's registers
 */
public interface PcodeTraceRegistersAccess extends PcodeTraceDataAccess {

	/**
	 * Initialize the given p-code thread's context register using register context from the trace
	 * at the thread's program counter
	 * 
	 * <p>
	 * This is called during thread construction, after the program counter is initialized from the
	 * same trace thread. This will ensure that the instruction decoder starts in the same mode as
	 * the disassembler was for the trace.
	 * 
	 * @param thread the thread to initialize
	 */
	void initializeThreadContext(PcodeThread<?> thread);
}
