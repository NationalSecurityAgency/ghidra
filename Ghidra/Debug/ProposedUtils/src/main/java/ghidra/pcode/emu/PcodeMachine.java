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
package ghidra.pcode.emu;

import java.util.List;

import ghidra.pcode.emu.DefaultPcodeThread.SleighEmulationLibrary;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.program.model.address.Address;

/**
 * A machine which execute p-code on state of an abstract type
 *
 * @param <T> the type of objects in the machine's state
 */
public interface PcodeMachine<T> {

	/**
	 * Create a new thread with a default name in this machine
	 * 
	 * @return the new thread
	 */
	PcodeThread<T> newThread();

	/**
	 * Create a new thread with the given name in this machine
	 * 
	 * @param name the name
	 * @return the new thread
	 */
	PcodeThread<T> newThread(String name);

	/**
	 * Get the thread, if present, with the given name
	 * 
	 * @param name the name
	 * @param createIfAbsent create a new thread if the thread does not already exist
	 * @return the thread, or {@code null} if absent and not created
	 */
	PcodeThread<T> getThread(String name, boolean createIfAbsent);

	/**
	 * Get the machine's memory state
	 * 
	 * <p>
	 * The returned state will may throw {@link IllegalArgumentException} if the client requests
	 * register values of it. This state is shared among all threads in this machine.
	 * 
	 * @return the memory state
	 */
	PcodeExecutorState<T> getMemoryState();

	/**
	 * Compile the given SLEIGH code for execution by a thread of this machine
	 * 
	 * <p>
	 * This links in the userop library given at construction time and those defining the emulation
	 * userops, e.g., {@code emu_swi}.
	 * 
	 * @param sourceName a user-defined source name for the resulting "program"
	 * @param lines the lines of SLEIGH source code
	 * @return the compiled program
	 */
	PcodeProgram compileSleigh(String sourceName, List<String> lines);

	/**
	 * Override the p-code at the given address with the given SLEIGH source
	 * 
	 * <p>
	 * This will attempt to compile the given source against this machine's userop library and then
	 * will inject it at the given address. The resulting p-code <em>replaces</em> that which would
	 * be executed by decoding the instruction at the given address. The means the machine will not
	 * decode, nor advance its counter, unless the SLEIGH causes it. In most cases, the SLEIGH will
	 * call {@link SleighEmulationLibrary#emu_exec_decoded()} to cause the machine to decode and
	 * execute the overridden instruction.
	 * 
	 * <p>
	 * Each address can have at most a single inject. If there is already one present, it is
	 * replaced and the old inject completely forgotten. The injector does not support chaining or
	 * double-wrapping, etc.
	 * 
	 * @param address the address to inject at
	 * @param sleigh the SLEIGH source to compile and inject
	 */
	void inject(Address address, List<String> sleigh);

	/**
	 * Remove the inject, if present, at the given address
	 * 
	 * @param address the address to clear
	 */
	void clearInject(Address address);

	/**
	 * Remove all injects from this machine
	 */
	void clearAllInjects();

	/**
	 * Add a (conditional) breakpoint at the given address
	 * 
	 * <p>
	 * Breakpoints are implemented at the p-code level using an inject, without modification to the
	 * emulated image. As such, it cannot coexist with another inject. A client needing to break
	 * during an inject must use {@link SleighEmulationLibrary#emu_swi()} in the injected SLEIGH.
	 * 
	 * @param address the address at which to break
	 * @param sleighCondition a SLEIGH expression which controls the breakpoint
	 */
	void addBreakpoint(Address address, String sleighCondition);
}
