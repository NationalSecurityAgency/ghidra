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

import java.util.Collection;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.DefaultPcodeThread.PcodeEmulationLibrary;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * A machine which execute p-code on state of an abstract type
 *
 * @param <T> the type of objects in the machine's state
 */
public interface PcodeMachine<T> {

	/**
	 * Specifies whether or not to interrupt on p-code breakpoints
	 */
	enum SwiMode {
		/**
		 * Heed {@link PcodeEmulationLibrary#emu_swi()} calls
		 */
		ACTIVE,
		/**
		 * Ignore all {@link PcodeEmulationLibrary#emu_swi()} calls
		 */
		IGNORE_ALL,
		/**
		 * Ignore {@link PcodeEmulationLibrary#emu_swi()} calls for one p-code step
		 * 
		 * <p>
		 * The mode is reset to {@link #ACTIVE} after one p-code step, whether or not that step
		 * causes an SWI.
		 */
		IGNORE_STEP,
	}

	/**
	 * The kind of access breakpoint
	 */
	enum AccessKind {
		/** A read access breakpoint */
		R(true, false),
		/** A write access breakpoint */
		W(false, true),
		/** A read/write access breakpoint */
		RW(true, true);

		private final boolean trapsRead;
		private final boolean trapsWrite;

		private AccessKind(boolean trapsRead, boolean trapsWrite) {
			this.trapsRead = trapsRead;
			this.trapsWrite = trapsWrite;
			;
		}

		/**
		 * Check if this kind of breakpoint should trap a read, i.e., {@link PcodeOp#LOAD}
		 * 
		 * @return true to interrupt
		 */
		public boolean trapsRead() {
			return trapsRead;
		}

		/**
		 * Check if this kind of breakpoint should trap a write, i.e., {@link PcodeOp#STORE}
		 * 
		 * @return true to interrupt
		 */
		public boolean trapsWrite() {
			return trapsWrite;
		}
	}

	/**
	 * Get the machine's Sleigh language (processor model)
	 * 
	 * @return the language
	 */
	SleighLanguage getLanguage();

	/**
	 * Get the arithmetic applied by the machine
	 * 
	 * @return the arithmetic
	 */
	PcodeArithmetic<T> getArithmetic();

	/**
	 * Change the efficacy of p-code breakpoints
	 * 
	 * <p>
	 * This is used to prevent breakpoints from interrupting at inappropriate times, e.g., upon
	 * continuing from a breakpoint.
	 * 
	 * @param mode the new mode
	 * @see #withSoftwareInterruptMode(SwiMode)
	 */
	void setSoftwareInterruptMode(SwiMode mode);

	/**
	 * Get the current software interrupt mode
	 * 
	 * @return the mode
	 */
	SwiMode getSoftwareInterruptMode();

	/**
	 * Get the userop library common to all threads in the machine.
	 * 
	 * <p>
	 * Note that threads may have larger libraries, but each contains all the userops in this
	 * library.
	 * 
	 * @return the userop library
	 */
	PcodeUseropLibrary<T> getUseropLibrary();

	/**
	 * Get a userop library which at least declares all userops available in each thread userop
	 * library.
	 * 
	 * <p>
	 * Thread userop libraries may have more userops than are defined in the machine's userop
	 * library. However, to compile Sleigh programs linked to thread libraries, the thread's userops
	 * must be known to the compiler. The stub library will name all userops common among the
	 * threads, even if their definitions vary. <b>WARNING:</b> The stub library is not required to
	 * provide implementations of the userops. Often they will throw exceptions, so do not attempt
	 * to use the returned library in an executor.
	 * 
	 * @return the stub library
	 */
	PcodeUseropLibrary<T> getStubUseropLibrary();

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
	 * Collect all threads present in the machine
	 * 
	 * @return the collection of threads
	 */
	Collection<? extends PcodeThread<T>> getAllThreads();

	/**
	 * Get the machine's shared (memory) state
	 * 
	 * <p>
	 * The returned state will may throw {@link IllegalArgumentException} if the client requests
	 * register values of it. This state is shared among all threads in this machine.
	 * 
	 * @return the memory state
	 */
	PcodeExecutorState<T> getSharedState();

	/**
	 * Set the suspension state of the machine
	 * 
	 * @see PcodeThread#setSuspended(boolean)
	 */
	void setSuspended(boolean suspended);

	/**
	 * Check the suspension state of the machine
	 * 
	 * @see PcodeThread#getSuspended()
	 */
	boolean isSuspended();

	/**
	 * Compile the given Sleigh code for execution by a thread of this machine
	 * 
	 * <p>
	 * This links in the userop library given at construction time and those defining the emulation
	 * userops, e.g., {@code emu_swi}.
	 * 
	 * @param sourceName a user-defined source name for the resulting "program"
	 * @param lines the Sleigh source
	 * @return the compiled program
	 */
	PcodeProgram compileSleigh(String sourceName, String source);

	/**
	 * Override the p-code at the given address with the given Sleigh source
	 * 
	 * <p>
	 * This will attempt to compile the given source against this machine's userop library and then
	 * inject it at the given address. The resulting p-code <em>replaces</em> that which would be
	 * executed by decoding the instruction at the given address. The means the machine will not
	 * decode, nor advance its counter, unless the Sleigh causes it. In most cases, the Sleigh will
	 * call {@link PcodeEmulationLibrary#emu_exec_decoded()} to cause the machine to decode and
	 * execute the overridden instruction.
	 * 
	 * <p>
	 * Each address can have at most a single inject. If there is already one present, it is
	 * replaced and the old inject completely forgotten. The injector does not support chaining or
	 * double-wrapping, etc.
	 * 
	 * <p>
	 * No synchronization is provided on the internal injection storage. Clients should ensure the
	 * machine is not executing when injecting p-code. Additionally, the client must ensure only one
	 * thread is injecting p-code to the machine at a time.
	 * 
	 * @param address the address to inject at
	 * @param source the Sleigh source to compile and inject
	 */
	void inject(Address address, String source);

	/**
	 * Remove the inject, if present, at the given address
	 * 
	 * @param address the address to clear
	 */
	void clearInject(Address address);

	/**
	 * Remove all injects from this machine
	 * 
	 * <p>
	 * This will clear execution breakpoints, but not access breakpoints. See
	 * {@link #clearAccessBreakpoints()}.
	 */
	void clearAllInjects();

	/**
	 * Add a conditional execution breakpoint at the given address
	 * 
	 * <p>
	 * Breakpoints are implemented at the p-code level using an inject, without modification to the
	 * emulated image. As such, it cannot coexist with another inject. A client needing to break
	 * during an inject must use {@link PcodeEmulationLibrary#emu_swi()} in the injected Sleigh.
	 * 
	 * <p>
	 * No synchronization is provided on the internal breakpoint storage. Clients should ensure the
	 * machine is not executing when adding breakpoints. Additionally, the client must ensure only
	 * one thread is adding breakpoints to the machine at a time.
	 * 
	 * @param address the address at which to break
	 * @param sleighCondition a Sleigh expression which controls the breakpoint
	 */
	void addBreakpoint(Address address, String sleighCondition);

	/**
	 * Add an access breakpoint over the given range
	 * 
	 * <p>
	 * Access breakpoints are implemented out of band, without modification to the emulated image.
	 * The breakpoints are only effective for p-code {@link PcodeOp#LOAD} and {@link PcodeOp#STORE}
	 * operations with concrete offsets. Thus, an operation that refers directly to a memory
	 * address, e.g., a memory-mapped register, will not be trapped. Similarly, access breakpoints
	 * on registers or unique variables will not work. Access to an abstract offset that cannot be
	 * made concrete, i.e., via {@link PcodeArithmetic#toConcrete(Object, Purpose)} cannot be
	 * trapped. To interrupt on direct and/or abstract accesses, consider wrapping the relevant
	 * state and/or overriding {@link PcodeExecutorStatePiece#getVar(Varnode, Reason)} and related.
	 * For accesses to abstract offsets, consider overriding
	 * {@link AbstractPcodeMachine#checkLoad(AddressSpace, Object)} and/or
	 * {@link AbstractPcodeMachine#checkStore(AddressSpace, Object)} instead.
	 * 
	 * <p>
	 * A breakpoint's range cannot cross more than one page boundary. Pages are 4096 bytes each.
	 * This allows implementations to optimize checking for breakpoints. If a breakpoint does not
	 * follow this rule, the behavior is undefined. Breakpoints may overlap, but currently no
	 * indication is given as to which breakpoint interrupted emulation.
	 * 
	 * <p>
	 * No synchronization is provided on the internal breakpoint storage. Clients should ensure the
	 * machine is not executing when adding breakpoints. Additionally, the client must ensure only
	 * one thread is adding breakpoints to the machine at a time.
	 * 
	 * @param range the address range to trap
	 * @param kind the kind of access to trap
	 */
	void addAccessBreakpoint(AddressRange range, AccessKind kind);

	/**
	 * Remove all access breakpoints from this machine
	 */
	void clearAccessBreakpoints();
}
