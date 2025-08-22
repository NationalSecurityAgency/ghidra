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

import java.math.BigInteger;
import java.util.Arrays;
import java.util.NoSuchElementException;

import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.DifferenceAddressSetView;
import ghidra.util.Msg;

/**
 * Utilities for working with plain emulators (not trace- or debugger-bound) and programs in
 * scripts.
 */
public enum EmulatorUtilities {
	;
	/**
	 * The conventional name of the memory block used to specify the location of the stack. This
	 * should only be the case for single-threaded emulation.
	 */
	public static final String BLOCK_NAME_STACK = "STACK";

	/**
	 * The default block size used to copy program bytes into the emulator
	 */
	public static final int DEFAULT_BLOCK_SIZE = 4096;
	/**
	 * The default max size to assume for the stack
	 */
	public static final int DEFAULT_STACK_SIZE = 0x4000;
	/**
	 * These utilities will avoid choosing a stack range lower than this bound, as most platforms
	 * will never map this page (even in kernel space) so that 0-valued pointers are never valid.
	 */
	public static final long PAGE_ZERO_END = 0x1000;

	/**
	 * Copy the bytes from the given program into the given emulator's memory.
	 * 
	 * <p>
	 * This copies each initialized block of memory from the given program into the emulator's
	 * shared machine state. Because the machine can have memory of any given type, it will use the
	 * machine's arithmetic to create values from the program's concrete data. Data is copied in
	 * blocks of the given size, which can be tweaked for performance. The default value, used by
	 * {@link #loadProgram(PcodeMachine, Program)} is {@value #DEFAULT_BLOCK_SIZE}.
	 * 
	 * @param <T> the type of values used by the emulator
	 * @param machine the emulator whose memory to initialize
	 * @param program the program whose bytes should be copied into the emulator
	 * @param blockSize the size of the temporary buffer used for copying
	 * @throws MemoryAccessException if the program's memory cannot be read
	 */
	public static <T> void loadProgram(PcodeMachine<T> machine, Program program, int blockSize)
			throws MemoryAccessException {
		byte[] buf = new byte[blockSize];
		PcodeExecutorState<T> state = machine.getSharedState();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!block.isInitialized()) {
				continue;
			}
			for (AddressRange rng : new AddressRangeChunker(block.getAddressRange(),
				buf.length)) {
				int len = block.getBytes(rng.getMinAddress(), buf);
				state.setConcrete(rng.getMinAddress(),
					len == buf.length ? buf : Arrays.copyOf(buf, len));
			}
		}
	}

	/**
	 * Copy the bytes from the given program into the given emulator's memory.
	 * 
	 * @see #loadProgram(PcodeMachine, Program, int)
	 * @param machine the emulator whose memory to initialize
	 * @param program the program whose bytes should be copied into the emulator
	 * @throws MemoryAccessException if the program's memory cannot be read
	 */
	public static void loadProgram(PcodeMachine<?> machine, Program program)
			throws MemoryAccessException {
		loadProgram(machine, program, DEFAULT_BLOCK_SIZE);
	}

	/**
	 * Choose an assumed stack range by examining the entry point for a contextual value of the
	 * stack pointer.
	 * 
	 * @param program the program whose context to examine
	 * @param entry the entry point where context should be examined
	 * @param stackSize the assumed max size of the stack
	 * @return the range assumed to be reserved for the stack, or null if no stack pointer value is
	 *         in the context
	 */
	public static AddressRange chooseStackRangeFromContext(Program program, Address entry,
			int stackSize) {
		ProgramContext ctx = program.getProgramContext();
		CompilerSpec cSpec = program.getCompilerSpec();
		Register sp = cSpec.getStackPointer();
		RegisterValue spVal = ctx.getRegisterValue(sp, entry);
		if (spVal == null || !spVal.hasValue()) {
			return null;
		}

		Address spAddr = cSpec.getStackBaseSpace().getAddress(spVal.getUnsignedValue().longValue());
		if (cSpec.stackGrowsNegative()) {
			Address max = spAddr.subtractWrap(1);
			Address min = spAddr.subtractWrap(stackSize);
			if (min.compareTo(max) > 0) {
				return new AddressRangeImpl(max.getAddressSpace().getMinAddress(), max);
			}
			return new AddressRangeImpl(min, max);
		}
		// Grows positive
		Address min = spAddr;
		Address max = spAddr.addWrap(stackSize - 1);
		if (min.compareTo(max) > 0) {
			return new AddressRangeImpl(min, min.getAddressSpace().getMaxAddress());
		}
		return new AddressRangeImpl(min, max);
	}

	/**
	 * Choose an assumed stack range by examining the program's memory map for a
	 * {@value #BLOCK_NAME_STACK} block.
	 * 
	 * @param program the program to examine
	 * @return the range assumed to be reserved for the stack, or null if no
	 *         {@value #BLOCK_NAME_STACK} block is found.
	 */
	public static AddressRange chooseStackRangeFromBlock(Program program) {
		AddressSpace space = program.getCompilerSpec().getStackBaseSpace();
		MemoryBlock stackBlock = program.getMemory().getBlock(BLOCK_NAME_STACK);
		if (stackBlock == null) {
			return null;
		}
		if (space != stackBlock.getStart().getAddressSpace().getPhysicalSpace()) {
			Msg.showError(EmulatorUtilities.class, null, "Invalid STACK block",
				"The STACK block must be in the stack's base space. Ignoring.");
			return null;
		}
		return new AddressRangeImpl(
			stackBlock.getStart().getPhysicalAddress(),
			stackBlock.getEnd().getPhysicalAddress());
	}

	/**
	 * Choose an assumed stack range
	 * 
	 * <p>
	 * This will first examine the entry point's context for a stack pointer value using
	 * {@link #chooseStackRangeFromContext(Program, Address, int)}. Then, it will examine the
	 * progam's memory map using {@link #chooseStackRangeFromBlock(Program)}. Finally, it will
	 * search for a slack address range of the requested size. That is, it seeks a range that does
	 * not intersect any existing memory block. If possible, this will avoid choosing a stack range
	 * that intersects [0, 4096), so that 0-valued pointers are in fact invalid.
	 * 
	 * <p>
	 * Note that a stack is not formally "allocated." Instead, the range is used to initialize a
	 * thread's stack pointer. Unless instrumentation is added to detect a stack overflow, nothing
	 * really prevents the program from exceeding the returned range. Thus, {@code stackSize} should
	 * be large enough to accommodate the target. Additionally, the user or client code should be
	 * prepared for undefined behavior caused by an unmitigated stack overflow.
	 * 
	 * @param program the program
	 * @param entry the entry point, in case context there defines an initial stack pointer
	 * @param stackSize the maximum expected size of the stack
	 * @return the chosen range assumed to be used for the stack
	 */
	public static AddressRange chooseStackRange(Program program, Address entry, int stackSize) {
		AddressRange customByContext = chooseStackRangeFromContext(program, entry, stackSize);
		if (customByContext != null) {
			return customByContext;
		}
		AddressRange customByBlock = chooseStackRangeFromBlock(program);
		if (customByBlock != null) {
			return customByBlock;
		}
		// Search for a range of the given size outside any block
		AddressSpace space = program.getCompilerSpec().getStackBaseSpace();
		Address max = space.getMaxAddress();
		AddressSet eligible;
		if (max.getOffsetAsBigInteger().compareTo(BigInteger.valueOf(0x1000)) < 0) {
			eligible = new AddressSet(space.getMinAddress(), max);
		}
		else {
			eligible = new AddressSet(space.getAddress(0x1000), max);
		}

		AddressSetView left = new DifferenceAddressSetView(eligible, program.getMemory());
		for (AddressRange candidate : left) {
			if (Long.compareUnsigned(candidate.getLength(), stackSize) >= 0) {
				try {
					return new AddressRangeImpl(candidate.getMinAddress(), stackSize);
				}
				catch (AddressOverflowException e) {
					throw new AssertionError(e);
				}
			}
		}
		throw new NoSuchElementException();
	}

	/**
	 * Choose an assumed stack range of size {@value #DEFAULT_STACK_SIZE}
	 * 
	 * @see #chooseStackRange(Program, Address, int)
	 * @param program the program
	 * @param entry the entry point, in case context there defines an initial stack pointer
	 * @return the chosen range assumed to be used for the stack
	 */
	public static AddressRange chooseStackRange(Program program, Address entry) {
		return chooseStackRange(program, entry, DEFAULT_STACK_SIZE);
	}

	/**
	 * Prepare a thread to emulate a given function
	 * 
	 * @param <T> the type of values in the emulator
	 * @param thread the thread whose state to initialize
	 * @param function the function to prepare to enter
	 * @param stackSize the maximum expected size of the stack
	 */
	public static <T> void initializeForFunction(PcodeThread<T> thread, Function function,
			int stackSize) {
		PcodeArithmetic<T> arithmetic = thread.getArithmetic();

		Program program = function.getProgram();
		Address entry = function.getEntryPoint();
		CompilerSpec cSpec = program.getCompilerSpec();
		Register sp = cSpec.getStackPointer();
		ThreadPcodeExecutorState<T> state = thread.getState();

		ProgramProcessorContext ctx =
			new ProgramProcessorContext(program.getProgramContext(), entry);
		for (Register reg : ctx.getRegisters()) {
			if (!reg.isBaseRegister()) {
				continue;
			}
			RegisterValue rv = ctx.getRegisterValue(reg);
			if (rv == null || !rv.hasAnyValue()) {
				continue;
			}
			/**
			 * NOTE: In theory, there's no need to combine masked values, if this is a fresh
			 * emulator. If I had to guess, the client would want their values to take precedence,
			 * so they should overwrite the values after calling this method. Combining can be
			 * problematic, because the emulator could return some abstraction for the current
			 * value.
			 */
			state.setRegisterValue(rv);
		}

		AddressRange stack = chooseStackRange(program, entry);
		long stackOffset = cSpec.stackGrowsNegative() ? stack.getMaxAddress().getOffset() + 1
				: stack.getMinAddress().getOffset();
		state.setVar(sp, arithmetic.fromConst(stackOffset, sp.getMinimumByteSize()));

		thread.overrideCounter(entry);
	}
}
