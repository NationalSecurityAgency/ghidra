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
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

import com.google.common.collect.Range;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.DefaultLanguageService;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.Trace;
import ghidra.trace.model.listing.TraceCodeRegisterSpace;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.symbol.TraceLabelSymbol;
import ghidra.trace.model.symbol.TraceNamespaceSymbol;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This script populates a trace database for demonstrations purposes and opens it in the current
 * tool.
 * 
 * <p>
 * Your current tool had better be the "TraceBrowser"! The demonstration serves two purposes. 1) It
 * puts interesting data into the TraceBrowser and leaves some annotations as an exercise. 2) It
 * demonstrates how a decent portion the Trace API works.
 * 
 * <p>
 * A Trace is basically a collection of observations of memory and registers over the lifetime of an
 * application or computer system. In Ghidra, the Trace object also supports many of the same
 * annotations as does Program. In the same way that Program brings knowledge markup to an image of
 * bytes, Trace brings knowledge markup to bytes observed over time.
 * 
 * <p>
 * Effectively, if you take the cross-product of Program with time and add Threads, Breakpoints,
 * etc., you get Trace. It's a lot. In order to use all the UI components which take a Program,
 * Trace can present itself as a Program at a particular point in time.
 * 
 * <p>
 * Each particular component will be introduced as its used in the script below, but for now some
 * core concepts:
 * 
 * <ul>
 * <li>A point in time is called a "snap." These don't necessarily correspond to any real unit of
 * time, though they may. The only requirement is that they are numbered in chronological
 * order.</li>
 * <li>Every annotation has a "lifespan," which is the range of snaps for which the annotation is
 * effective. Some annotations may overlap, others may not. In general, if the corresponding concept
 * in Program permits address overlap, then Trace permits both address and time overlap. If not,
 * then neither is permitted. In essense, Trace defines overlap as the intersection of rectangles,
 * where an annotation's X dimension is it's address range, and its Y dimension is its lifespan.
 * </li>
 * <li>Observations in memory happen at a particular snap and are assumed in effect until another
 * observation changes that. To record the "freshness" of observations, the memory manager tags
 * regions as KNOWN, UNKNOWN, or ERROR. An observation implicitly marks the affected region as
 * KNOWN. The intent is to grey the background for regions where memory is UNKNOWN for the current
 * snap.</li>
 * <li>Observations of registers behave exactly the same as observations for memory, by leveraging
 * Ghidra's "register space." The only difference is that those observations must be recorded with
 * respect to a given thread. Each thread is effectively allocated its own copy of the register
 * space. Most the the API components require you to obtain a special "register space" for a given
 * thread before recording observations of or applying annotations to that thread.</li>
 * </ul>
 * 
 * <p>
 * After you've run this script, a trace should appear in the UI. Note that there is not yet a way
 * to save a trace in the UI. As an exercise, try adding data units to analyze the threads' stacks.
 * It may take some getting accustomed to, but the rules for laying down units should be very
 * similar to those in a Program. However, the Trace must take the applied units and decide how far
 * into the future they are effective. In general, it defaults to "from here on out." However, two
 * conditions may cause the trace to choose an ending tick: 1) The underlying bytes change sometime
 * in the future, and 2) There is an overlapping code unit sometime in the future.
 * 
 * <p>
 * The trace chooses the latest tick possible preceding any byte change or existing code unit, so
 * that the unit's underlying bytes remain constant for its lifespan, and the unit does not overlap
 * any existing unit. This rule causes some odd behavior for null-terminated strings. I intend to
 * adjust this rule slightly for static data types wrt/ byte changes. For those, the placed unit
 * should be truncated as described above, however, another data unit of the same type can be placed
 * at the change. The same rule is then applied iteratively into the future until an overlapping
 * unit is encountered, or there are no remaining byte changes.
 */
public class PopulateDemoTrace extends GhidraScript {

	/**
	 * The Memory APIs all use Java NIO ByteBuffer. While it has it can sometimes be annoying, it
	 * provides most of the conveniences you'd need for packing arbitrary data into a memory buffer.
	 * I'll allocate one here large enough to write a couple values at a time.
	 */
	private ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);

	/**
	 * I will imagine the execution of two threads, so I'll need a stack for each.
	 */
	private static final long STACK1_BOTTOM = 0x001f0000;
	private static final long STACK2_BOTTOM = 0x002f0000;

	/**
	 * Objects I will need to construct the trace, and a few convenient handles to keep around.
	 */
	private LanguageService langServ;
	private Language x86Lang;
	private CompilerSpec cspec;
	private Trace trace;
	private TraceMemoryManager memory;
	private AddressSpace defaultSpace;
	private TraceNamespaceSymbol global;

	/**
	 * Labels I will place in the trace, and whose addresses I'll use instead of hardcoding.
	 * 
	 * Note that the other symbol types are implemented, but not demonstrated here as they haven't
	 * been tested in the UI.
	 */
	private TraceLabelSymbol mainLabel;
	private TraceLabelSymbol cloneLabel;
	private TraceLabelSymbol childLabel;
	private TraceLabelSymbol exitLabel;

	/**
	 * Fields to store the handle to the first (main) thread and its registers
	 */
	private TraceThread thread1;
	private TraceMemoryRegisterSpace regs1;

	/**
	 * Fields to store the handle to the second (cloned) thread and its registers
	 */
	private TraceThread thread2;
	private TraceMemoryRegisterSpace regs2;

	/**
	 * Create an address in the processor's (x86_64) default space.
	 * 
	 * @param offset the byte offset
	 * @return the address
	 */
	protected Address addr(long offset) {
		return defaultSpace.getAddress(offset);
	}

	/**
	 * Create an address range in the processor's default space.
	 * 
	 * @param min the minimum byte offset
	 * @param max the maximum (inclusive) byte offset
	 * @return the range
	 */
	protected AddressRange rng(long min, long max) {
		return new AddressRangeImpl(addr(min), addr(max));
	}

	/**
	 * Get an x86_64 register by name
	 * 
	 * @param name the name
	 * @return the register
	 */
	protected Register reg(String name) {
		return x86Lang.getRegister(name);
	}

	/**
	 * Set RIP at the given tick for the given space to the address of a given instruction
	 * 
	 * @param tick the tick
	 * @param regs the register space for a given thread
	 * @param ins the instructions
	 */
	protected void putRIP(long tick, TraceMemoryRegisterSpace regs, Instruction ins) {
		regs.setValue(tick,
			new RegisterValue(reg("RIP"), ins.getAddress().getOffsetAsBigInteger()));
	}

	/**
	 * (Re-)place a data unit if necessary.
	 * 
	 * This is a TODO item in the Trace database. Currently, the API allows a caller to modify bytes
	 * in the middle of a code unit's lifespan. The intended rule is: If the modification is at the
	 * unit's start tick, the behavior should be the same as Program (permit changes under static
	 * data types only). If the modification is after, then the code unit's lifespan should be
	 * truncated to allow the modification. Additionally, for static data types, a new unit should
	 * be placed to fill out the old lifespan.
	 * 
	 * Because that TODO is not implemented yet, this method corrects the issue by implementing
	 * effectively the same rule.
	 * 
	 * @param tick the tick where a register change may have occurred
	 * @param thread the thread whose registers to check/correct
	 * @param reg the register to check/correct
	 * @throws CodeUnitInsertionException shouldn't happen
	 * @throws CancelledException shouldn't happen
	 */
	protected void placeRegUnitIfNeeded(long tick, TraceThread thread, Register reg)
			throws CodeUnitInsertionException, CancelledException {
		// NOTE: This is compensating for a TODO in the memory and code managers

		// TODO: Consider convenience methods TraceThread#getMemorySpace(boolean), etc
		TraceMemoryRegisterSpace mem =
			thread.getTrace().getMemoryManager().getMemoryRegisterSpace(thread, true);
		// First check if the value was set at all
		if (mem.getState(tick, reg) != TraceMemoryState.KNOWN) {
			return;
		}
		// The value may have been set, but not changed
		RegisterValue oldValue = mem.getValue(tick - 1, reg);
		RegisterValue newValue = mem.getValue(tick, reg);
		if (Objects.equals(oldValue, newValue)) {
			return;
		}

		TraceCodeRegisterSpace code =
			thread.getTrace().getCodeManager().getCodeRegisterSpace(thread, true);
		code.definedUnits().clear(Range.atLeast(tick), reg, TaskMonitor.DUMMY);
		code.definedData().create(Range.atLeast(tick), reg, PointerDataType.dataType);
	}

	/**
	 * Invoke the above method for the three registers I modify during this demonstration.
	 * 
	 * @param tick the tick where the registers may have changed
	 * @param thread the thread to check/correct
	 * @throws CodeUnitInsertionException shouldn't happen
	 * @throws CancelledException shoudn't happen
	 */
	protected void placeRegUnits(long tick, TraceThread thread)
			throws CodeUnitInsertionException, CancelledException {
		placeRegUnitIfNeeded(tick, thread, reg("RIP"));
		placeRegUnitIfNeeded(tick, thread, reg("RSP"));
		placeRegUnitIfNeeded(tick, thread, reg("RBP"));
	}

	@Override
	protected void run() throws Exception {
		/**
		 * Construct a Trace with x86_64 and the default compiler
		 */
		langServ = DefaultLanguageService.getLanguageService();
		x86Lang = langServ.getLanguage(new LanguageID("x86:LE:64:default"));
		defaultSpace = x86Lang.getAddressFactory().getDefaultAddressSpace();
		cspec = x86Lang.getDefaultCompilerSpec();
		trace = new DBTrace("Demo", cspec, this);

		/**
		 * Grab the memory manager and global namespace symbol for convenience
		 */
		memory = trace.getMemoryManager();
		global = trace.getSymbolManager().getGlobalNamespace();

		/**
		 * A list of instructions in the main function for ease of setting RIP
		 */
		List<Instruction> mainInstructions = new ArrayList<>();

		/**
		 * Instead of tracking this by hand, use variables!
		 */
		int stack1offset = 0;
		int stack2offset = 0;
		int pc1 = 0;
		int pc2 = 0;

		/**
		 * For clarity, I will add each tick to the trace in its own transaction. The
		 * UndoableTransaction class eases the syntax and reduces errors in starting and ending
		 * transactions. This Utility deprecates ProgramTransaction, as it can be used on any domain
		 * object.
		 */
		try (UndoableTransaction tid =
			UndoableTransaction.start(trace, "Populate First Snapshot", true)) {
			/**
			 * While not strictly required, each tick should be explicitly added to the database and
			 * given a description. Some things may mis-behave if there does not exist at least one
			 * tick.
			 */
			TraceSnapshot snapshot = trace.getTimeManager().createSnapshot("Launched");
			long snap = snapshot.getKey();

			/**
			 * Add two regions to the trace: ".text" for the program instructions and "[STACK 1]"
			 * for the main thread's stack. Again, while not strictly required all memory
			 * observations should occur within a recorded region. As regions may come and go
			 * through the course of execution, this is the first place where we see a lifespan.
			 * These are represented using a Range object from Guava. While you may specify open or
			 * closed ends, the range will be normalized to use closed ends. Also Long.MIN and
			 * Long.MAX will be normalized to negative and positive infinity, respectively. In
			 * general, observations should be given the range [currentTick..INF) meaning "from here
			 * on out". Most annotations allow mutation of the end tick.
			 * 
			 * The trace database DOES permit recording and retrieving observations outside any
			 * recorded region. However, when viewed as a Program, only the current regions are
			 * presented as memory blocks. Thus, observations outside a region are not visible in
			 * the UI.
			 */
			memory.addRegion(".text", Range.atLeast(snap), rng(0x00400000, 0x00400fff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			memory.addRegion("[STACK 1]", Range.atLeast(snap), rng(0x00100000, 0x001effff),
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);

			/**
			 * Create the main thread, assumed alive from here on out.
			 */
			thread1 = trace.getThreadManager().addThread("Thread 1", Range.atLeast(snap));
			/**
			 * Get a handle to the main thread's register values.
			 * 
			 * Note that the values are accessed via the memory manager. The memory implementation
			 * is re-used to record register values, since registers to Ghidra are just special
			 * addresses. As a convenience, the register-space interface of the memory manager
			 * presents conveniences which use Register and RegisterValue instead of Address and
			 * ByteBuffer.
			 */
			regs1 = memory.getMemoryRegisterSpace(thread1, true);

			/**
			 * Place these labels. I guessed and checked as far as positions, go. There just needs
			 * to be enough room in main for the assembled instructions below. "child" has to be
			 * placed more carefully. Perhaps in a later version of this demo, I will upgrade main,
			 * clone, and exit to actual functions.
			 */
			mainLabel = trace.getSymbolManager()
					.labels()
					.create(snap, null, addr(0x00400000),
						"main", global, SourceType.USER_DEFINED);
			cloneLabel = trace.getSymbolManager()
					.labels()
					.create(snap, null, addr(0x00400060),
						"clone", global, SourceType.USER_DEFINED);
			childLabel = trace.getSymbolManager()
					.labels()
					.create(snap, null, addr(0x00400034),
						"child", global, SourceType.USER_DEFINED);
			exitLabel = trace.getSymbolManager()
					.labels()
					.create(snap, null, addr(0x00400061),
						"exit", global, SourceType.USER_DEFINED);

			/**
			 * Note the use of getProgramView as a means of using components intended for Program
			 * with Trace. Such views typically have a fixed tick, however, you can also obtain a
			 * view which can seek to a different tick. The variable-tick version is generally for
			 * UI compatibility, whereas the fixed-tick version is generally for API compatibility.
			 * Here we use it to apply the assembler.
			 * 
			 * This is the "main" function of the demonstration. it is imagined with a decent bit of
			 * fidelity, but some bits are elided for my sanity and to stay succinct.
			 * 
			 * It starts with the typical stack frame setup and then immediately clones a second
			 * thread. I arbitrarily decided which thread would execute for each step. The cloned
			 * thread then jumps to the "child" portion of the code while the main thread falls
			 * through. Each places some data on its stack and then terminate. The "clone" and
			 * "exit" functions are stubbed out, but one should imagine they are system calls.
			 * 
			 * A call to "clone" results in the creation of a second thread with stack. That stack
			 * contains only the return address. The caller's RAX is set to 0, the clone's RAX is
			 * set to 1.
			 * 
			 * A call to "exit" results in the immediate termination of the calling thread.
			 */
			Assembler asm = Assemblers.getAssembler(trace.getFixedProgramView(snap));
			Iterator<Instruction> mainBlock = asm.assemble(mainLabel.getAddress(), //
				"PUSH RBP", //
				"MOV RBP,RSP", //
				"CALL clone", //
				"TEST EAX,EAX", //
				"JNZ child", //
				"SUB RSP,0x10", //
				"MOV dword ptr [RSP],0x6c6c6548", //
				"MOV dword ptr [RSP+4],0x57202c6f", //
				"MOV dword ptr [RSP+8],0x646c726f", //
				"MOV word ptr [RSP+0xc],0x21", //
				"CALL exit", //
				"SUB RSP,0x10", //
				"MOV dword ptr [RSP],0x2c657942", //
				"MOV dword ptr [RSP+4],0x726f5720", //
				"MOV dword ptr [RSP+8],0x21646c", //
				"CALL exit" //
			);
			mainBlock.forEachRemaining(mainInstructions::add);

			/**
			 * Stub out "clone"
			 */
			asm.assemble(cloneLabel.getAddress(), "RET");
			trace.getCodeManager()
					.codeUnits()
					.getAt(0, cloneLabel.getAddress())
					.setComment(
						CodeUnit.EOL_COMMENT, "Pretend this is a syscall");

			/**
			 * Stub out "exit"
			 */
			asm.assemble(exitLabel.getAddress(), "HLT");
			trace.getCodeManager()
					.codeUnits()
					.getAt(0, exitLabel.getAddress())
					.setComment(
						CodeUnit.EOL_COMMENT, "Pretend this is a syscall");

			/**
			 * "Launch" the program by initializing RIP and RSP of the main thread
			 */
			putRIP(snap, regs1, mainInstructions.get(pc1));
			regs1.setValue(snap,
				new RegisterValue(reg("RSP"), BigInteger.valueOf(STACK1_BOTTOM + stack1offset)));

			placeRegUnits(snap, thread1);
		}

		/**
		 * Just hand emulate the stepping
		 */
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap = trace.getTimeManager().createSnapshot("Stepped: PUSH RBP").getKey();

			stack1offset -= 8;
			putRIP(snap, regs1, mainInstructions.get(++pc1));
			/**
			 * This demonstrates recording a memory observation, i.e., writing to trace memory.
			 * 
			 * The ByteBuffer API can be a bit annoying, but it generally follows the same pattern,
			 * and it permits packing an arbitrary number of "fields" into the buffer (limited by
			 * the allocated size of the buffer). If this API is too inconvenient, you can also use
			 * getBufferAt, to use the familiar MemBuffer API.
			 */
			memory.putBytes(snap, addr(STACK1_BOTTOM - 8), buf.clear().putLong(0).flip());
			/**
			 * Since register "memory" is just an extension of physical memory, the same API is
			 * available for recording register observations.
			 */
			regs1.putBytes(snap, reg("RSP"),
				buf.clear().putLong(STACK1_BOTTOM + stack1offset).flip());

			placeRegUnits(snap, thread1);
		}

		/**
		 * More hand emulation
		 */
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap = trace.getTimeManager().createSnapshot("Stepped: MOV RBP,RSP").getKey();

			putRIP(snap, regs1, mainInstructions.get(++pc1));
			regs1.putBytes(snap, reg("RBP"),
				buf.clear().putLong(STACK1_BOTTOM + stack1offset).flip());

			placeRegUnits(snap, thread1);
		}

		/**
		 * Emulate the clone "syscall"
		 * 
		 * While this is a complicated call, there is nothing new to demonstrate in its
		 * implementation. As an exercise, see if you can follow what is happening within.
		 */
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap = trace.getTimeManager()
					.createSnapshot("Stepped Thread 1: CALL clone -> Thread 2")
					.getKey();

			memory.addRegion("[STACK 2]", Range.atLeast(snap), rng(0x00200000, 0x002effff),
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);

			thread2 = trace.getThreadManager().addThread("Thread 2", Range.atLeast(snap));
			regs2 = memory.getMemoryRegisterSpace(thread2, true);

			stack1offset -= 8;
			regs1.putBytes(snap, reg("RIP"),
				buf.clear().putLong(cloneLabel.getAddress().getOffset()).flip());
			regs1.putBytes(snap, reg("RSP"),
				buf.clear().putLong(STACK1_BOTTOM + stack1offset).flip());
			regs1.putBytes(snap, reg("RAX"), buf.clear().putLong(0).flip());
			memory.putBytes(snap, addr(STACK1_BOTTOM + stack1offset),
				buf.clear().putLong(mainInstructions.get(++pc1).getAddress().getOffset()).flip());

			stack2offset -= 8;
			regs2.putBytes(snap, reg("RIP"),
				buf.clear().putLong(cloneLabel.getAddress().getOffset()).flip());
			regs2.putBytes(snap, reg("RSP"),
				buf.clear().putLong(STACK2_BOTTOM + stack2offset).flip());
			regs2.putBytes(snap, reg("RAX"), buf.clear().putLong(1).flip());
			memory.putBytes(snap, addr(STACK2_BOTTOM + stack2offset), buf.clear()
					.putLong(
						mainInstructions.get(pc2 = pc1).getAddress().getOffset())
					.flip());

			placeRegUnits(snap, thread1);
			placeRegUnits(snap, thread2);
		}

		/**
		 * Hand emulate thread1 a few steps
		 */
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 1: RET from clone").getKey();

			stack1offset += 8;
			putRIP(snap, regs1, mainInstructions.get(pc1));
			regs1.putBytes(snap, reg("RSP"),
				buf.clear().putLong(STACK1_BOTTOM + stack1offset).flip());

			placeRegUnits(snap, thread1);
		}

		/**
		 * ...
		 */
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 1: TEST EAX,EAX").getKey();

			putRIP(snap, regs1, mainInstructions.get(++pc1));
			regs1.putBytes(snap, reg("ZF"), buf.clear().put((byte) 1).flip());

			placeRegUnits(snap, thread1);
		}

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 1: JNZ child").getKey();

			putRIP(snap, regs1, mainInstructions.get(++pc1));

			placeRegUnits(snap, thread1);
		}

		/**
		 * Switch to thread2
		 */
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 2: RET from clone").getKey();

			stack2offset += 8;
			putRIP(snap, regs2, mainInstructions.get(pc2));
			regs2.putBytes(snap, reg("RSP"),
				buf.clear().putLong(STACK2_BOTTOM + stack2offset).flip());

			placeRegUnits(snap, thread2);
		}

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 2: TEST EAX,EAX").getKey();

			putRIP(snap, regs2, mainInstructions.get(++pc2));
			regs2.putBytes(snap, reg("ZF"), buf.clear().put((byte) 0).flip());

			placeRegUnits(snap, thread2);
		}

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 2: JNZ child").getKey();

			putRIP(snap, regs2, mainInstructions.get(pc2 = 11));

			placeRegUnits(snap, thread2);
		}

		/**
		 * Switch to thread1
		 */
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 1: SUB RSP,0x10").getKey();

			stack1offset -= 0x10;
			putRIP(snap, regs1, mainInstructions.get(++pc1));
			regs1.putBytes(snap, reg("RSP"),
				buf.clear().putLong(STACK1_BOTTOM + stack1offset).flip());

			placeRegUnits(snap, thread1);
		}

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 1: MOV...(1)").getKey();

			putRIP(snap, regs1, mainInstructions.get(++pc1));
			memory.putBytes(snap, addr(STACK1_BOTTOM + stack1offset + 0),
				buf.clear().putInt(0x6c6c6548).flip());

			placeRegUnits(snap, thread1);
		}

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 1: MOV...(2)").getKey();

			putRIP(snap, regs1, mainInstructions.get(++pc1));
			memory.putBytes(snap, addr(STACK1_BOTTOM + stack1offset + 4),
				buf.clear().putInt(0x57202c6f).flip());

			placeRegUnits(snap, thread1);
		}

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 1: MOV...(3)").getKey();

			putRIP(snap, regs1, mainInstructions.get(++pc1));
			memory.putBytes(snap, addr(STACK1_BOTTOM + stack1offset + 8),
				buf.clear().putInt(0x646c726f).flip());

			placeRegUnits(snap, thread1);
		}

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 1: MOV...(4)").getKey();

			putRIP(snap, regs1, mainInstructions.get(++pc1));
			memory.putBytes(snap, addr(STACK1_BOTTOM + stack1offset + 0xc),
				buf.clear().putShort((short) 0x21).flip());

			placeRegUnits(snap, thread1);
		}

		/**
		 * Switch to thread2
		 */
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 2: SUB RSP,0x10").getKey();

			stack2offset -= 0x10;
			putRIP(snap, regs2, mainInstructions.get(++pc2));
			regs2.putBytes(snap, reg("RSP"),
				buf.clear().putLong(STACK2_BOTTOM + stack2offset).flip());

			placeRegUnits(snap, thread2);
		}

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 2: MOV...(1)").getKey();

			putRIP(snap, regs2, mainInstructions.get(++pc2));
			memory.putBytes(snap, addr(STACK2_BOTTOM + stack2offset + 0),
				buf.clear().putInt(0x2c657942).flip());

			placeRegUnits(snap, thread2);
		}

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 2: MOV...(2)").getKey();

			putRIP(snap, regs2, mainInstructions.get(++pc2));
			memory.putBytes(snap, addr(STACK2_BOTTOM + stack2offset + 4),
				buf.clear().putInt(0x726f5720).flip());

			placeRegUnits(snap, thread2);
		}

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 2: MOV...(3)").getKey();

			putRIP(snap, regs2, mainInstructions.get(++pc2));
			memory.putBytes(snap, addr(STACK2_BOTTOM + stack2offset + 8),
				buf.clear().putInt(0x21646c).flip());

			placeRegUnits(snap, thread2);
		}

		/**
		 * Let thread2 exit first
		 */
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 2: CALL exit").getKey();

			thread2.setDestructionSnap(snap);
		}

		/**
		 * Terminate
		 */
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			long snap =
				trace.getTimeManager().createSnapshot("Stepped Thread 1: CALL exit").getKey();

			thread1.setDestructionSnap(snap);
		}

		/**
		 * Give a program view to Ghidra's program manager
		 * 
		 * NOTE: Eventually, there will probably be a TraceManager service as well, but to use the
		 * familiar UI components, we generally take orders from the ProgramManager.
		 */
		DebuggerTraceManagerService manager =
			state.getTool().getService(DebuggerTraceManagerService.class);
		manager.openTrace(trace);
		manager.activateTrace(trace);
	}
}
