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
package ghidra.pcode.emu.sys;

import static ghidra.pcode.emu.sys.EmuSyscallLibrary.*;
import static org.junit.Assert.*;

import org.junit.*;

import db.Transaction;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.*;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.SpaceNames;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class EmuAmd64SyscallUseropLibraryTest extends AbstractGhidraHeadlessIntegrationTest {

	/**
	 * A library with two 4-argument syscalls.
	 * 
	 * <p>
	 * For x86:LE:64:default:gcc, the storage for the 4th argument varies by calling convention. For
	 * __stdcall, it's RCX. For syscall, it's R10. Both syscalls just return the 4th argument. Thus,
	 * it's possible to detect whether the emulator heeds conventions by binding each to a different
	 * convention, then invoking them with distinct values placed in RCX and R10 and verifying that
	 * the correct value shows in RAX, the return register.
	 */
	protected final class SyscallTestUseropLibrary
			extends AnnotatedEmuSyscallUseropLibrary<byte[]> {
		protected final Register regRAX;

		public SyscallTestUseropLibrary(PcodeMachine<byte[]> machine, Program program) {
			super(machine, program);
			regRAX = machine.getLanguage().getRegister("RAX");
		}

		@Override
		public long readSyscallNumber(PcodeExecutorState<byte[]> state, Reason reason) {
			return machine.getArithmetic().toLong(state.getVar(regRAX, reason), Purpose.OTHER);
		}

		@PcodeUserop
		@EmuSyscall("syscall0")
		public byte[] test_syscall0(byte[] arg0, byte[] arg1, byte[] arg2, byte[] arg3) {
			return arg3;
		}

		@PcodeUserop
		@EmuSyscall("syscall1")
		public byte[] test_syscall1(byte[] arg0, byte[] arg1, byte[] arg2, byte[] arg3) {
			return arg3;
		}

		@Override
		public boolean handleError(PcodeExecutor<byte[]> executor, PcodeExecutionException err) {
			return false;
		}
	}

	protected final class SyscallTestPcodeEmulator extends PcodeEmulator {
		protected SyscallTestUseropLibrary syscalls;

		public SyscallTestPcodeEmulator() {
			super(program.getLanguage());
		}

		@Override
		protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
			syscalls = new SyscallTestUseropLibrary(this, program);
			return syscalls;
		}
	}

	Program program;
	SleighLanguage language;
	Assembler asm;

	Register regRAX;
	AddressSpace space;
	Address start;
	int size;
	MemoryBlock block;
	PcodeArithmetic<byte[]> arithmetic;

	protected void placeSyscall(long number, String name, String convention) throws Exception {
		AddressSpace spaceSyscall = program.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME);
		FunctionManager functions = program.getFunctionManager();

		Address addr = spaceSyscall.getAddress(number);
		functions.createFunction(name, addr, new AddressSet(addr), SourceType.USER_DEFINED)
				.setCallingConvention(convention);
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram("HelloSyscalls", "x86:LE:64:default", "gcc", this);
		language = (SleighLanguage) program.getLanguage();
		arithmetic = BytesPcodeArithmetic.forLanguage(language);

		regRAX = program.getRegister("RAX");
		space = program.getAddressFactory().getDefaultAddressSpace();
		start = space.getAddress(0x00400000);
		size = 0x1000;

		try (Transaction tx = program.openTransaction("Initialize")) {
			block = program.getMemory()
					.createInitializedBlock(".text", start, size, (byte) 0, TaskMonitor.DUMMY,
						false);

			// Fulfill requirements for the syscall userop library:
			// 1) The "/pointer" data type exists, so it knows the machine word size
			program.getDataTypeManager()
					.resolve(PointerDataType.dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
			// 2) Create the syscall space and add those we'll be using
			Address startOther = program.getAddressFactory()
					.getAddressSpace(SpaceNames.OTHER_SPACE_NAME)
					.getAddress(0);
			MemoryBlock blockSyscall = program.getMemory()
					.createUninitializedBlock(SYSCALL_SPACE_NAME, startOther, 0x10000, true);
			blockSyscall.setPermissions(true, false, true);

			placeSyscall(0, "syscall0", "__stdcall");
			placeSyscall(1, "syscall1", "syscall");

			asm = Assemblers.getAssembler(program);
		}
	}

	@After
	public void tearDown() {
		if (program != null) {
			program.release(this);
		}
	}

	public SyscallTestPcodeEmulator prepareEmulator() throws Exception {
		SyscallTestPcodeEmulator emu = new SyscallTestPcodeEmulator();
		byte[] buf = new byte[size];
		assertEquals(size, block.getBytes(start, buf));
		emu.getSharedState().setVar(space, start.getOffset(), size, true, buf);
		return emu;
	}

	public PcodeThread<byte[]> launchThread(PcodeEmulator emu, Address pc) {
		PcodeThread<byte[]> thread = emu.newThread();
		thread.overrideCounter(start);
		thread.overrideContextWithDefault();
		thread.reInitialize();
		return thread;
	}

	@Test
	public void testSyscallWithStdcallConvention() throws Exception {
		try (Transaction tx = program.openTransaction("Initialize")) {
			asm.assemble(start,
				"MOV RAX,0",
				"MOV RCX,0xbeef",
				"MOV R10,0xdead",
				"SYSCALL");
		}

		SyscallTestPcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);

		thread.stepInstruction(4);

		assertArrayEquals(arithmetic.fromConst(0xbeef, regRAX.getNumBytes()),
			thread.getState().getVar(regRAX, Reason.INSPECT));
	}

	@Test
	public void testSyscallWithSyscallConvention() throws Exception {
		try (Transaction tx = program.openTransaction("Initialize")) {
			asm.assemble(start,
				"MOV RAX,1",
				"MOV RCX,0xdead",
				"MOV R10,0xbeef",
				"SYSCALL");
		}

		SyscallTestPcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);

		thread.stepInstruction(4);

		assertArrayEquals(arithmetic.fromConst(0xbeef, regRAX.getNumBytes()),
			thread.getState().getVar(regRAX, Reason.INSPECT));
	}
}
