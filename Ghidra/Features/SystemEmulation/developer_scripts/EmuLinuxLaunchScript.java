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
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.List;
import java.util.Objects;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.*;
import ghidra.pcode.emu.elf.ElfHeaderReader;
import ghidra.pcode.emu.linux.LinuxStackInitializer;
import ghidra.pcode.emu.linux.LinuxUserspaceEmulatorFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;

public class EmuLinuxLaunchScript extends GhidraScript {
	public static final int STACK_SIZE = 0x22000;
	public static final int ARGC_OFFSET = 0x20000;
	public static final long ASLR_MASK = 0x0000_7fff_ffff_f000L;

	public static final List<String> ARGV = List.of("/tmp/termmines");
	public static final List<String> ENV = List.of(
		"HOME=/home/user");

	Program findProgram(String path) {
		// LATER: Search the project? Or just open programs
		ProgramManager progMan = state.getTool().getService(ProgramManager.class);
		for (Program program : progMan.getAllOpenPrograms()) {
			if (Objects.equals(path, program.getExecutablePath())) {
				return program;
			}
		}
		return null;
	}

	@Override
	protected void run() throws Exception {
		DebuggerTraceManagerService traceManager =
			state.getTool().getService(DebuggerTraceManagerService.class);
		SecureRandom random = new SecureRandom();

		ElfHeaderReader elfReader = new ElfHeaderReader(currentProgram);
		String interpPath = elfReader.getInterpreter();

		Address entry;
		Address interpDynBase;
		Program interpreter;
		if (interpPath == null) {
			interpreter = null;
			interpDynBase = null;
			entry = elfReader.getNominalEntry().add(elfReader.getLoadedImageShift());
		}
		else {
			interpreter = findProgram(interpPath);
			if (interpreter == null) {
				printerr("Could not find interpreter: %s".formatted(interpPath));
				return;
			}
			ElfHeaderReader elfReaderInterp = new ElfHeaderReader(interpreter);
			// Pick a random 47-bit block-aligned address for the interpreter (ld-linux, probably)
			interpDynBase = interpreter.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(random.nextLong() & ASLR_MASK);
			Address interpBase = elfReaderInterp.getNominalImageBase();
			entry = interpDynBase.add(elfReaderInterp.getNominalEntry().subtract(interpBase));
		}

		try (ManagedDomainObject<Trace> mdo = new ManagedDomainObject<Trace>(
			c -> ProgramEmulationUtils.launchEmulationTrace(currentProgram, entry, STACK_SIZE, c));
				Transaction _ = mdo.get().openTransaction("Write auxv")) {

			Trace trace = mdo.get();
			TraceSnapshot init = trace.getTimeManager().getSnapshot(0, true);

			if (interpreter != null) {
				ProgramEmulationUtils.loadExecutable(init, interpreter, interpDynBase, List.of());
			}

			TraceThread thread = trace.getThreadManager().getAllThreads().iterator().next();

			TraceMemorySpace regs = trace.getMemoryManager().getMemoryRegisterSpace(thread, false);
			CompilerSpec cSpec = trace.getBaseCompilerSpec();
			Register sp = cSpec.getStackPointer();
			Address stackBase = cSpec.getStackBaseSpace()
					.getAddress(regs.getValue(0, sp).getUnsignedValue().longValue());
			long maxInitSize = STACK_SIZE - ARGC_OFFSET;
			Address argcBase = stackBase.subtract(maxInitSize);

			LinuxStackInitializer stackInit =
				new LinuxStackInitializer(trace.getBaseLanguage(), Charset.forName("utf8"), random);

			stackInit.program(currentProgram, null);
			stackInit.arg(currentProgram.getExecutablePath());
			stackInit.env("HOME", "/home/user");

			ByteBuffer stackBuf = ByteBuffer.allocate(STACK_SIZE);
			stackInit.encode(argcBase.getOffset(), stackBuf);
			trace.getMemoryManager().putBytes(0, argcBase, stackBuf.flip());
			regs.setValue(0, new RegisterValue(sp, argcBase.getOffsetAsBigInteger()));

			traceManager.openTrace(trace);
		}

		state.getTool()
				.getService(DebuggerEmulationService.class)
				.setEmulatorFactory(LinuxUserspaceEmulatorFactory.TITLE);
	}
}
