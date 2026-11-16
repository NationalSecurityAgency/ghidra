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
package ghidra.pcode.emu.linux;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.Cleaner;
import java.lang.ref.Cleaner.Cleanable;
import java.nio.charset.Charset;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.*;

import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingContext;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.services.*;
import ghidra.app.services.TerminalService.TerminalGivingStreams;
import ghidra.debug.api.emulation.EmulatorFactory;
import ghidra.debug.api.emulation.PcodeDebuggerAccess;
import ghidra.debug.api.modules.DebuggerAddressTranslator;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.pcode.emu.*;
import ghidra.pcode.emu.unix.*;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.Writer;
import ghidra.pcode.exec.trace.data.PcodeTraceAccess;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.util.Msg;

public class LinuxUserspaceEmulatorFactory implements EmulatorFactory {
	public static final String TITLE = "Linux Userspace Concrete P-code Emulator (INCOMPLETE)";

	@Override
	public String getTitle() {
		return TITLE;
	}

	public static DebuggerAddressTranslator getTranslator(ServiceProvider serviceProvider,
			Trace trace) {
		DebuggerTraceManagerService traceManager =
			serviceProvider.getService(DebuggerTraceManagerService.class);
		if (traceManager.getOpenTraces().contains(trace)) {
			DebuggerStaticMappingService service =
				serviceProvider.getService(DebuggerStaticMappingService.class);
			if (service != null) {
				return service;
			}
		}
		DebuggerStaticMappingContext ctx = new DebuggerStaticMappingContext();
		ProgramManager programManager = serviceProvider.getService(ProgramManager.class);
		try (var cc = ctx.collectChanges()) {
			ctx.addTrace(cc, trace);
			for (var program : programManager.getAllOpenPrograms()) {
				ctx.addProgram(cc, program);
			}
		}
		return ctx;
	}

	public static void populateFileSystem(EmuUnixFileSystem<byte[]> fs,
			ServiceProvider serviceProvider) {
		ProgramManager programManager = serviceProvider.getService(ProgramManager.class);
		if (programManager == null) {
			return;
		}
		List<Program> programs = List.of(programManager.getAllOpenPrograms());
		for (Program p : programs) {
			String exePath = p.getExecutablePath();
			if (exePath == null) {
				continue;
			}
			Path ep = Path.of(exePath);
			/**
			 * LATER: Can we have some kind of file system that ignores paths up to a file and just
			 * matches on the final file name? Is that even a good idea?
			 */
			for (FileBytes fileBytes : p.getMemory().getAllFileBytes()) {
				String filename = fileBytes.getFilename();
				if (filename == null) {
					continue;
				}
				Path path;
				try {
					path = Path.of(filename);
				}
				catch (InvalidPathException e) {
					continue;
				}

				String pathname;
				if (path.isAbsolute()) {
					pathname = path.toString();
				}
				else if (ep.isAbsolute() && ep.endsWith(path)) {
					pathname = ep.toString();
				}
				else {
					continue;
				}
				fs.putFile(pathname, new FileBytesEmuUnixFile(pathname, 0x4, fileBytes));
			}
		}
	}

	public static LinuxUserspacePcodeEmulator create(ServiceProvider serviceProvider,
			PcodeTraceAccess access, PcodeEmulationCallbacks<byte[]> cb) {
		Trace trace = access.getPlatform().getTrace();
		DebuggerAddressTranslator translator = getTranslator(serviceProvider, trace);
		TerminalService terminalService = Objects.requireNonNull(
			serviceProvider.getService(TerminalService.class),
			"No TerminalService");

		long snap = access.getThreadsSnap();
		Set<Program> programs = translator.getOpenMappedProgramsAtSnap(trace, 0);
		if (programs == null || programs.isEmpty()) {
			throw new IllegalStateException("No target program mapped into the trace at snap 0");
		}
		if (programs.size() > 1) {
			Msg.warn(LinuxUserspaceEmulatorFactory.class,
				"Multiple programs mapping into the trace at snap 0. Picking arbitrarily");
		}
		Program program = programs.iterator().next();
		EmuUnixUser user = EmuUnixUser.DEFAULT_USER;

		// TODO: What to put in this filesystem?
		EmuUnixFileSystem<byte[]> fs = new BytesEmuUnixFileSystem();
		// LATER: I'll start with open programs, at their executable paths. Should be configurable

		populateFileSystem(fs, serviceProvider);

		TerminalGivingStreams termAndIo =
			terminalService.createGivingStreams(Charset.forName("utf8"));

		return new LinuxUserspacePcodeEmulator(access.getLanguage(), cb, termAndIo.terminal(),
			termAndIo.in(), termAndIo.out(), program, fs, user, trace, snap);
	}

	@Override
	public PcodeMachine<?> create(ServiceProvider serviceProvider, PcodeDebuggerAccess access,
			Writer writer) {
		return create(serviceProvider, access, writer.callbacks());
	}

	@Override
	public PcodeMachine<?> create(PcodeDebuggerAccess access, Writer writer) {
		throw new AssertionError("This method is deprecated");
	}

	public static class LinuxUserspacePcodeEmulator extends PcodeEmulator {
		private static final Cleaner CLEANER = Cleaner.create();

		static class State implements Runnable {
			private final Terminal terminal;

			public State(Terminal terminal) {
				this.terminal = terminal;
			}

			@Override
			public void run() {
				terminal.terminated(-1);
				// TODO: Also on exit_group
			}
		}

		private final State state;
		@SuppressWarnings("unused")
		private final Cleanable cleanable;

		private final InputStream in;
		private final OutputStream out;
		private final OutputStream err;
		protected final Program program;
		private final EmuUnixFileSystem<byte[]> fs;
		protected final EmuUnixUser user;
		/**
		 * LATER: More generic memory protection, incl. compatible with JIT
		 */
		private final Trace trace;
		private final long snap;

		public LinuxUserspacePcodeEmulator(Language language, PcodeEmulationCallbacks<byte[]> cb,
				Terminal terminal, InputStream in, OutputStream out, Program program,
				EmuUnixFileSystem<byte[]> fs, EmuUnixUser user, Trace trace, long snap) {
			this(language, cb, terminal, in, out, out, program, fs, user, trace, snap);
		}

		public LinuxUserspacePcodeEmulator(Language language, PcodeEmulationCallbacks<byte[]> cb,
				Terminal terminal, InputStream in, OutputStream out, OutputStream err,
				Program program, EmuUnixFileSystem<byte[]> fs, EmuUnixUser user, Trace trace,
				long snap) {
			// TODO: Somewhere in here, we need to simulate the Linux pty thing.
			// Namely the translation of newlines
			// Probably also the translation of Ctrl-C
			this.state = terminal == null ? null : new State(terminal);
			this.in = in;
			this.out = out;
			this.err = err;
			this.program = program;
			this.fs = fs;
			this.user = user;
			this.trace = trace;
			this.snap = snap;
			super(language, cb);
			this.cleanable = state == null ? null : CLEANER.register(this, state);
		}

		protected AbstractEmuLinuxSyscallUseropLibrary<byte[]> createSyscallLibrary() {
			return switch (language.getLanguageID().getIdAsString()) {
				case "x86:LE:64:default" -> new EmuLinuxAmd64SyscallUseropLibrary<>(
					this, fs, program, user);
				case "x86:LE:32:default" -> new EmuLinuxX86SyscallUseropLibrary<>(
					this, fs, program, user);
				default -> throw new UnsupportedOperationException(
					"Linux userspace emulation only supports x86 32- and 64-bit currently");
			};
		}

		@Override
		protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
			/**
			 * TODO: Use the same discovery mechanism as we do for language. Trouble is I need to be
			 * able to pass in specific parameters, i.e., the filesystem and user, not to mention
			 * adding the tty file descriptors.
			 */
			AbstractEmuLinuxSyscallUseropLibrary<byte[]> syscalls = createSyscallLibrary();
			CompilerSpec cSpec = program.getCompilerSpec();
			IOStreamEmuUnixFileHandle stdin =
				new IOStreamEmuUnixFileHandle(this, cSpec, in, null);
			IOStreamEmuUnixFileHandle stdout =
				new IOStreamEmuUnixFileHandle(this, cSpec, null, out);
			IOStreamEmuUnixFileHandle stderr =
				new IOStreamEmuUnixFileHandle(this, cSpec, null, err);
			syscalls.putDescriptor(EmuUnixFileDescriptor.FD_STDIN, stdin);
			syscalls.putDescriptor(EmuUnixFileDescriptor.FD_STDOUT, stdout);
			syscalls.putDescriptor(EmuUnixFileDescriptor.FD_STDERR, stderr);

			for (TraceMemoryRegion region : trace.getMemoryManager().getRegionsAtSnap(snap)) {
				Address min = region.getMinAddress(snap);
				if (min.getAddressSpace() != language.getDefaultDataSpace()) {
					continue;
				}
				syscalls.putClaimedMemory(min.getOffset(), region.getMaxAddress(snap).getOffset());
			}

			return super.createUseropLibrary().compose(syscalls);
		}

		TraceMemoryRegion getRegion(Address start, int size) {
			TraceMemoryRegion regionStart = trace.getMemoryManager()
					.getRegionContaining(snap, start);
			TraceMemoryRegion regionEnd = trace.getMemoryManager()
					.getRegionContaining(snap, start.add(size - 1));
			if (regionStart != regionEnd) {
				throw new SegfaultPcodeExecutionException(start, size,
					"Access to %s spans segments".formatted(start));
			}
			if (regionStart == null) {
				throw new SegfaultPcodeExecutionException(start, size,
					"No segment at %s".formatted(start));
			}
			return regionStart;
		}

		@Override
		protected PcodeExecutorState<byte[]> createLocalState(PcodeThread<byte[]> thread) {
			PcodeExecutorState<byte[]> state = super.createLocalState(thread);
			SleighLanguage language = thread.getLanguage();
			switch (language.getProcessor().toString()) {
				case "x86" -> {
					Register regXCR0 = language.getRegister("XCR0");
					byte[] initXCR0 = arithmetic.fromConst(0x2e7, regXCR0.getNumBytes());
					state.setVar(regXCR0, initXCR0);
				}
			}
			return state;
		}

		public Terminal getTerminal() {
			return state == null ? null : state.terminal;
		}
	}
}
