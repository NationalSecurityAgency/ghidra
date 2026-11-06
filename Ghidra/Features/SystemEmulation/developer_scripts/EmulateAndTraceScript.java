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
//A script to create a trace via emulation with Linux-userspace

//@author 
//@category Tracing
//@keybinding
//@menupath
//@toolbar video-x-generic16.png

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationIntegration;
import ghidra.app.plugin.core.debug.service.emulation.data.DefaultPcodeDebuggerAccess;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.TerminalService;
import ghidra.app.services.TerminalService.TerminalGivingStreams;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.debug.flatapi.FlatDebuggerAPI;
import ghidra.pcode.emu.*;
import ghidra.pcode.emu.linux.*;
import ghidra.pcode.emu.linux.LinuxUserspaceEmulatorFactory.LinuxUserspacePcodeEmulator;
import ghidra.pcode.emu.sys.EmuProcessExitedException;
import ghidra.pcode.emu.unix.*;
import ghidra.pcode.emu.unix.FileBytesEmuUnixFile.FileBytesEmuFileContents;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.Writer;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.*;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceStaticMapping;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.symbol.TraceReferenceManager;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;

public class EmulateAndTraceScript extends GhidraScript implements FlatDebuggerAPI {
	static final int CHUNK_SIZE = 4096;

	Address xferAddress(Address saddr, Trace dtrace) {
		AddressSpace sspace = saddr.getAddressSpace();
		if (sspace.getPhysicalSpace() == sspace) {
			return saddr;
		}
		return dtrace.getBaseAddressFactory()
				.getAddressSpace(sspace.getName())
				.getAddress(saddr.getOffset());
	}

	AddressRange xferRange(AddressRange srange, Trace dtrace) {
		AddressSpace sspace = srange.getAddressSpace();
		if (sspace.getPhysicalSpace() == sspace) {
			return srange;
		}
		AddressSpace dspace = dtrace.getBaseAddressFactory().getAddressSpace(sspace.getName());
		return new AddressRangeImpl(
			dspace.getAddress(srange.getMinAddress().getOffset()),
			dspace.getAddress(srange.getMaxAddress().getOffset()));
	}

	void copyObjects(TraceObject src, TraceObject dst, Lifespan slife, Lifespan dlife) {
		for (TraceObjectValue sv : src.getValues(slife)) {
			String keyPc = src.getSchema().checkAliasedAttribute(TraceStackFrame.KEY_PC);
			if (sv.getEntryKey().equals(keyPc)) {
				if (src.getInterfaces().contains(TraceStackFrame.class)) {
					continue;
				}
			}
			Object dvv = switch (sv.getValue()) {
				case TraceObject sobj -> dst.getTrace()
						.getObjectManager()
						.createObject(sobj.getCanonicalPath());
				default -> sv.getValue();
			};
			TraceObjectValue dv = dst.setValue(dlife, sv.getEntryKey(), dvv);
			if (dv.isCanonical()) {
				copyObjects(sv.getChild(), dv.getChild(), slife, dlife);
			}
		}
	}

	@Override
	protected void run() throws Exception {
		DebuggerCoordinates source = getCurrentDebuggerCoordinates();
		Trace strace = source.getTrace();
		long ssnap = source.getSnap();
		TraceMemoryManager smem = strace.getMemoryManager();

		final Trace dtrace;
		final long dsnap = 0;
		final TraceMemoryManager dmem;
		try (var mdo = new ManagedDomainObject<Trace>(c -> new DBTrace(
			"emu_%s".formatted(strace.getName()), strace.getBaseCompilerSpec(), c));
				var _ = mdo.get().openTransaction("Copy initial snap")) {
			dtrace = mdo.get();
			dmem = dtrace.getMemoryManager();

			dtrace.getObjectManager().createRootObject(strace.getObjectManager().getRootSchema());

			copyObjects(strace.getObjectManager().getRootObject(),
				dtrace.getObjectManager().getRootObject(),
				Lifespan.at(ssnap), Lifespan.nowOn(dsnap));

			AddressSet toCopy = new AddressSet();
			Set<AddressSpace> toCreate = new LinkedHashSet<>();
			for (AddressSpace space : strace.getBaseAddressFactory().getAllAddressSpaces()) {
				if (!(space.getPhysicalSpace().isMemorySpace() ||
					space.getPhysicalSpace().isRegisterSpace())) {
					continue;
				}
				if (space.isOverlaySpace()) {
					toCreate.add(space);
				}
				AddressRange range =
					new AddressRangeImpl(space.getMinAddress(), space.getMaxAddress());
				for (Entry<TraceAddressSnapRange, TraceMemoryState> entry : smem
						.getStates(Lifespan.since(ssnap), range)) {
					if (entry.getValue() == TraceMemoryState.KNOWN) {
						toCopy.add(entry.getKey().getRange());
					}
				}
			}

			for (AddressSpace sspace : toCreate) {
				dmem.getOrCreateOverlayAddressSpace(sspace.getName(), sspace.getPhysicalSpace());
			}

			for (TraceMemoryRegion sreg : smem.getRegionsAtSnap(ssnap)) {
				dmem.createRegion(sreg.getPath(), dsnap, xferRange(sreg.getRange(ssnap), dtrace),
					sreg.getFlags(ssnap));
			}

			for (TraceStaticMapping smap : strace.getStaticMappingManager().getAllEntries()) {
				if (!smap.getLifespan().contains(ssnap)) {
					continue;
				}
				dtrace.getStaticMappingManager()
						.add(xferRange(smap.getTraceAddressRange(), dtrace), Lifespan.nowOn(0),
							smap.getStaticProgramURL(), smap.getStaticAddress());
			}

			for (AddressRange range : toCopy) {
				ByteBuffer buf = ByteBuffer.allocate(CHUNK_SIZE);
				for (AddressRange chunk : new AddressRangeChunker(range, CHUNK_SIZE)) {
					buf.clear();
					buf.limit((int) chunk.getLength());
					int slen = smem.getBytes(ssnap, chunk.getMinAddress(), buf);
					if (slen < chunk.getLength()) {
						printerr(
							"Incomplete copy of %s. Read %d of %d bytes.".formatted(chunk, slen,
								chunk.getLength()));
					}
					buf.flip();
					int dlen =
						dmem.putBytes(dsnap, xferAddress(chunk.getMinAddress(), dtrace), buf);
					if (dlen < slen) {
						printerr("Incomplete copy of %s. Wrote %d of %d bytes.".formatted(chunk,
							dlen, slen));
					}
				}
			}

			for (TraceThread thread : dtrace.getThreadManager().getAllThreads()) {
				TraceMemorySpace regs =
					dtrace.getMemoryManager().getMemoryRegisterSpace(thread, false);
				if (regs == null) {
					continue;
				}
				// This assumes x86, but so does the Linux userop library
				Register regSSP = dtrace.getBaseLanguage().getRegister("SSP");
				Register regDF = dtrace.getBaseLanguage().getRegister("DF");
				regs.setValue(dsnap, new RegisterValue(regSSP, BigInteger.ZERO));
				regs.setValue(dsnap, new RegisterValue(regDF, BigInteger.ZERO));
			}

			// Hand off to trace manager before closing
			openTrace(dtrace);
		}

		TracePlatform dplatform = dtrace.getPlatformManager().getHostPlatform();
		TraceReferenceManager refman = dtrace.getReferenceManager();
		DefaultPcodeDebuggerAccess acc =
			new DefaultPcodeDebuggerAccess(state.getTool(), null, dplatform, dsnap);
		Writer writer = DebuggerEmulationIntegration.bytesDelayedWriteTrace(acc);
		var refsCb = new PcodeEmulationCallbacks<byte[]>() {
			boolean enabled = false;
			long cursnap = dsnap;
			AddressSet written = new AddressSet();
			TraceSnapshot snapshot;
			Address pc;
			int opIndex = 0;

			@Override
			public void beforeStepOp(PcodeThread<byte[]> thread, PcodeOp op, PcodeFrame frame) {
				if (monitor.isCancelled()) {
					throw new PcodeExecutionException("Cancelled");
				}
			}

			@Override
			public void beforeExecuteInject(PcodeThread<byte[]> thread, Address address,
					PcodeProgram program) {
				if (!enabled) {
					return;
				}
				snapshot = dtrace.getTimeManager().getSnapshot(cursnap, true);
				if (snapshot.getDescription().isBlank()) {
					snapshot.setDescription("Step (Inject)");
				}
				TraceThread t =
					dtrace.getThreadManager().getLiveThreadByPath(dsnap, thread.getName());
				snapshot.setEventThread(t);
				pc = address;
				TraceStack stack = dtrace.getStackManager().getLatestStack(t, cursnap);
				TraceStackFrame frame = stack.getFrame(cursnap, 0, true);
				frame.setProgramCounter(Lifespan.at(cursnap), pc);
			}

			@Override
			public void beforeExecuteInstruction(PcodeThread<byte[]> thread,
					Instruction instruction, PcodeProgram program) {
				if (!enabled) {
					return;
				}
				snapshot = dtrace.getTimeManager().getSnapshot(cursnap, true);
				if (snapshot.getDescription().isBlank()) {
					snapshot.setDescription("Step");
				}
				TraceThread t =
					dtrace.getThreadManager().getLiveThreadByPath(dsnap, thread.getName());
				snapshot.setEventThread(t);
				pc = instruction.getAddress();
				TraceStack stack = dtrace.getStackManager().getLatestStack(t, cursnap);
				TraceStackFrame frame = stack.getFrame(cursnap, 0, true);
				frame.setProgramCounter(Lifespan.at(cursnap), pc);
			}

			@Override
			public void afterExecuteInstruction(PcodeThread<byte[]> thread,
					Instruction instruction) {
				if (!enabled) {
					return;
				}
				if (snapshot.getKey() == cursnap) {
					cursnap++;
					written.clear();
					opIndex = 0;
					monitor.setMessage("%d Snaps".formatted(cursnap));
				}
			}

			@Override
			public void afterExecuteInject(PcodeThread<byte[]> thread, Address address) {
				if (!enabled) {
					return;
				}
				if (snapshot.getKey() == cursnap) {
					cursnap++;
					written.clear();
					opIndex = 0;
					monitor.setMessage("%d Snaps".formatted(cursnap));
				}
			}

			@SuppressWarnings("unused")
			private String display(AddressRange range) {
				Address min = range.getMinAddress().getPhysicalAddress();
				int len = (int) range.getLength();
				Register register = dplatform.getLanguage().getRegister(min, len);
				if (register != null) {
					return register.getName();
				}
				return "%s:%08x-%08x".formatted(min.getAddressSpace(), min.getOffset(),
					min.getOffset() + len - 1);
			}

			@Override
			public <A, U> void dataRead(PcodeThread<byte[]> thread,
					PcodeExecutorStatePiece<A, U> piece, Address address, int length, U value,
					Reason reason) {
				if (!enabled) {
					return;
				}
				if (address.isUniqueAddress()) {
					return;
				}
				if (reason != Reason.EXECUTE_READ) {
					return;
				}
				TraceThread t = snapshot.getEventThread();
				TraceMemorySpace mem = address.isRegisterAddress()
						? dmem.getMemoryRegisterSpace(t, true)
						: dmem.getMemorySpace(address.getAddressSpace(), true);

				Address overlay = mem.getAddressSpace().getOverlayAddress(address);
				AddressSet set = new AddressSet(overlay, overlay.add(length - 1));
				set.delete(written);

				for (AddressRange rng : set) {
					if (value instanceof byte[] v) {
						Address min = rng.getMinAddress();
						int offset = (int) min.subtract(overlay);
						int len = (int) rng.getLength();
						mem.putBytes(cursnap, min, ByteBuffer.wrap(v, offset, len));
					}
					refman.addMemoryReference(Lifespan.at(cursnap), pc, rng, RefType.READ,
						SourceType.IMPORTED, opIndex);
					opIndex++;
				}
			}

			@Override
			public <A, U> void dataWritten(PcodeThread<byte[]> thread,
					PcodeExecutorStatePiece<A, U> piece, Address address, int length, U value) {
				if (!enabled) {
					return;
				}
				if (address.isUniqueAddress()) {
					return;
				}
				TraceThread t = snapshot.getEventThread();
				TraceMemorySpace mem = address.isRegisterAddress()
						? dmem.getMemoryRegisterSpace(t, true)
						: dmem.getMemorySpace(address.getAddressSpace(), true);

				Address overlay = mem.getAddressSpace().getOverlayAddress(address);
				AddressRangeImpl range = new AddressRangeImpl(overlay, overlay.add(length - 1));

				written.add(range);

				if (value instanceof byte[] v) {
					mem.putBytes(cursnap + 1, overlay, ByteBuffer.wrap(v));
				}

				for (Register reg : piece.getLanguage()
						.getRegisters(address.getPhysicalAddress())) {
					if (reg.isProgramCounter() || reg.isProcessorContext()) {
						return;
					}
				}
				refman.addMemoryReference(Lifespan.at(cursnap), pc, range, RefType.WRITE,
					SourceType.IMPORTED, opIndex);
				opIndex++;
			}

			public void addMappingFromRead(EmuUnixFileDescriptor<byte[]> fd, Address start,
					int len, long offset) {
				if (!(fd instanceof AbstractEmuUnixFileHandle<byte[]> handle)) {
					return;
				}
				if (!(handle.getFile()
						.getContents() instanceof FileBytesEmuFileContents contents)) {
					return;
				}

				FileBytes fb = contents.getFileBytes();
				ProgramLocation stLoc = locateFileBytes(fb, offset, len);
				if (stLoc == null) {
					return;
				}
				DebuggerStaticMappingUtils.addMapping(
					new DefaultTraceLocation(dtrace, null, Lifespan.nowOn(cursnap), start),
					stLoc, len, true);
			}
		};

		Language language = currentProgram.getLanguage();
		PcodeEmulationCallbacks<byte[]> cc =
			new ComposedPcodeEmulationCallbacks<>(writer.callbacks(), refsCb);
		TerminalService terminalService = state.getTool().getService(TerminalService.class);
		TerminalGivingStreams termAndIo =
			terminalService.createGivingStreams(Charset.forName("utf8"));
		EmuUnixFileSystem<byte[]> fs = new BytesEmuUnixFileSystem();
		LinuxUserspaceEmulatorFactory.populateFileSystem(fs, state.getTool());
		LinuxUserspacePcodeEmulator emu =
			new LinuxUserspacePcodeEmulator(language, cc, termAndIo.terminal(),
				termAndIo.in(), termAndIo.out(), currentProgram, fs, EmuUnixUser.DEFAULT_USER,
				dtrace, dsnap) {

				@Override
				protected AbstractEmuLinuxSyscallUseropLibrary<byte[]> createSyscallLibrary() {
					return switch (language.getLanguageID().getIdAsString()) {
						case "x86:LE:64:default" -> new EmuLinuxAmd64SyscallUseropLibrary<>(this,
							fs, program, user) {

							@Override
							public int unix_read(int fd, long bufPtr, int count) {
								int result = super.unix_read(fd, bufPtr, count);
								EmuUnixFileDescriptor<byte[]> desc = findFd(fd);
								long offset = desc.getOffset() - result; // Cheeky
								AddressSpace space =
									dtrace.getBaseAddressFactory().getDefaultAddressSpace();
								Address start = space.getAddress(bufPtr);
								refsCb.addMappingFromRead(desc, start, result, offset);
								return result;
							}

							@Override
							public int unix_pread(int fd, long bufPtr, int count, long offset) {
								int result = super.unix_pread(fd, bufPtr, count, offset);
								EmuUnixFileDescriptor<byte[]> desc = findFd(fd);
								AddressSpace space =
									dtrace.getBaseAddressFactory().getDefaultAddressSpace();
								Address start = space.getAddress(bufPtr);
								refsCb.addMappingFromRead(desc, start, result, offset);
								return result;
							}
						};
						// TODO: The x86-32 one, too
						default -> super.createSyscallLibrary();
					};
				}
			};

		TraceThread t = dtrace.getThreadManager().getAllThreads().iterator().next();
		PcodeThread<byte[]> thread = emu.newThread(t.getPath());

		try (var _ = dtrace.openTransaction("Emulate")) {
			try {
				refsCb.enabled = true;
				thread.run();
			}
			catch (EmuProcessExitedException e) {
				dtrace.getTimeManager()
						.createSnapshot("Exited with code %s".formatted(e.getStatus()));
				emu.getTerminal().terminated(e.getStatus() instanceof Number n ? n.intValue() : -1);
			}
			catch (Exception e) {
				e.printStackTrace();
				dtrace.getTimeManager()
						.createSnapshot("Terminated: %s".formatted(e.getMessage()));
				emu.getTerminal().terminated(-1);
			}
		}

		activateTrace(dtrace);
	}

	Program findProgramOwning(FileBytes fb) {
		ProgramManager programManager = state.getTool().getService(ProgramManager.class);
		List<Program> programs = List.of(programManager.getAllOpenPrograms());

		for (Program program : programs) {
			for (FileBytes pfb : program.getMemory().getAllFileBytes()) {
				if (pfb == fb) {
					return program;
				}
			}
		}
		return null;
	}

	ProgramLocation locateFileBytes(FileBytes fb, long offset, int len) {
		Program program = findProgramOwning(fb);
		if (program == null) {
			return null;
		}
		List<Address> addrs = program.getMemory().locateAddressesForFileOffset(offset);
		// Eh, just take the first one...
		for (Address a : addrs) {
			return new ProgramLocation(program, a);
		}
		return null;
	}
}
