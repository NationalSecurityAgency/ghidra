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
package ghidra.app.plugin.core.debug.platform.dbgeng;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.debug.disassemble.*;
import ghidra.app.plugin.core.debug.disassemble.DisassemblyInjectInfo.PlatformInfo;
import ghidra.app.services.DebuggerTargetService;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemBufferByteProvider;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.debug.api.target.Target;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.util.ProgramContextImpl;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@DisassemblyInjectInfo(
	platforms = {
		@PlatformInfo(langID = "x86:LE:64:default", compilerID = "windows"),
		@PlatformInfo(langID = "x86:LE:64:default", compilerID = "clangwindows"),
	})
public class DbgengX64DisassemblyInject implements DisassemblyInject {

	enum Mode {
		X64, X86, UNK;
	}

	@Override
	public void pre(PluginTool tool, TraceDisassembleCommand command, TracePlatform platform,
			long snap, TraceThread thread, AddressSetView startSet, AddressSetView restricted) {
		AddressRange first = startSet.getFirstRange();
		if (first == null) {
			return;
		}
		Trace trace = platform.getTrace();
		DebuggerTargetService targetService = tool.getService(DebuggerTargetService.class);
		Target target = targetService == null ? null : targetService.getTarget(trace);
		Collection<? extends TraceModule> modules =
			trace.getModuleManager().getModulesAt(snap, first.getMinAddress());
		Msg.debug(this, "Disassembling in modules: " +
			modules.stream().map(TraceModule::getName).collect(Collectors.joining(",")));
		Set<Mode> modes = modules.stream()
				.map(m -> modeForModule(target, trace, snap, m))
				.filter(m -> m != Mode.UNK)
				.collect(Collectors.toSet());
		Msg.debug(this, "Disassembling in mode(s): " + modes);
		if (modes.size() != 1) {
			return;
		}
		Mode mode = modes.iterator().next();

		Language language = platform.getLanguage();
		Register longModeReg = language.getRegister("longMode");
		Register addrsizeReg = language.getRegister("addrsize");
		Register opsizeReg = language.getRegister("opsize");
		ProgramContextImpl context = new ProgramContextImpl(language);
		language.applyContextSettings(context);
		RegisterValue ctxVal = context.getDisassemblyContext(first.getMinAddress());
		command.setInitialContext(switch (mode) {
			case X64 -> ctxVal
					.assign(longModeReg, BigInteger.ONE)
					.assign(addrsizeReg, BigInteger.TWO)
					.assign(opsizeReg, BigInteger.ONE);
			case X86 -> ctxVal
					.assign(longModeReg, BigInteger.ZERO)
					.assign(addrsizeReg, BigInteger.ONE)
					.assign(opsizeReg, BigInteger.ONE);
			default -> throw new AssertionError();
		});
	}

	protected Mode modeForModule(Target target, Trace trace, long snap,
			TraceModule module) {
		if (target != null && target.getSnap() == snap) {
			AddressSet set = new AddressSet();
			set.add(module.getBase(), module.getBase()); // Recorder should read page
			try {
				target.readMemory(set, TaskMonitor.DUMMY);
				trace.flushEvents();
			}
			catch (CancelledException e) {
				throw new AssertionError(e);
			}
		}
		MemBuffer bufferAt = trace.getMemoryManager().getBufferAt(snap, module.getBase());
		try (ByteProvider bp = new MemBufferByteProvider(bufferAt)) {
			PortableExecutable pe = new PortableExecutable(bp, SectionLayout.MEMORY, false, false);
			NTHeader ntHeader = pe.getNTHeader();
			if (ntHeader == null) {
				return Mode.UNK;
			}
			OptionalHeader optionalHeader = ntHeader.getOptionalHeader();
			if (optionalHeader == null) {
				return Mode.UNK; // Really shouldn't happen, but who knows?
			}
			return optionalHeader.is64bit() ? Mode.X64 : Mode.X86;
		}
		catch (IOException e) {
			Msg.warn(this, "Could not parse PE from trace: " + e);
			return Mode.UNK;
		}
	}
}
