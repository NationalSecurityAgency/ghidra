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
package ghidra.app.plugin.core.debug.platform;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collection;
import java.util.Set;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.debug.workflow.DisassemblyInject;
import ghidra.app.plugin.core.debug.workflow.DisassemblyInjectInfo;
import ghidra.app.services.DebuggerModelService;
import ghidra.app.services.TraceRecorder;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.ProgramContextImpl;
import ghidra.trace.model.Trace;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

@DisassemblyInjectInfo(langIDs = { "x86:LE:64:default" })
// TODO: Filter / selector on debugger. This is running for GDB, too....
public class DbgengX64DisassemblyInject implements DisassemblyInject {

	enum Mode {
		X64, X86, UNK;
	}

	@Override
	public void pre(PluginTool tool, DisassembleCommand command, TraceProgramView view,
			TraceThread thread, AddressSetView startSet, AddressSetView restricted) {
		Trace trace = view.getTrace();
		AddressRange first = startSet.getFirstRange();
		if (first == null) {
			return;
		}
		DebuggerModelService modelService = tool.getService(DebuggerModelService.class);
		TraceRecorder recorder = modelService == null ? null : modelService.getRecorder(trace);
		Collection<? extends TraceModule> modules =
			trace.getModuleManager().getModulesAt(view.getSnap(), first.getMinAddress());
		Set<Mode> modes = modules.stream()
				.map(m -> modeForModule(recorder, view, m))
				.filter(m -> m != Mode.UNK)
				.collect(Collectors.toSet());
		if (modes.size() != 1) {
			return;
		}
		Mode mode = modes.iterator().next();
		Language lang = trace.getBaseLanguage();
		Register addrsizeReg = lang.getRegister("addrsize");
		Register opsizeReg = lang.getRegister("opsize");
		ProgramContextImpl context = new ProgramContextImpl(lang);
		lang.applyContextSettings(context);
		RegisterValue ctxVal = context.getDisassemblyContext(first.getMinAddress());
		if (mode == Mode.X64) {
			command.setInitialContext(ctxVal
					.assign(addrsizeReg, BigInteger.TWO)
					.assign(opsizeReg, BigInteger.TWO));
		}
		else if (mode == Mode.X86) {
			command.setInitialContext(ctxVal
					.assign(addrsizeReg, BigInteger.ONE)
					.assign(opsizeReg, BigInteger.ONE));
		}
		// Shouldn't ever get anything else.
	}

	protected Mode modeForModule(TraceRecorder recorder, TraceProgramView view,
			TraceModule module) {
		if (recorder != null && recorder.getSnap() == view.getSnap()) {
			AddressSet set = new AddressSet();
			set.add(module.getBase(), module.getBase()); // Recorder should read page
			try {
				// This is on its own task thread, so whatever.
				// Just don't hang it indefinitely.
				recorder.captureProcessMemory(set, TaskMonitor.DUMMY)
						.get(1000, TimeUnit.MILLISECONDS);
			}
			catch (InterruptedException | ExecutionException | TimeoutException e) {
				Msg.error("Could not read module header from target", e);
				// Try to parse whatever's there. If 0s, it'll come UNK.
			}
		}
		MemoryByteProvider mbp = new MemoryByteProvider(view.getMemory(), module.getBase());
		try {
			PortableExecutable pe = PortableExecutable.createPortableExecutable(
				RethrowContinuesFactory.INSTANCE, mbp, SectionLayout.MEMORY, false, false);
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
