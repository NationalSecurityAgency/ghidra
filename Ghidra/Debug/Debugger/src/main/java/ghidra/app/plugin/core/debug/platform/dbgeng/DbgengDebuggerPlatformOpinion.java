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
import java.util.Collection;
import java.util.Set;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.debug.disassemble.DisassemblyInject;
import ghidra.app.plugin.core.debug.gui.action.PCLocationTrackingSpec;
import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.app.services.DebuggerTargetService;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemBufferByteProvider;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.debug.api.platform.DebuggerPlatformMapper;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.target.TraceObject;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class DbgengDebuggerPlatformOpinion extends AbstractDebuggerPlatformOpinion {
	protected static final LanguageID LANG_ID_X86_64 = new LanguageID("x86:LE:64:default");
	protected static final LanguageID LANG_ID_X86_64_32 = new LanguageID("x86:LE:64:compat32");
	protected static final CompilerSpecID COMP_ID_VS = new CompilerSpecID("windows");
	protected static final Set<DisassemblyInject> INJECTS =
		Set.of(new DbgengX64DisassemblyInject());

	enum Mode {
		X64, X86, UNK;

		static Mode computeFor(PluginTool tool, Trace trace, Address address, long snap) {
			DebuggerTargetService targetService = tool.getService(DebuggerTargetService.class);
			Target target = targetService == null ? null : targetService.getTarget(trace);
			Collection<? extends TraceModule> modules =
				trace.getModuleManager().getModulesAt(snap, address);
			Msg.debug(Mode.class, "Disassembling in modules: " +
				modules.stream().map(m -> m.getName(snap)).collect(Collectors.joining(",")));
			Set<Mode> modes = modules.stream()
					.map(m -> modeForModule(target, trace, snap, m))
					.filter(m -> m != UNK)
					.collect(Collectors.toSet());
			Msg.debug(Mode.class, "Disassembling in mode(s): " + modes);
			if (modes.size() != 1) {
				return UNK;
			}
			return modes.iterator().next();
		}

		static Mode modeForModule(Target target, Trace trace, long snap, TraceModule module) {
			if (target != null && target.getSnap() == snap) {
				AddressSet set = new AddressSet();
				set.add(module.getBase(snap), module.getBase(snap)); // Recorder should read page
				try {
					target.readMemoryAsync(set, TaskMonitor.DUMMY).get(1, TimeUnit.SECONDS);
					trace.flushEvents();
				}
				catch (InterruptedException | ExecutionException | TimeoutException e) {
					throw new AssertionError(e);
				}
			}
			MemBuffer bufferAt = trace.getMemoryManager().getBufferAt(snap, module.getBase(snap));
			try (ByteProvider bp = new MemBufferByteProvider(bufferAt)) {
				PortableExecutable pe =
					new PortableExecutable(bp, SectionLayout.MEMORY, false, false);
				NTHeader ntHeader = pe.getNTHeader();
				if (ntHeader == null) {
					return UNK;
				}
				OptionalHeader optionalHeader = ntHeader.getOptionalHeader();
				if (optionalHeader == null) {
					return UNK; // Really shouldn't happen, but who knows?
				}
				return optionalHeader.is64bit() ? X64 : X86;
			}
			catch (IOException e) {
				Msg.warn(Mode.class, "Could not parse PE from trace: " + e);
				return UNK;
			}
		}
	}

	protected abstract static class AbstractDbgengX64DebuggerPlatformMapper
			extends DefaultDebuggerPlatformMapper {
		public AbstractDbgengX64DebuggerPlatformMapper(PluginTool tool, Trace trace,
				CompilerSpec cSpec) {
			super(tool, trace, cSpec);
		}
		// TODO: Map registers: efl,rfl,rflags->eflags

		@Override
		protected TracePlatform getDisassemblyPlatform(TraceObject object, Address start,
				long snap) {
			CompilerSpec x64cs = Offer.X64.getCompilerSpec();
			return addOrGetPlatform(x64cs, snap);
		}

		@Override
		protected Collection<DisassemblyInject> getDisassemblyInjections(TracePlatform platform) {
			return INJECTS;
		}
	}

	protected static class DbgengX64DebuggerPlatformMapper
			extends AbstractDbgengX64DebuggerPlatformMapper {
		public DbgengX64DebuggerPlatformMapper(PluginTool tool, Trace trace,
				CompilerSpec cSpec) {
			super(tool, trace, cSpec);
		}
	}

	protected static class DbgengX64_32DebuggerPlatformMapper
			extends AbstractDbgengX64DebuggerPlatformMapper {
		public DbgengX64_32DebuggerPlatformMapper(PluginTool tool, Trace trace,
				CompilerSpec cSpec) {
			super(tool, trace, cSpec);
		}
	}

	protected static class DbgengWoW64DebuggerPlatformMapper
			extends AbstractDbgengX64DebuggerPlatformMapper {
		public DbgengWoW64DebuggerPlatformMapper(PluginTool tool, Trace trace,
				CompilerSpec cSpec) {
			super(tool, trace, cSpec);
		}

		@Override
		public TracePlatform addToTrace(TraceObject newFocus, long snap) {
			DebuggerCoordinates coords = DebuggerCoordinates.NOWHERE.object(newFocus).snap(snap);
			Address pc = PCLocationTrackingSpec.INSTANCE.computeTraceAddress(tool, coords);
			if (pc == null) {
				return addOrGetPlatform(Offer.X64_32.getCompilerSpec(), snap);
			}
			Offer sel = switch (Mode.computeFor(tool, trace, pc, snap)) {
				case X64 -> Offer.X64;
				default -> Offer.X64_32;
			};
			return addOrGetPlatform(sel.getCompilerSpec(), snap);
		}
	}

	enum Offer implements DebuggerPlatformOffer {
		// TODO: X86?
		X64 {
			@Override
			public String getDescription() {
				return "Dbgeng x64 (64-bit module)";
			}

			@Override
			public int getConfidence() {
				return HostDebuggerPlatformOpinion.CONFIDENCE_HOST_KNOWN + 10;
			}

			@Override
			public CompilerSpec getCompilerSpec() {
				return getCompilerSpec(LANG_ID_X86_64, COMP_ID_VS);
			}

			@Override
			public DebuggerPlatformMapper take(PluginTool tool, Trace trace) {
				return new DbgengX64DebuggerPlatformMapper(tool, trace, getCompilerSpec());
			}

			@Override
			public boolean isCreatorOf(DebuggerPlatformMapper mapper) {
				return mapper.getClass() == DbgengX64DebuggerPlatformMapper.class;
			}
		},
		X64_32 {
			@Override
			public String getDescription() {
				return "Dbgeng x64 (32-bit module)";
			}

			@Override
			public int getConfidence() {
				return HostDebuggerPlatformOpinion.CONFIDENCE_HOST_KNOWN + 10;
			}

			@Override
			public CompilerSpec getCompilerSpec() {
				return getCompilerSpec(LANG_ID_X86_64_32, COMP_ID_VS);
			}

			@Override
			public DebuggerPlatformMapper take(PluginTool tool, Trace trace) {
				return new DbgengX64_32DebuggerPlatformMapper(tool, trace, getCompilerSpec());
			}

			@Override
			public boolean isCreatorOf(DebuggerPlatformMapper mapper) {
				return mapper.getClass() == DbgengX64_32DebuggerPlatformMapper.class;
			}
		},
		WOW64 {
			@Override
			public String getDescription() {
				return "Dbgeng x64 (WoW64)";
			}

			@Override
			public int getConfidence() {
				return HostDebuggerPlatformOpinion.CONFIDENCE_HOST_KNOWN + 20;
			}

			@Override
			public CompilerSpec getCompilerSpec() {
				// Report x86-32 in opinions, even though we mix
				return getCompilerSpec(LANG_ID_X86_64_32, COMP_ID_VS);
			}

			@Override
			public DebuggerPlatformMapper take(PluginTool tool, Trace trace) {
				return new DbgengWoW64DebuggerPlatformMapper(tool, trace, getCompilerSpec());
			}

			@Override
			public boolean isCreatorOf(DebuggerPlatformMapper mapper) {
				return mapper.getClass() == DbgengWoW64DebuggerPlatformMapper.class;
			}
		},;
	}

	@Override
	protected Set<DebuggerPlatformOffer> getOffers(TraceObject object, long snap, TraceObject env,
			String debugger, String arch, String os, Endian endian, boolean includeOverrides) {
		if (debugger == null || arch == null || !debugger.toLowerCase().contains("dbg")) {
			return Set.of();
		}
		boolean is64Bit = arch.contains("x86_64") || arch.contains("x64_32");
		if (!is64Bit) {
			return Set.of();
		}
		return Set.of(Offer.X64, Offer.X64_32, Offer.WOW64);
	}
}
