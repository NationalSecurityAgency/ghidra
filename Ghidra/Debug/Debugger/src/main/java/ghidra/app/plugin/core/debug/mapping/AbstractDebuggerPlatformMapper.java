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
package ghidra.app.plugin.core.debug.mapping;

import java.util.Collection;
import java.util.Set;

import ghidra.app.plugin.core.debug.disassemble.TraceDisassembleCommand;
import ghidra.app.plugin.core.debug.workflow.DisassemblyInject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractDebuggerPlatformMapper implements DebuggerPlatformMapper {
	protected final PluginTool tool;
	protected final Trace trace;

	public AbstractDebuggerPlatformMapper(PluginTool tool, Trace trace) {
		this.tool = tool;
		this.trace = trace;
	}

	protected boolean canInterpret(TraceObject newFocus, long snap, TraceObject env,
			String debugger, String arch, String os, Endian endian) {
		return true;
	}

	@Override
	public boolean canInterpret(TraceObject newFocus, long snap) {
		TraceObject env = DebuggerPlatformOpinion.getEnvironment(newFocus, snap);
		if (env == null) {
			return canInterpret(newFocus, snap, env, null, null, null, null);
		}
		String debugger = DebuggerPlatformOpinion.getDebugggerFromEnv(env, snap);
		String arch = DebuggerPlatformOpinion.getArchitectureFromEnv(env, snap);
		String os = DebuggerPlatformOpinion.getOperatingSystemFromEnv(env, snap);
		Endian endian = DebuggerPlatformOpinion.getEndianFromEnv(env, snap);
		return canInterpret(newFocus, snap, env, debugger, arch, os, endian);
	}

	protected boolean isCancelSilently(Address start, long snap) {
		return trace.getCodeManager().definedUnits().containsAddress(snap, start);
	}

	protected Collection<DisassemblyInject> getDisassemblyInjections(TraceObject object) {
		return Set.of();
	}

	@Override
	public DisassemblyResult disassemble(TraceThread thread, TraceObject object,
			Address start, AddressSetView restricted, long snap, TaskMonitor monitor) {
		if (isCancelSilently(start, snap)) {
			return DisassemblyResult.CANCELLED;
		}
		TracePlatform platform = trace.getPlatformManager().getPlatform(getCompilerSpec(object));

		Collection<DisassemblyInject> injects = getDisassemblyInjections(object);
		TraceDisassembleCommand dis = new TraceDisassembleCommand(platform, start, restricted);
		Language language = platform.getLanguage();
		AddressSet startSet = new AddressSet(start);
		for (DisassemblyInject i : injects) {
			i.pre(tool, dis, trace, language, snap, thread, startSet, restricted);
		}
		boolean result = dis.applyToTyped(trace.getFixedProgramView(snap), monitor);
		if (!result) {
			return DisassemblyResult.failed(dis.getStatusMsg());
		}
		for (DisassemblyInject i : injects) {
			i.post(tool, trace, snap, dis.getDisassembledAddressSet());
		}
		return DisassemblyResult.success(!dis.getDisassembledAddressSet().isEmpty());
	}
}
