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
package ghidra.pcode.emu.taint.full;

import com.google.common.collect.Range;

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.emu.taint.trace.TaintTracePcodeExecutorStatePiece;
import ghidra.pcode.emu.taint.trace.TaintTraceSpace;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.util.ProgramLocation;
import ghidra.taint.model.TaintSet;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.property.TracePropertyMapSpace;

/**
 * The storage space for taint sets in a trace's address space
 * 
 * <p>
 * This adds to {@link TaintTraceSpace} the ability to load taint sets from mapped static programs.
 */
public class TaintDebuggerSpace extends TaintTraceSpace {
	protected final PluginTool tool;
	protected final Trace trace;

	/**
	 * Create the space
	 * 
	 * @param tool the the tool that created the emulator
	 * @param trace the trace backing this space
	 * @param space the address space
	 * @param backing if present, the backing object
	 * @param snap the source snap
	 */
	public TaintDebuggerSpace(PluginTool tool, Trace trace, AddressSpace space,
			TracePropertyMapSpace<String> backing, long snap) {
		super(space, backing, snap);
		this.tool = tool;
		this.trace = trace;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * The taint trace space will call this when the cache misses and the trace has no taint set
	 * stored, allowing us to populate it with a taint set stored in a mapped static program. See
	 * notes in {@link TaintTraceSpace#whenNull(long)}.
	 */
	@Override
	protected TaintSet whenTraceNull(long offset) {
		DebuggerStaticMappingService mappingService =
			tool.getService(DebuggerStaticMappingService.class);
		ProgramLocation sloc =
			mappingService.getOpenMappedLocation(new DefaultTraceLocation(trace, null,
				Range.singleton(snap), space.getAddress(offset)));
		if (sloc == null) {
			return super.whenTraceNull(offset);
		}

		// NB. This is stored in the program, not the user data, despite what the name implies
		StringPropertyMap map = sloc.getProgram()
				.getUsrPropertyManager()
				.getStringPropertyMap(TaintTracePcodeExecutorStatePiece.NAME);
		if (map == null) {
			return super.whenTraceNull(offset);
		}
		String string = map.getString(sloc.getAddress());
		if (string == null) {
			return super.whenTraceNull(offset);
		}
		return TaintSet.parse(string);
	}
}
