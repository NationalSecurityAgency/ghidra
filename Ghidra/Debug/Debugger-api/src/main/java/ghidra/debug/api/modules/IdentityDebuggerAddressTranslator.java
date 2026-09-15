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
package ghidra.debug.api.modules;

import java.net.URL;
import java.util.*;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.program.TraceProgramView;

public class IdentityDebuggerAddressTranslator implements DebuggerAddressTranslator {
	private final Trace trace;
	private final Program program;

	public IdentityDebuggerAddressTranslator(Trace trace, Program program) {
		this.trace = trace;
		this.program = program;
	}

	@Override
	public Set<Program> getOpenMappedProgramsAtSnap(Trace trace, long snap) {
		return Set.of(program);
	}

	@Override
	public ProgramLocation getOpenMappedLocation(TraceLocation loc) {
		return new ProgramLocation(program, loc.getAddress());
	}

	@Override
	public ProgramLocation getStaticLocationFromDynamic(ProgramLocation loc) {
		return new ProgramLocation(program, loc.getAddress());
	}

	@Override
	public Set<TraceLocation> getOpenMappedLocations(ProgramLocation loc) {
		return Set.of(new DefaultTraceLocation(trace, null, Lifespan.ALL, loc.getAddress()));
	}

	@Override
	public TraceLocation getOpenMappedLocation(Trace trace, ProgramLocation loc, long snap) {
		if (trace != this.trace) {
			return null;
		}
		return new DefaultTraceLocation(trace, null, Lifespan.ALL, loc.getAddress());
	}

	@Override
	public ProgramLocation getDynamicLocationFromStatic(TraceProgramView view,
			ProgramLocation loc) {
		if (view.getTrace() != this.trace) {
			return null;
		}
		return new ProgramLocation(view, loc.getAddress());
	}

	@Override
	public Map<Program, Collection<MappedAddressRange>> getOpenMappedViews(Trace trace,
			AddressSetView set, long snap) {
		return Map.ofEntries(
			Map.entry(program, set.stream().map(r -> new MappedAddressRange(r, r)).toList()));
	}

	@Override
	public Map<TraceSpan, Collection<MappedAddressRange>> getOpenMappedViews(Program program,
			AddressSetView set) {
		if (program != this.program) {
			return Map.of();
		}
		return Map.ofEntries(Map.entry(new DefaultTraceSpan(trace, Lifespan.ALL),
			set.stream().map(r -> new MappedAddressRange(r, r)).toList()));
	}

	@Override
	public Set<URL> getMappedProgramUrlsInView(Trace trace, AddressSetView set, long snap) {
		// This is not necessary here
		return Set.of();
	}
}
