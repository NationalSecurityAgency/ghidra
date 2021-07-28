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
package ghidra.app.plugin.core.debug.service.modules;

import java.net.URL;
import java.util.List;

import com.google.common.collect.Range;

import ghidra.app.plugin.core.debug.utils.ProgramURLUtils;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.TraceLocation;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.Msg;

public enum DebuggerStaticMappingUtils {
	;

	protected static <T> T noProject(Object originator) {
		Msg.warn(originator, "The given program does not exist in any project");
		return null;
	}

	/**
	 * Add a static mapping (relocation) from the given trace to the given program
	 * 
	 * <p>
	 * Note if the trace is backed by a Ghidra database, the caller must already have started a
	 * transaction on the relevant domain object.
	 * 
	 * 
	 * @param from the source trace location, including lifespan
	 * @param to the destination program location
	 * @param length the length of the mapped region
	 * @param truncateExisting true to delete or truncate the lifespan of overlapping entries
	 * @throws TraceConflictedMappingException if a conflicting mapping overlaps the source and
	 *             {@code truncateExisting} is false.
	 */
	public static void addMapping(TraceLocation from, ProgramLocation to, long length,
			boolean truncateExisting)
			throws TraceConflictedMappingException {
		Program tp = to.getProgram();
		if (tp instanceof TraceProgramView) {
			throw new IllegalArgumentException(
				"Mapping destination cannot be a " + TraceProgramView.class.getSimpleName());
		}
		TraceStaticMappingManager manager = from.getTrace().getStaticMappingManager();
		URL toURL = ProgramURLUtils.getUrlFromProgram(tp);
		if (toURL == null) {
			noProject(DebuggerStaticMappingService.class);
		}
		try {
			Address start = from.getAddress();
			Address end = start.addNoWrap(length - 1);
			// Also check end in the destination
			Address toAddress = to.getAddress();
			toAddress.addNoWrap(length - 1); // Anticipate possible AddressOverflow
			AddressRangeImpl range = new AddressRangeImpl(start, end);
			if (truncateExisting) {
				long truncEnd = DBTraceUtils.lowerEndpoint(from.getLifespan()) - 1;
				for (TraceStaticMapping existing : List
						.copyOf(manager.findAllOverlapping(range, from.getLifespan()))) {
					existing.delete();
					if (Long.compareUnsigned(existing.getStartSnap(), truncEnd) < 0) {
						manager.add(existing.getTraceAddressRange(),
							Range.closed(existing.getStartSnap(), truncEnd),
							existing.getStaticProgramURL(), existing.getStaticAddress());
					}
				}
			}
			manager.add(range, from.getLifespan(), toURL,
				toAddress.toString(true));
		}
		catch (AddressOverflowException e) {
			throw new IllegalArgumentException("Length would cause address overflow", e);
		}
	}

	/**
	 * Add a static mapping (relocation) from the given module to the given program
	 * 
	 * <p>
	 * This is simply a shortcut and does not mean to imply that all mappings must represent module
	 * relocations. The lifespan is that of the module's.
	 * 
	 * @param from the source module
	 * @param length the "size" of the module -- {@code max-min+1} as loaded/mapped in memory
	 * @param toProgram the destination program
	 * @see #addMapping(TraceLocation, ProgramLocation, long, boolean)
	 */
	public static void addModuleMapping(TraceModule from, long length, Program toProgram,
			boolean truncateExisting) throws TraceConflictedMappingException {
		TraceLocation fromLoc =
			new DefaultTraceLocation(from.getTrace(), null, from.getLifespan(), from.getBase());
		ProgramLocation toLoc = new ProgramLocation(toProgram, toProgram.getImageBase());
		addMapping(fromLoc, toLoc, length, truncateExisting);
	}

	/**
	 * Add a static mapping (relocation) from the given section to the given program memory block
	 * 
	 * <p>
	 * This is simply a shortcut and does not mean to imply that all mappings must represent section
	 * relocations. In most cases the lengths of the from and to objects match exactly, but this may
	 * not be the case. Whatever the case, the minimum length is computed, and the start addresses
	 * are used as the location. The lifespan is that of the section's containing module.
	 * 
	 * @param from the source section
	 * @param toProgram the destination program
	 * @param to the destination memory block
	 * @see #addMapping(TraceLocation, ProgramLocation, long, boolean)
	 */
	public static void addSectionMapping(TraceSection from, Program toProgram, MemoryBlock to,
			boolean truncateExisting) throws TraceConflictedMappingException {
		TraceLocation fromLoc = new DefaultTraceLocation(from.getTrace(), null,
			from.getModule().getLifespan(), from.getStart());
		ProgramLocation toLoc = new ProgramLocation(toProgram, to.getStart());
		long length = Math.min(from.getRange().getLength(), to.getSize());
		addMapping(fromLoc, toLoc, length, truncateExisting);
	}
}
