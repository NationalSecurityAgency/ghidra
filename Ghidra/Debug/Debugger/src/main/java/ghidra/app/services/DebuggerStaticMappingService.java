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
package ghidra.app.services;

import java.util.*;

import com.google.common.collect.Range;

import ghidra.app.services.ModuleMapProposal.ModuleMapEntry;
import ghidra.app.services.RegionMapProposal.RegionMapEntry;
import ghidra.app.services.SectionMapProposal.SectionMapEntry;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A service for consuming and mutating trace static mappings, i.e., relocations
 * 
 * <p>
 * This service consumes and tracks all open traces' mappings, tracks when the destination programs
 * are opened and closed, notifies listeners of changes in the tool's overall mapping picture, and
 * provides for addition and validation of new mappings.
 * 
 * <p>
 * Note, the relation of trace locations to program locations is many-to-one.
 * 
 * <p>
 * This service also provides methods for proposing and adding mappings.
 */
public interface DebuggerStaticMappingService {

	/**
	 * A pair for describing sets of mapped addresses
	 * 
	 * <p>
	 * Note, the natural order is by the <em>destination</em> address.
	 */
	public class MappedAddressRange implements Comparable<MappedAddressRange> {

		private final AddressRange srcRange;
		private final AddressRange dstRange;
		private final int hashCode;
		private final long shift;

		public MappedAddressRange(AddressRange srcRange, AddressRange dstRange) {
			this.srcRange = srcRange;
			this.dstRange = dstRange;
			this.hashCode = Objects.hash(dstRange, srcRange);
			this.shift = dstRange.getMinAddress().getOffset() -
				srcRange.getMinAddress().getOffset();
		}

		@Override
		public String toString() {
			return "<MappedRange " + srcRange + "::" + dstRange + ">";
		}

		/**
		 * Get the shift from the source address range to this address range
		 * 
		 * <p>
		 * The meaning depends on what returned this view. If this view is the "static" range, then
		 * this shift describes what was added to the offset of the "dynamic" address to get a
		 * particular address in the "static" range.
		 * 
		 * @return the shift
		 */
		public long getShift() {
			return shift;
		}

		/**
		 * Map an address in the source range to the corresponding address in the destination range
		 * 
		 * @param saddr the source address (not validated)
		 * @return the destination address
		 */
		public Address mapSourceToDestination(Address saddr) {
			return dstRange.getAddressSpace().getAddress(saddr.getOffset() + shift);
		}

		/**
		 * Map an address in the destination range to the corresponding address in the source range
		 * 
		 * @param daddr the destination address (not validated)
		 * @return the source address
		 */
		public Address mapDestinationToSource(Address daddr) {
			return srcRange.getAddressSpace().getAddress(daddr.getOffset() - shift);
		}

		/**
		 * Map a sub-range of the source to the corresponding sub-range of the destination
		 * 
		 * @param srng the source sub-range
		 * @return the destination sub-range
		 */
		public AddressRange mapSourceToDestination(AddressRange srng) {
			try {
				return new AddressRangeImpl(mapSourceToDestination(srng.getMinAddress()),
					srng.getLength());
			}
			catch (AddressOverflowException e) {
				throw new IllegalArgumentException(e);
			}
		}

		/**
		 * Map a sub-range of the destination to the corresponding sub-range of the source
		 * 
		 * @param drng the destination sub-range
		 * @return the source sub-range
		 */
		public AddressRange mapDestinationToSource(AddressRange drng) {
			try {
				return new AddressRangeImpl(mapDestinationToSource(drng.getMinAddress()),
					drng.getLength());
			}
			catch (AddressOverflowException e) {
				throw new IllegalArgumentException(e);
			}
		}

		/**
		 * Get the source address range
		 * 
		 * @return the address range
		 */
		public AddressRange getSourceAddressRange() {
			return srcRange;
		}

		/**
		 * Get the destination address range
		 * 
		 * @return the address range
		 */
		public AddressRange getDestinationAddressRange() {
			return dstRange;
		}

		@Override
		public int compareTo(MappedAddressRange that) {
			int c;
			c = this.dstRange.compareTo(that.dstRange);
			if (c != 0) {
				return c;
			}
			c = this.srcRange.compareTo(that.srcRange);
			if (c != 0) {
				return c;
			}
			return 0;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof MappedAddressRange)) {
				return false;
			}
			MappedAddressRange that = (MappedAddressRange) obj;
			if (!this.dstRange.equals(that.dstRange)) {
				return false;
			}
			if (!this.srcRange.equals(that.srcRange)) {
				return false;
			}
			return true;
		}

		@Override
		public int hashCode() {
			return hashCode;
		}
	}

	/**
	 * Add a static mapping (relocation) from the given trace to the given program
	 * 
	 * @param from the source trace location, including lifespan
	 * @param to the destination program location
	 * @param length the length of the mapped region, where 0 indicates {@code 1 << 64}.
	 * @param truncateExisting true to delete or truncate the lifespan of overlapping entries
	 * @throws TraceConflictedMappingException if a conflicting mapping overlaps the source and
	 *             {@code truncateExisting} is false.
	 */
	void addMapping(TraceLocation from, ProgramLocation to, long length, boolean truncateExisting)
			throws TraceConflictedMappingException;

	/**
	 * Add a static mapping from the given trace to the given program, using identical addresses
	 *
	 * @param from the source trace
	 * @param toProgram the destination program
	 * @param lifespan the lifespan of the mapping
	 * @param truncateExisting true to delete or truncate the lifespan of overlapping entries. If
	 *            false, overlapping entries are omitted.
	 */
	void addIdentityMapping(Trace from, Program toProgram, Range<Long> lifespan,
			boolean truncateExisting);

	void addMapping(MapEntry<?, ?> entry, boolean truncateExisting)
			throws TraceConflictedMappingException;

	void addMappings(Collection<? extends MapEntry<?, ?>> entries, TaskMonitor monitor,
			boolean truncateExisting, String description) throws CancelledException;

	/**
	 * Add several static mappings (relocations)
	 * 
	 * <p>
	 * This will group the entries by trace and add each's entries in a single transaction. If any
	 * entry fails, including due to conflicts, that failure is logged but ignored, and the
	 * remaining entries are processed.
	 * 
	 * @param entries the entries to add
	 * @param monitor a monitor to cancel the operation
	 * @param truncateExisting true to delete or truncate the lifespan of overlapping entries
	 * @see #addMapping(TraceLocation, ProgramLocation, long, boolean)
	 * @throws TraceConflictedMappingException if a conflicting mapping overlaps the source and
	 *             {@code truncateExisting} is false.
	 */
	void addModuleMappings(Collection<ModuleMapEntry> entries, TaskMonitor monitor,
			boolean truncateExisting) throws CancelledException;

	/**
	 * Add several static mappings (relocations)
	 * 
	 * <p>
	 * This will group the entries by trace and add each's entries in a single transaction. If any
	 * entry fails, including due to conflicts, that failure is logged but ignored, and the
	 * remaining entries are processed.
	 * 
	 * @param entries the entries to add
	 * @param monitor a monitor to cancel the operation
	 * @param truncateExisting true to delete or truncate the lifespan of overlapping entries
	 * @see #addMapping(TraceLocation, ProgramLocation, long, boolean)
	 */
	void addSectionMappings(Collection<SectionMapEntry> entries, TaskMonitor monitor,
			boolean truncateExisting) throws CancelledException;

	/**
	 * Add several static mappings (relocations)
	 * 
	 * <p>
	 * This will group the entries by trace and add each's entries in a single transaction. If any
	 * entry fails, including due to conflicts, that failure is logged but ignored, and the
	 * remaining entries are processed.
	 * 
	 * @param entries the entries to add
	 * @param monitor a monitor to cancel the operation
	 * @param truncateExisting true to delete or truncate the lifespan of overlapping entries
	 * @see #addMapping(TraceLocation, ProgramLocation, long, boolean)
	 */
	void addRegionMappings(Collection<RegionMapEntry> entries, TaskMonitor monitor,
			boolean truncateExisting) throws CancelledException;

	/**
	 * Collect all the open destination programs relevant for the given trace and snap
	 * 
	 * @param trace the trace
	 * @param snap the snap
	 * @return the set of open destination programs
	 */
	Set<Program> getOpenMappedProgramsAtSnap(Trace trace, long snap);

	/**
	 * Map the given trace location to a program location, if the destination is open
	 * 
	 * @param loc the source location
	 * @return the destination location, or {@code null} if not mapped, or not open
	 */
	ProgramLocation getOpenMappedLocation(TraceLocation loc);

	/**
	 * Similar to {@link #getOpenMappedLocation(TraceLocation)} but preserves details
	 * 
	 * <p>
	 * The given location's {@link ProgramLocation#getProgram()} method must return a
	 * {@link TraceProgramView}. It derives the trace and snap from that view. Additionally, this
	 * will attempt to map over other "location" details, e.g., field, row, column.
	 * 
	 * @param loc a location within a trace view
	 * @return a mapped location in a program, or {@code null}
	 */
	ProgramLocation getStaticLocationFromDynamic(ProgramLocation loc);

	/**
	 * Map the given program location back to open source trace locations
	 * 
	 * @param loc the program location
	 * @return the, possibly empty, set of trace locations
	 */
	Set<TraceLocation> getOpenMappedLocations(ProgramLocation loc);

	/**
	 * Map the given program location back to a source trace and snap
	 * 
	 * @param trace the source trace, to which we are mapping back
	 * @param loc the destination location, from which we are mapping back
	 * @param snap the source snap, to which we are mapping back
	 * @return the source of the found mapping, or {@code null} if not mapped
	 */
	TraceLocation getOpenMappedLocation(Trace trace, ProgramLocation loc, long snap);

	/**
	 * Similar to {@link #getOpenMappedLocation(Trace, ProgramLocation, long)} but preserves details
	 * 
	 * <p>
	 * This method derives the source trace and snap from the given view. Additinoally, this will
	 * attempt to map over other "location" details, e.g., field, row, column.
	 * 
	 * @param view the view, specifying the source trace and snap, to which we are mapping back
	 * @param loc the destination location, from which we are mapping back.
	 * @return the destination of the found mapping, or {@code null} if not mapped
	 */
	ProgramLocation getDynamicLocationFromStatic(TraceProgramView view, ProgramLocation loc);

	/**
	 * Find/compute all destination address sets given a source trace address set
	 * 
	 * @param trace the source trace
	 * @param set the source address set
	 * @param snap the source snap
	 * @return a map of destination programs to corresponding computed destination address ranges
	 */
	Map<Program, Collection<MappedAddressRange>> getOpenMappedViews(Trace trace,
			AddressSetView set, long snap);

	/**
	 * Find/compute all source address sets given a destination program address set
	 * 
	 * @param program the destination program, from which we are mapping back
	 * @param set the destination address set, from which we are mapping back
	 * @return a map of source traces to corresponding computed source address ranges
	 */
	Map<TraceSpan, Collection<MappedAddressRange>> getOpenMappedViews(Program program,
			AddressSetView set);

	/**
	 * Open all destination programs in mappings intersecting the given source trace, address set,
	 * and snap
	 * 
	 * <p>
	 * Note, because the trace's mapping table contains {@link Program} URLs, it's possible the
	 * destination program(s) do not exist, and/or that there may be errors opening the destinations
	 * program(s).
	 * 
	 * <p>
	 * Note, the caller to this method should not expect the relevant mappings to be immediately
	 * loaded by the manager implementation. Instead, it should listen for the expected changes in
	 * mappings before proceeding.
	 * 
	 * @param trace the source trace
	 * @param set the source address set
	 * @param snap the source snap
	 * @param failures a, possibly empty, set of failures encountered when opening the programs
	 * @return the set of destination programs in the relevant mappings, including those already
	 *         open
	 */
	Set<Program> openMappedProgramsInView(Trace trace, AddressSetView set, long snap,
			Set<Exception> failures);

	/**
	 * Add a listener for changes in mappings
	 * 
	 * <p>
	 * Note, the caller must ensure a strong reference to the listener is maintained, or it will be
	 * removed automatically.
	 * 
	 * @param l the listener
	 */
	void addChangeListener(DebuggerStaticMappingChangeListener l);

	/**
	 * Remove a listener for changes in mappings
	 * 
	 * @param l the listener
	 */
	void removeChangeListener(DebuggerStaticMappingChangeListener l);

	/**
	 * Collect likely matches for destination programs for the given trace module
	 * 
	 * <p>
	 * If the trace is saved in a project, this will search that project preferring its siblings; if
	 * no sibling are probable, it will try the rest of the project. Otherwise, it will search the
	 * current project. "Probable" leaves room for implementations to use any number of heuristics
	 * available, e.g., name, path, type; however, they should refrain from opening or checking out
	 * domain files.
	 * 
	 * @param module the trace module
	 * @return the, possibly empty, set of probable matches
	 */
	Set<DomainFile> findProbableModulePrograms(TraceModule module);

	/**
	 * Propose a module map for the given module to the given program
	 * 
	 * <p>
	 * Note, no sanity check is performed on the given parameters. This will simply propose the
	 * given module-program pair. It is strongly advised to use
	 * {@link ModuleMapProposal#computeScore()} to assess the proposal. Alternatively, use
	 * {@link #proposeModuleMap(TraceModule, Collection)} to have the service select the best-scored
	 * mapping from a collection of proposed programs.
	 * 
	 * @param module the module to consider
	 * @param program the destination program to consider
	 * @return the proposal
	 */
	ModuleMapProposal proposeModuleMap(TraceModule module, Program program);

	/**
	 * Compute the best-scored module map for the given module and programs
	 * 
	 * <p>
	 * Note, no sanity check is performed on any given module-program pair. Instead, the
	 * highest-scoring proposal is selected from the possible module-program pairs. In particular,
	 * the names of the programs vs. the module name may not be examined by the implementation.
	 * 
	 * @see ModuleMapProposal#computeScore()
	 * 
	 * @param module the module to consider
	 * @param programs a set of proposed destination programs
	 * @return the best-scored proposal, or {@code null} if no program is proposed
	 */
	ModuleMapProposal proposeModuleMap(TraceModule module, Collection<? extends Program> programs);

	/**
	 * Compute the "best" map of trace module to program for each given module given a collection of
	 * proposed programs.
	 * 
	 * <p>
	 * Note, this method will first examine module and program names in order to cull unlikely
	 * pairs. It then takes the best-scored proposal for each module. If a module has no likely
	 * paired program, then it is omitted from the result, i.e.., the returned map will have no
	 * {@code null} values.
	 * 
	 * @param modules the modules to map
	 * @param programs the set of proposed destination programs
	 * @return the proposal
	 */
	Map<TraceModule, ModuleMapProposal> proposeModuleMaps(
			Collection<? extends TraceModule> modules, Collection<? extends Program> programs);

	/**
	 * Propose a singleton section map from the given section to the given program memory block
	 * 
	 * <p>
	 * Note, no sanity check is performed on the given parameters. This will simply give a singleton
	 * map of the given entry. It is strongly advised to use
	 * {@link SectionMapProposal#computeScore()} to assess the proposal. Alternatively, use
	 * {@link #proposeSectionMap(TraceModule, Collection)} to have the service select the
	 * best-scored mapping from a collection of proposed programs.
	 * 
	 * @param section the section to map
	 * @param program the destination program
	 * @param block the memory block in the destination program
	 * @return the proposed map
	 */
	SectionMapProposal proposeSectionMap(TraceSection section, Program program, MemoryBlock block);

	/**
	 * Propose a section map for the given module to the given program
	 * 
	 * <p>
	 * Note, no sanity check is performed on the given parameters. This will do its best to map
	 * sections from the given module to memory blocks in the given program. It is strongly advised
	 * to use {@link SectionMapProposal#computeScore()} to assess the proposal. Alternatively, use
	 * {@link #proposeSectionMap(TraceModule, Collection)} to have the service select the
	 * best-scored mapping from a collection of proposed programs.
	 * 
	 * @param module the module whose sections to map
	 * @param program the destination program whose blocks to consider
	 * @return the proposed map
	 */
	SectionMapProposal proposeSectionMap(TraceModule module, Program program);

	/**
	 * Proposed the best-scored section map for the given module and programs
	 * 
	 * <p>
	 * Note, no sanity check is performed on any given module-program pair. Instead, the
	 * highest-scoring proposal is selected from the possible module-program pairs. In particular,
	 * the names of the programs vs. the module name may not be examined by the implementation.
	 * 
	 * @see SectionMapProposal#computeScore()
	 * 
	 * @param module the module whose sections to map
	 * @param programs a set of proposed destination programs
	 * @return the best-scored map, or {@code null} if no program is proposed
	 */
	SectionMapProposal proposeSectionMap(TraceModule module,
			Collection<? extends Program> programs);

	/**
	 * Propose the best-scored maps of trace sections to program memory blocks for each given module
	 * given a collection of proposed programs.
	 * 
	 * <p>
	 * Note, this method will first examine module and program names in order to cull unlikely
	 * pairs. It then takes the best-scored proposal for each module. If a module has no likely
	 * paired program, then it is omitted from the result, i.e., the returned map will have no
	 * {@code null} values.
	 * 
	 * @param modules the modules to map
	 * @param programs a set of proposed destination programs
	 * @return the composite proposal
	 */
	Map<TraceModule, SectionMapProposal> proposeSectionMaps(
			Collection<? extends TraceModule> modules, Collection<? extends Program> programs);

	/**
	 * Propose a singleton region map from the given region to the given program memory block
	 * 
	 * <p>
	 * Note, no sanity check is performed on the given parameters. This will simply give a singleton
	 * map of the given entry. It is strongly advised to use
	 * {@link RegionMapProposal#computeScore()} to assess the proposal. Alternatively, use
	 * {@link #proposeRegionMap(Collection, Collection)} to have the service select the best-scored
	 * mapping from a collection of proposed programs.
	 * 
	 * @param region the region to map
	 * @param program the destination program
	 * @param block the memory block in the destination program
	 * @return the proposed map
	 */
	RegionMapProposal proposeRegionMap(TraceMemoryRegion region, Program program,
			MemoryBlock block);

	/**
	 * Propose a region map for the given regions to the given program
	 * 
	 * <p>
	 * Note, no sanity check is performed on the given parameters. This will do its best to map
	 * regions to memory blocks in the given program. For the best results, regions should all
	 * comprise the same module, and the minimum address among the regions should be the module's
	 * base address. It is strongly advised to use {@link RegionMapProposal#computeScore()} to
	 * assess the proposal. Alternatively, use {@link #proposeRegionMap(Collection, Collection)} to
	 * have the service select the best-scored mapping from a collection of proposed programs.
	 * 
	 * @param region the region to map
	 * @param program the destination program whose blocks to consider
	 * @return the proposed map
	 */
	RegionMapProposal proposeRegionMap(Collection<? extends TraceMemoryRegion> regions,
			Program program);

	/**
	 * Propose the best-scored maps of trace regions to program memory blocks for each given
	 * "module" given a collection of proposed programs.
	 * 
	 * <p>
	 * Note, this method will first group regions into likely modules by parsing their names, then
	 * compare to program names in order to cull unlikely pairs. It then takes the best-scored
	 * proposal for each module. If a module has no likely paired program, then it is omitted from
	 * the result. For informational purposes, the keys in the returned map reflect the grouping of
	 * regions into likely modules. For the best results, the minimum address of each module should
	 * be among the regions.
	 * 
	 * @param modules the modules to map
	 * @param programs a set of proposed destination programs
	 * @return the composite proposal
	 */
	Map<Collection<TraceMemoryRegion>, RegionMapProposal> proposeRegionMaps(
			Collection<? extends TraceMemoryRegion> regions,
			Collection<? extends Program> programs);
}
