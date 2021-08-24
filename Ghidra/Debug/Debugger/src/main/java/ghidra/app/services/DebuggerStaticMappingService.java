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
import java.util.stream.Collectors;

import com.google.common.collect.Range;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.MathUtilities;
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
	 * A proposed mapping of module to program
	 */
	public interface ModuleMapProposal {

		/**
		 * Flatten proposals into a single collection of entries
		 * 
		 * <p>
		 * The output is suitable for use in
		 * {@link DebuggerStaticMappingService#addModuleMappings(Collection, TaskMonitor, boolean)}.
		 * In some contexts, the user should be permitted to see and optionally adjust the
		 * collection first.
		 * 
		 * <p>
		 * Note, a suitable parameter to this method is derived by invoking {@link Map#values()} on
		 * the result of
		 * {@link DebuggerStaticMappingService#proposeModuleMaps(Collection, Collection)}.
		 * 
		 * <p>
		 * Note, it is advisable to filter the returned collection using
		 * {@link DebuggerStaticMappingService#removeOverlappingModuleEntries(Collection)} to avoid
		 * errors from adding overlapped mappings. Alternatively, you can set
		 * {@code truncateExisting} to true when calling
		 * {@link DebuggerStaticMappingService#addModuleMappings(Collection, TaskMonitor, boolean)}.
		 * 
		 * @param proposals the collection of proposed maps
		 * @return the flattened, filtered collection
		 */
		static Collection<ModuleMapEntry> flatten(Collection<ModuleMapProposal> proposals) {
			Collection<ModuleMapEntry> result = new LinkedHashSet<>();
			for (ModuleMapProposal map : proposals) {
				result.addAll(map.computeMap().values());
			}
			return result;
		}

		/**
		 * Remove entries from a collection which overlap existing entries in the trace
		 * 
		 * @param entries the entries to filter
		 * @return the filtered entries
		 */
		public static Set<ModuleMapEntry> removeOverlapping(Collection<ModuleMapEntry> entries) {
			return entries.stream().filter(e -> {
				TraceStaticMappingManager manager = e.module.getTrace().getStaticMappingManager();
				return manager.findAllOverlapping(e.moduleRange, e.module.getLifespan()).isEmpty();
			}).collect(Collectors.toSet());
		}

		/**
		 * Get the trace module of this proposal
		 * 
		 * @return the module
		 */
		TraceModule getModule();

		/**
		 * Get the corresponding program image of this proposal
		 * 
		 * @return the program
		 */
		Program getProgram();

		/**
		 * Compute a notional "score" of the proposal
		 * 
		 * <p>
		 * This may examine the module and program names, but must consider the likelihood of the
		 * match based on this proposal. The implementation need not assign meaning to any
		 * particular score, but a higher score must imply a more likely match.
		 * 
		 * @implNote some information to consider: length and case of matched image and module
		 *           names, alignment of program memory blocks to trace memory regions, etc.
		 * 
		 * @return a score of the proposed pair
		 */
		double computeScore();

		/**
		 * Compute the overall module map given by this proposal
		 * 
		 * @return the map
		 */
		Map<TraceModule, ModuleMapEntry> computeMap();
	}

	/**
	 * A proposed map of sections to program memory blocks
	 */
	public interface SectionMapProposal {

		/**
		 * Flatten proposals into a single collection of entries
		 * 
		 * <p>
		 * The output is suitable for use in
		 * {@link DebuggerStaticMappingService#addSectionMappings(Collection, TaskMonitor, boolean)}.
		 * In some contexts, the user should be permitted to see and optionally adjust the
		 * collection first.
		 * 
		 * <p>
		 * Note, a suitable parameter to this method is derived by invoking {@link Map#values()} on
		 * the result of
		 * {@link DebuggerStaticMappingService#proposeSectionMaps(Collection, Collection)}.
		 * 
		 * <p>
		 * Note, it is advisable to filter the returned collection using
		 * {@link DebuggerStaticMappingService#removeOverlappingSectionEntries(Collection)} to avoid
		 * errors from adding overlapped mappings. Alternatively, you can set
		 * {@code truncateExisting} to true when calling
		 * {@link DebuggerStaticMappingService#addSectionMappings(Collection, TaskMonitor, boolean)}.
		 * 
		 * @param proposals the collection of proposed maps
		 * @return the flattened, filtered collection
		 */
		static Collection<SectionMapEntry> flatten(Collection<SectionMapProposal> proposals) {
			Collection<SectionMapEntry> result = new LinkedHashSet<>();
			for (SectionMapProposal map : proposals) {
				result.addAll(map.computeMap().values());
			}
			return result;
		}

		/**
		 * Remove entries from a collection which overlap existing entries in the trace
		 * 
		 * @param entries the entries to filter
		 * @return the filtered entries
		 */
		public static Set<SectionMapEntry> removeOverlapping(Collection<SectionMapEntry> entries) {
			return entries.stream().filter(e -> {
				TraceStaticMappingManager manager = e.section.getTrace().getStaticMappingManager();
				Range<Long> moduleLifespan = e.section.getModule().getLifespan();
				return manager.findAllOverlapping(e.section.getRange(), moduleLifespan).isEmpty();
			}).collect(Collectors.toSet());
		}

		/**
		 * Get the trace module of this proposal
		 * 
		 * @return the module
		 */
		TraceModule getModule();

		/**
		 * Get the corresponding program image of this proposal
		 * 
		 * @return the program
		 */
		Program getProgram();

		/**
		 * Compute a notional "score" of the proposal
		 * 
		 * <p>
		 * This may examine the module and program names, but must consider the likelihood of the
		 * match based on this proposal. The implementation need not assign meaning to any
		 * particular score, but a higher score must imply a more likely match.
		 * 
		 * @implNote some attributes of sections and blocks to consider: matched names vs. total
		 *           names, sizes, addresses (last n hexidecimal digits, to account for relocation),
		 *           consistency of relocation offset, etc.
		 * 
		 * @return a score of the proposed pair
		 */
		double computeScore();

		/**
		 * Get the program block proposed for a given trace section
		 * 
		 * @param section the trace section
		 * @return the proposed program block
		 */
		MemoryBlock getDestination(TraceSection section);

		/**
		 * Compute the overall section map given by this proposal
		 * 
		 * @return the map
		 */
		Map<TraceSection, SectionMapEntry> computeMap();
	}

	/**
	 * A module-program entry in a proposed module map
	 */
	public static class ModuleMapEntry {
		/**
		 * Check if a block should be included in size computations or analyzed for proposals
		 * 
		 * @param program the program containing the block
		 * @param block the block
		 * @return true if included, false otherwise
		 */
		public static boolean includeBlock(Program program, MemoryBlock block) {
			if (program.getImageBase().getAddressSpace() != block.getStart().getAddressSpace()) {
				return false;
			}
			if (!block.isLoaded()) {
				return false;
			}
			if (block.isMapped()) {
				// TODO: Determine how to handle these.
				return false;
			}
			if (MemoryBlock.EXTERNAL_BLOCK_NAME.equals(block.getName())) {
				return false;
			}
			return true;
		}

		/**
		 * Compute the "size" of an image
		 * 
		 * <p>
		 * This is considered the maximum loaded address as mapped in memory, minus the image base.
		 * 
		 * @param program the program image whose size to compute
		 * @return the size
		 */
		public static long computeImageSize(Program program) {
			Address imageBase = program.getImageBase();
			long imageSize = 0;
			// TODO: How to handle Harvard architectures?
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (!includeBlock(program, block)) {
					continue;
				}
				imageSize = Math.max(imageSize, block.getEnd().subtract(imageBase) + 1);
			}
			return imageSize;
		}

		private final TraceModule module;
		private Program program;
		private AddressRange moduleRange;

		/**
		 * Construct a module map entry
		 * 
		 * <p>
		 * Generally, only the service implementation should construct an entry. See
		 * {@link DebuggerStaticMappingService#proposeModuleMap(TraceModule, Program)} and related
		 * to obtain these.
		 * 
		 * @param module the module
		 * @param program the matched program
		 * @param moduleRange a range from the module base the size of the program's image
		 */
		public ModuleMapEntry(TraceModule module, Program program, AddressRange moduleRange) {
			this.module = module;
			this.program = program;
			this.moduleRange = moduleRange;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof ModuleMapEntry)) {
				return false;
			}
			ModuleMapEntry that = (ModuleMapEntry) obj;
			if (this.module != that.module) {
				return false;
			}
			/*if (this.program != that.program) {
				return false;
			}*/
			// imageSize is derived
			return true;
		}

		@Override
		public int hashCode() {
			return Objects.hash(module/*, program*/);
		}

		/**
		 * Get the module for this entry
		 * 
		 * @return the module
		 */
		public TraceModule getModule() {
			return module;
		}

		/**
		 * Get the address range of the module in the trace, as computed from the matched program's
		 * image size
		 * 
		 * @return the module range
		 */
		public AddressRange getModuleRange() {
			return moduleRange;
		}

		/**
		 * Get the matched program
		 * 
		 * @return the program
		 */
		public Program getProgram() {
			return program;
		}

		/**
		 * Set the matched program
		 * 
		 * <p>
		 * This is generally used in UIs to let the user tweak and reassign, if desired. This will
		 * also re-compute the module range based on the new program's image size.
		 * 
		 * @param program the program
		 */
		public void setProgram(Program program) {
			this.program = program;
			try {
				this.moduleRange =
					new AddressRangeImpl(module.getBase(), computeImageSize(program));
			}
			catch (AddressOverflowException e) {
				// This is terribly unlikely
				throw new IllegalArgumentException(
					"Specified program is too large for module's memory space");
			}
		}
	}

	/**
	 * A section-block entry in a proposed section map
	 */
	public static class SectionMapEntry {
		private final TraceSection section;
		private Program program;
		private MemoryBlock block;

		/**
		 * Construct a section map entry
		 * 
		 * <p>
		 * Generally, only the service implementation should construct an entry. See
		 * {@link DebuggerStaticMappingService#proposeSectionMap(TraceSection, Program, MemoryBlock)}
		 * and related to obtain these.
		 * 
		 * @param section the section
		 * @param program the program containing the matched block
		 * @param block the matched memory block
		 */
		public SectionMapEntry(TraceSection section, Program program, MemoryBlock block) {
			this.section = section;
			this.program = program;
			this.block = block;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof SectionMapEntry)) {
				return false;
			}
			SectionMapEntry that = (SectionMapEntry) obj;
			if (this.section != that.section) {
				return false;
			}
			/*if (this.program != that.program) {
				return false;
			}
			if (this.block != that.block) {
				return false;
			}*/
			return true;
		}

		@Override
		public int hashCode() {
			return Objects.hash(section/*, program, block*/);
		}

		/**
		 * Get the module containing the section
		 * 
		 * @return the module
		 */
		public TraceModule getModule() {
			return section.getModule();
		}

		/**
		 * Get the section
		 * 
		 * @return the section
		 */
		public TraceSection getSection() {
			return section;
		}

		/**
		 * Get the program containing the matched memory block
		 * 
		 * @return the program
		 */
		public Program getProgram() {
			return program;
		}

		/**
		 * Get the matched memory block
		 * 
		 * @return the block
		 */
		public MemoryBlock getBlock() {
			return block;
		}

		/**
		 * Set the matched memory block
		 * 
		 * @param program the program containing the block
		 * @param block the block
		 */
		public void setBlock(Program program, MemoryBlock block) {
			this.program = program;
			this.block = block;
		}

		/**
		 * Get the length of the match
		 * 
		 * <p>
		 * Ideally, the section and block have <em>exactly</em> the same length. If they do not, the
		 * (unsigned) minimum of the two is used.
		 * 
		 * @return the length
		 */
		public long getLength() {
			return MathUtilities.unsignedMin(section.getRange().getLength(), block.getSize());
		}
	}

	/**
	 * <<<<<<< HEAD A {@code (shift,view)} pair for describing sets of mapped addresses
	 */
	public class ShiftAndAddressSetView {
		private final long shift;
		private final AddressSetView view;

		public ShiftAndAddressSetView(long shift, AddressSetView view) {
			this.shift = shift;
			this.view = view;
		}

		/**
		 * Get the shift from the source address set to this address set
		 * 
		 * <p>
		 * The meaning depends on what returned this view. If this view is the "static" set, then
		 * this shift describes what was added to the offset of the "dynamic" address to get a
		 * particular address in this set. Note that since not all addresses from the requested
		 * source set may have been mapped, you cannot simply compare min addresses to obtain this
		 * shift. To "map back" to the source address from a destination address in this set,
		 * <em>subtract</em> this shift.
		 * 
		 * @return the shift
		 */
		public long getShift() {
			return shift;
		}

		/**
		 * Get the destination address set view as mapped from the source address set
		 * 
		 * @return the address set
		 */
		public AddressSetView getAddressSetView() {
			return view;
		}
	}

	/**
	 * Add a static mapping (relocation) from the given trace to the given program
	 * 
	 * <p>
	 * Note if the trace is backed by a Ghidra database, the caller must already have started a
	 * transaction on the relevant domain object.
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
	void addModuleMapping(TraceModule from, long length, Program toProgram,
			boolean truncateExisting) throws TraceConflictedMappingException;

	/**
	 * ======= >>>>>>> d694542c5 (GP-660: Put program filler back in. Need to performance test.) Add
	 * several static mappings (relocations)
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
	 * @return a map of destination programs to corresponding computed destination address sets
	 */
	Map<Program, ShiftAndAddressSetView> getOpenMappedViews(Trace trace,
			AddressSetView set, long snap);

	/**
	 * Find/compute all source address sets given a destination program address set
	 * 
	 * @param program the destination program, from which we are mapping back
	 * @param set the destination address set, from which we are mapping back
	 * @return a map of source traces to corresponding computed source address sets
	 */
	Map<TraceSnap, ShiftAndAddressSetView> getOpenMappedViews(Program program,
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
	 * Recursively collect external programs, i.e., libraries, starting at the given seed
	 * 
	 * @param seed the seed, usually the executable
	 * @param monitor a monitor to cancel the process
	 * @return the set of found programs, including the seed
	 * @throws CancelledException if cancelled by the monitor
	 */
	Set<Program> collectLibraries(Program seed, TaskMonitor monitor) throws CancelledException;

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
	 * pairs. If then takes the best-scored proposal for each module. If a module has no likely
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
}
