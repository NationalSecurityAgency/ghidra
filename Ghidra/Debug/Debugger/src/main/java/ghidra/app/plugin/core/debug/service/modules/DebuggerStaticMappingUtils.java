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
import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.debug.utils.ProgramURLUtils;
import ghidra.app.services.MapEntry;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.ComparatorMath;
import ghidra.util.Msg;

public enum DebuggerStaticMappingUtils {
	;

	protected static <T> T noProject(Object originator) {
		Msg.warn(originator, "The given program does not exist in any project");
		return null;
	}

	protected static void collectLibraries(ProjectData project, DomainFile cur,
			Set<DomainFile> col) {
		if (!Program.class.isAssignableFrom(cur.getDomainObjectClass()) || !col.add(cur)) {
			return;
		}
		Set<String> paths = new HashSet<>();
		try (PeekOpenedDomainObject peek = new PeekOpenedDomainObject(cur)) {
			if (!(peek.object instanceof Program program)) {
				return;
			}
			ExternalManager externalManager = program.getExternalManager();
			for (String libraryName : externalManager.getExternalLibraryNames()) {
				Library library = externalManager.getExternalLibrary(libraryName);
				String path = library.getAssociatedProgramPath();
				if (path != null) {
					paths.add(path);
				}
			}
		}

		for (String libraryPath : paths) {
			DomainFile libFile = project.getFile(libraryPath);
			if (libFile == null) {
				continue;
			}
			collectLibraries(project, libFile, col);
		}
	}

	/**
	 * Recursively collect external programs, i.e., libraries, starting at the given seeds
	 * 
	 * <p>
	 * This will only descend into domain files that are already opened. This will only include
	 * results whose content type is a {@link Program}.
	 * 
	 * @param seeds the seeds, usually including the executable
	 * @return the set of found domain files, including the seeds
	 */
	public static Set<DomainFile> collectLibraries(Collection<DomainFile> seeds) {
		Set<DomainFile> result = new LinkedHashSet<>();
		for (DomainFile seed : seeds) {
			collectLibraries(seed.getParent().getProjectData(), seed, result);
		}
		return result;
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
	 * @param length the length of the mapped region
	 * @param truncateExisting true to delete or truncate the lifespan of overlapping entries
	 * @throws TraceConflictedMappingException if a conflicting mapping overlaps the source and
	 *             {@code truncateExisting} is false.
	 */
	public static void addMapping(TraceLocation from, ProgramLocation to, long length,
			boolean truncateExisting) throws TraceConflictedMappingException {
		Program tp = to.getProgram();
		if (tp instanceof TraceProgramView) {
			throw new IllegalArgumentException(
				"Mapping destination cannot be a " + TraceProgramView.class.getSimpleName());
		}
		TraceStaticMappingManager manager = from.getTrace().getStaticMappingManager();
		URL toURL = ProgramURLUtils.getUrlFromProgram(tp);
		if (toURL == null) {
			noProject(DebuggerStaticMappingUtils.class);
		}
		Address fromAddress = from.getAddress();
		Address toAddress = to.getByteAddress();
		long maxFromLengthMinus1 =
			fromAddress.getAddressSpace().getMaxAddress().subtract(fromAddress);
		long maxToLengthMinus1 =
			toAddress.getAddressSpace().getMaxAddress().subtract(toAddress);
		if (Long.compareUnsigned(length - 1, maxFromLengthMinus1) > 0) {
			throw new IllegalArgumentException("Length would cause address overflow in trace");
		}
		if (Long.compareUnsigned(length - 1, maxToLengthMinus1) > 0) {
			throw new IllegalArgumentException("Length would cause address overflow in program");
		}
		Address end = fromAddress.addWrap(length - 1);
		// Also check end in the destination
		AddressRangeImpl range = new AddressRangeImpl(fromAddress, end);
		Lifespan fromLifespan = from.getLifespan();
		if (truncateExisting) {
			long truncEnd = fromLifespan.lmin() - 1;
			for (TraceStaticMapping existing : List
					.copyOf(manager.findAllOverlapping(range, fromLifespan))) {
				existing.delete();
				if (fromLifespan.minIsFinite() &&
					Lifespan.DOMAIN.compare(existing.getStartSnap(), truncEnd) <= 0) {
					manager.add(existing.getTraceAddressRange(),
						Lifespan.span(existing.getStartSnap(), truncEnd),
						existing.getStaticProgramURL(), existing.getStaticAddress());
				}
			}
		}
		manager.add(range, fromLifespan, toURL, toAddress.toString(true));
	}

	public static void addMapping(MapEntry<?, ?> entry, boolean truncateExisting)
			throws TraceConflictedMappingException {
		TraceLocation fromLoc = entry.getFromTraceLocation();
		ProgramLocation toLoc = entry.getToProgramLocation();
		long length = entry.getMappingLength();
		addMapping(fromLoc, toLoc, length, truncateExisting);
	}

	public static class Extrema {
		private Address min = null;
		private Address max = null;

		public void consider(AddressRange range) {
			min = min == null ? range.getMinAddress()
					: ComparatorMath.cmin(min, range.getMinAddress());
			max = max == null ? range.getMaxAddress()
					: ComparatorMath.cmax(max, range.getMaxAddress());
		}

		public Address getMin() {
			return min;
		}

		public Address getMax() {
			return max;
		}

		public long getLength() {
			return max.subtract(min) + 1;
		}
	}

	public static boolean isReal(MemoryBlock block) {
		return block.isLoaded() && !block.isOverlay() && !block.isExternalBlock();
	}

	public static void addIdentityMapping(Trace from, Program toProgram, Lifespan lifespan,
			boolean truncateExisting) throws TraceConflictedMappingException {
		AddressSet failures = new AddressSet();
		Set<TraceStaticMapping> conflicts = new HashSet<>();
		Map<AddressSpace, Extrema> extremaBySpace = new HashMap<>();
		for (MemoryBlock block : toProgram.getMemory().getBlocks()) {
			if (!isReal(block)) {
				continue;
			}
			AddressRange range = new AddressRangeImpl(block.getStart(), block.getEnd());
			extremaBySpace.computeIfAbsent(range.getAddressSpace(), s -> new Extrema())
					.consider(range);
		}

		for (Extrema extrema : extremaBySpace.values()) {
			AddressRange fromRange =
				clippedRange(from, extrema.getMin().getAddressSpace().getName(),
					extrema.getMin().getOffset(), extrema.getMax().getOffset());
			if (fromRange == null) {
				continue;
			}
			try {
				addMapping(
					new DefaultTraceLocation(from, null, lifespan, fromRange.getMinAddress()),
					new ProgramLocation(toProgram, extrema.getMin()), fromRange.getLength(),
					truncateExisting);
			}
			catch (TraceConflictedMappingException e) {
				failures.add(fromRange);
				conflicts.addAll(e.getConflicts());
				Msg.error(DebuggerStaticMappingUtils.class,
					"Could not add identity mapping " + fromRange + ": " + e.getMessage());
			}
		}
		if (!failures.isEmpty()) {
			throw new TraceConflictedMappingException("Conflicting mappings for " + failures,
				conflicts);
		}
	}

	protected static AddressRange clippedRange(Trace trace, String spaceName, long min,
			long max) {
		AddressSpace space = trace.getBaseAddressFactory().getAddressSpace(spaceName);
		if (space == null) {
			return null;
		}
		Address spaceMax = space.getMaxAddress();
		if (Long.compareUnsigned(min, spaceMax.getOffset()) > 0) {
			return null;
		}
		if (Long.compareUnsigned(max, spaceMax.getOffset()) > 0) {
			return new AddressRangeImpl(space.getAddress(min), spaceMax);
		}
		return new AddressRangeImpl(space.getAddress(min), space.getAddress(max));
	}

	/**
	 * Parse the final file name from the given URL.
	 * 
	 * <p>
	 * This is used when listing the "image" name for mappings, since displaying a full URL would
	 * probably clutter the table. This generally matches the "program name," but in certain cases
	 * may not.
	 * 
	 * @param staticProgramURL the URL of the static program image
	 * @return the piece after the final "/"
	 */
	public static String getImageName(URL staticProgramURL) {
		String[] parts = staticProgramURL.toExternalForm().split("/");
		return parts[parts.length - 1];
	}

	/**
	 * Compute a string suitable for displaying the mapped module names for a given range
	 * 
	 * <p>
	 * Ideally, the entire range is covered by a single mapping entry. In that case, the "image
	 * name" (see {@link #getImageName(URL)}) for that one mapping is returned. If a single mapping
	 * is found, but it only partially covers the given range, an asterisk is appended. If no
	 * mappings are found, the empty string is returned. If multiple mappings are found, they are
	 * each listed alphabetically. No asterisk is displayed in the case of multiple images, since
	 * it's implied that none cover the entire range.
	 * 
	 * @param trace the trace whose mappings to query
	 * @param snap the relevant snapshot
	 * @param range the address range to consider
	 * @return the names of any mapped images
	 */
	public static String computeMappedFiles(Trace trace, long snap, AddressRange range) {
		List<TraceStaticMapping> mappings = List.copyOf(
			trace.getStaticMappingManager().findAllOverlapping(range, Lifespan.at(snap)));
		if (mappings.isEmpty()) {
			return "";
		}
		if (mappings.size() == 1) {
			TraceStaticMapping single = mappings.get(0);
			AddressRange mappedRange = single.getTraceAddressRange();
			if (mappedRange.contains(range.getMinAddress()) &&
				mappedRange.contains(range.getMaxAddress())) {
				return getImageName(single.getStaticProgramURL());
			}
			return getImageName(single.getStaticProgramURL()) + "*";
		}
		/**
		 * Its possible multiple mappings to the same image are at play. This would happen if the
		 * user is mapping by sections instead of modules.
		 */
		List<String> names = mappings.stream()
				.map(m -> getImageName(m.getStaticProgramURL()))
				.sorted()
				.distinct()
				.toList();
		if (names.size() == 1) {
			return names.get(0) + "*";
		}
		return names.stream().collect(Collectors.joining(","));
	}
}
