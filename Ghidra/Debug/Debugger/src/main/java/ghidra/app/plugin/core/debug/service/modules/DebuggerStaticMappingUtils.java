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

import java.io.IOException;
import java.net.URL;
import java.util.*;

import com.google.common.collect.Range;

import ghidra.app.plugin.core.debug.utils.ProgramURLUtils;
import ghidra.app.services.MapEntry;
import ghidra.framework.data.OpenedDomainFile;
import ghidra.framework.model.*;
import ghidra.framework.store.FileSystem;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.*;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public enum DebuggerStaticMappingUtils {
	;

	protected static <T> T noProject(Object originator) {
		Msg.warn(originator, "The given program does not exist in any project");
		return null;
	}

	public static DomainFile resolve(DomainFolder folder, String path) {
		StringBuilder fullPath = new StringBuilder(folder.getPathname());
		if (!fullPath.toString().endsWith(FileSystem.SEPARATOR)) {
			// Only root should end with /, anyway
			fullPath.append(FileSystem.SEPARATOR_CHAR);
		}
		fullPath.append(path);
		return folder.getProjectData().getFile(fullPath.toString());
	}

	public static Set<DomainFile> findPrograms(String modulePath, DomainFolder folder) {
		// TODO: If not found, consider filenames with space + extra info
		while (folder != null) {
			DomainFile found = resolve(folder, modulePath);
			if (found != null) {
				return Set.of(found);
			}
			folder = folder.getParent();
		}
		return Set.of();
	}

	public static Set<DomainFile> findProgramsByPathOrName(String modulePath,
			DomainFolder folder) {
		Set<DomainFile> found = findPrograms(modulePath, folder);
		if (!found.isEmpty()) {
			return found;
		}
		int idx = modulePath.lastIndexOf(FileSystem.SEPARATOR);
		if (idx == -1) {
			return Set.of();
		}
		found = findPrograms(modulePath.substring(idx + 1), folder);
		if (!found.isEmpty()) {
			return found;
		}
		return Set.of();
	}

	public static Set<DomainFile> findProgramsByPathOrName(String modulePath, Project project) {
		return findProgramsByPathOrName(modulePath, project.getProjectData().getRootFolder());
	}

	protected static String normalizePath(String path) {
		path = path.replace('\\', FileSystem.SEPARATOR_CHAR);
		while (path.startsWith(FileSystem.SEPARATOR)) {
			path = path.substring(1);
		}
		return path;
	}

	public static Set<DomainFile> findProbableModulePrograms(TraceModule module, Project project) {
		// TODO: Consider folders containing existing mapping destinations
		DomainFile df = module.getTrace().getDomainFile();
		String modulePath = normalizePath(module.getName());
		if (df == null) {
			return findProgramsByPathOrName(modulePath, project);
		}
		DomainFolder parent = df.getParent();
		if (parent == null) {
			return findProgramsByPathOrName(modulePath, project);
		}
		return findProgramsByPathOrName(modulePath, parent);
	}

	protected static void collectLibraries(ProjectData project, Program cur, Set<Program> col,
			TaskMonitor monitor) throws CancelledException {
		if (!col.add(cur)) {
			return;
		}
		ExternalManager externs = cur.getExternalManager();
		for (String extName : externs.getExternalLibraryNames()) {
			monitor.checkCanceled();
			Library lib = externs.getExternalLibrary(extName);
			String libPath = lib.getAssociatedProgramPath();
			if (libPath == null) {
				continue;
			}
			DomainFile libFile = project.getFile(libPath);
			if (libFile == null) {
				Msg.info(DebuggerStaticMappingUtils.class,
					"Referenced external program not found: " + libPath);
				continue;
			}
			try (OpenedDomainFile<Program> program =
				OpenedDomainFile.open(Program.class, libFile, monitor)) {
				collectLibraries(project, program.content, col, monitor);
			}
			catch (ClassCastException e) {
				Msg.info(DebuggerStaticMappingUtils.class,
					"Referenced external program is not a program: " + libPath + " is " +
						libFile.getDomainObjectClass());
				continue;
			}
			catch (VersionException | CancelledException | IOException e) {
				Msg.info(DebuggerStaticMappingUtils.class,
					"Referenced external program could not be opened: " + e);
				continue;
			}
		}
	}

	/**
	 * Recursively collect external programs, i.e., libraries, starting at the given seed
	 * 
	 * @param seed the seed, usually the executable
	 * @param monitor a monitor to cancel the process
	 * @return the set of found programs, including the seed
	 * @throws CancelledException if cancelled by the monitor
	 */
	public static Set<Program> collectLibraries(Program seed, TaskMonitor monitor)
			throws CancelledException {
		Set<Program> result = new LinkedHashSet<>();
		collectLibraries(seed.getDomainFile().getParent().getProjectData(), seed, result,
			monitor);
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
		Range<Long> fromLifespan = from.getLifespan();
		if (truncateExisting) {
			long truncEnd = DBTraceUtils.lowerEndpoint(fromLifespan) - 1;
			for (TraceStaticMapping existing : List
					.copyOf(manager.findAllOverlapping(range, fromLifespan))) {
				existing.delete();
				if (fromLifespan.hasLowerBound() &&
					Long.compare(existing.getStartSnap(), truncEnd) <= 0) {
					manager.add(existing.getTraceAddressRange(),
						Range.closed(existing.getStartSnap(), truncEnd),
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

	public static void addIdentityMapping(Trace from, Program toProgram, Range<Long> lifespan,
			boolean truncateExisting) {
		Map<String, Address> mins = new HashMap<>();
		Map<String, Address> maxs = new HashMap<>();
		for (AddressRange range : toProgram.getMemory().getAddressRanges()) {
			mins.compute(range.getAddressSpace().getName(), (n, min) -> {
				Address can = range.getMinAddress();
				if (min == null || can.compareTo(min) < 0) {
					return can;
				}
				return min;
			});
			maxs.compute(range.getAddressSpace().getName(), (n, max) -> {
				Address can = range.getMaxAddress();
				if (max == null || can.compareTo(max) > 0) {
					return can;
				}
				return max;
			});
		}
		for (String name : mins.keySet()) {
			AddressRange range = clippedRange(from, name, mins.get(name).getOffset(),
				maxs.get(name).getOffset());
			if (range == null) {
				continue;
			}
			try {
				addMapping(new DefaultTraceLocation(from, null, lifespan, range.getMinAddress()),
					new ProgramLocation(toProgram, mins.get(name)), range.getLength(),
					truncateExisting);
			}
			catch (TraceConflictedMappingException e) {
				Msg.error(DebuggerStaticMappingUtils.class,
					"Could not add identity mapping " + range + ": " + e.getMessage());
			}
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
}
