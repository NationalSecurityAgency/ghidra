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
package ghidra.trace.model.memory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map.Entry;
import java.util.function.Predicate;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.*;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Operations for mutating memory regions, values, and state within a trace
 * 
 * <p>
 * This models memory over the course of an arbitrary number of snaps. The duration between snaps is
 * unspecified. However, the mapping of snaps to real time ought to be strictly monotonic.
 * Observations of memory are recorded using the {@link #putBytes(long, Address, ByteBuffer)} and
 * related methods. Those observations, and some related deductions can be retrieved using the
 * {@link #getBytes(long, Address, ByteBuffer)} and related methods. Many of the {@code get} methods
 * permit the retrieval of the most recent observations. This is useful as an observed value in
 * memory is presumed unchanged until another observation is made. Observations of bytes in memory
 * cause the state at the same location and snap to become {@link TraceMemoryState#KNOWN}. These
 * states can be manipulated directly; however, this is recommended only to record read failures,
 * using the state {@link TraceMemoryState#ERROR}. A state of {@code null} is equivalent to
 * {@link TraceMemoryState#UNKNOWN} and indicates no observation has been made.
 * 
 * <p>
 * Negative snaps may have different semantics than positive, since negative snaps are used as
 * "scratch space". These snaps are not presumed to have any temporal relation to their neighbors,
 * or any other snap for that matter. Clients may use the description field of the
 * {@link TraceSnapshot} to indicate a relationship to another snap. Operations which seek the
 * "most-recent" data might not retrieve anything from scratch snaps, and writing to a scratch snap
 * might not cause any changes to others. Note the "integrity" of data where the memory state is not
 * {@link TraceMemoryState#KNOWN} may be neglected to some extent. For example, writing bytes to
 * snap -10 may cause bytes in snap -9 to change, where the effected range at snap -9 has state
 * {@link TraceMemoryState#UNKNOWN}. The time semantics are not necessarily prohibited in scratch
 * space, but implementations may choose cheaper semantics if desired. Clients should be wary not to
 * accidentally rely on implied temporal relationships in scratch space.
 */
public interface TraceMemoryOperations {
	/**
	 * Get the trace to which the memory manager belongs
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Add a new region with the given properties
	 * 
	 * <p>
	 * Regions model the memory mappings of a debugging target. As such, they are never allowed to
	 * overlap. Additionally, to ensure {@link #getLiveRegionByPath(long, String)} returns a unique
	 * region, duplicate paths cannot exist in the same snap.
	 * 
	 * <p>
	 * Regions have a "full name" (path) as well as a short name. The path is immutable and can be
	 * used to reliably retrieve the same region later. The short name should be something suitable
	 * for display on the screen. Short names are mutable and can be -- but probbaly shouldn't be --
	 * duplicated.
	 * 
	 * @param path the "full name" of the region
	 * @param lifespan the lifespan of the region
	 * @param range the address range of the region
	 * @param flags the flags, e.g., permissions, of the region
	 * @return the newly-added region
	 * @throws TraceOverlappedRegionException if the specified region would overlap an existing one
	 * @throws DuplicateNameException if the specified region has a name which duplicates another at
	 *             any intersecting snap
	 */
	TraceMemoryRegion addRegion(String path, Range<Long> lifespan, AddressRange range,
			Collection<TraceMemoryFlag> flags)
			throws TraceOverlappedRegionException, DuplicateNameException;

	/**
	 * @see #addRegion(String, Range, AddressRange, Collection)
	 */
	default TraceMemoryRegion addRegion(String path, Range<Long> lifespan,
			AddressRange range, TraceMemoryFlag... flags)
			throws TraceOverlappedRegionException, DuplicateNameException {
		return addRegion(path, lifespan, range, Arrays.asList(flags));
	}

	/**
	 * Add a region created at the given snap, with no specified destruction snap
	 * 
	 * @see #addRegion(String, Range, AddressRange, Collection)
	 */
	default TraceMemoryRegion createRegion(String path, long snap, AddressRange range,
			Collection<TraceMemoryFlag> flags)
			throws TraceOverlappedRegionException, DuplicateNameException {
		return addRegion(path, Range.atLeast(snap), range, flags);
	}

	/**
	 * @see #createRegion(String, long, AddressRange, Collection)
	 */
	default TraceMemoryRegion createRegion(String path, long snap, AddressRange range,
			TraceMemoryFlag... flags)
			throws TraceOverlappedRegionException, DuplicateNameException {
		return addRegion(path, Range.atLeast(snap), range, flags);
	}

	/**
	 * Get all the regions in this space or manager
	 * 
	 * @return the collection of all regions
	 */
	Collection<? extends TraceMemoryRegion> getAllRegions();

	/**
	 * Get the region with the given path at the given snap
	 * 
	 * @param snap the snap which must be within the region's lifespan
	 * @param path the "full name" of the region
	 * @return the region, or {@code null} if no region matches
	 */
	TraceMemoryRegion getLiveRegionByPath(long snap, String path);

	/**
	 * Get the region at the given address and snap
	 * 
	 * @param snap the snap which must be within the region's lifespan
	 * @param address the address which must be within the region's range
	 * @return the region, or {@code null} if no region matches
	 */
	TraceMemoryRegion getRegionContaining(long snap, Address address);

	/**
	 * Collect regions intersecting the given lifespan and range
	 * 
	 * @param lifespan the lifespan
	 * @param range the range
	 * @return the collection of matching regions
	 */
	Collection<? extends TraceMemoryRegion> getRegionsIntersecting(Range<Long> lifespan,
			AddressRange range);

	/**
	 * Collect regions at the given snap
	 * 
	 * @param snap the snap which must be within the regions' lifespans
	 * @return the collection of matching regions
	 */
	Collection<? extends TraceMemoryRegion> getRegionsAtSnap(long snap);

	/**
	 * Get the addresses contained by regions at the given snap
	 * 
	 * <p>
	 * The implementation may provide a view that updates with changes.
	 * 
	 * @param snap the snap which must be within the regions' lifespans
	 * @return the union of ranges of matching regions
	 */
	AddressSetView getRegionsAddressSet(long snap);

	/**
	 * Get the addresses contained by regions at the given snap satisfying the given predicate
	 * 
	 * <p>
	 * The implementation may provide a view that updates with changes.
	 * 
	 * @param snap the snap which must be within the region's lifespans
	 * @param predicate a predicate on regions to search for
	 * @return the address set
	 */
	AddressSetView getRegionsAddressSetWith(long snap, Predicate<TraceMemoryRegion> predicate);

	/**
	 * Set the state of memory over a given time and address range
	 * 
	 * <p>
	 * Setting state to {@link TraceMemoryState#KNOWN} via this method is not recommended. Setting
	 * bytes will automatically update the state accordingly.
	 * 
	 * @param snap the time
	 * @param range the range
	 * @param state the state
	 */
	void setState(long snap, AddressRange range, TraceMemoryState state);

	/**
	 * @see #setState(long, AddressRange, TraceMemoryState)
	 */
	void setState(long snap, Address address, TraceMemoryState state);

	/**
	 * @see #setState(long, AddressRange, TraceMemoryState)
	 */
	void setState(long snap, Address start, Address end, TraceMemoryState state);

	/**
	 * Set the state of memory over a given time and address set
	 * 
	 * @see #setState(long, AddressRange, TraceMemoryState)
	 */
	void setState(long snap, AddressSetView set, TraceMemoryState state);

	/**
	 * Get the state of memory at a given snap and address
	 * 
	 * <p>
	 * If the location's state has not been set, the result is {@code null}, which implies
	 * {@link TraceMemoryState#UNKNOWN}.
	 * 
	 * @param snap the time
	 * @param address the location
	 * @return the state
	 */
	TraceMemoryState getState(long snap, Address address);

	/**
	 * Get the state of memory at a given snap and address, following schedule forks
	 * 
	 * @param snap the time
	 * @param address the location
	 * @return the state, and the snap where it was found
	 */
	Entry<Long, TraceMemoryState> getViewState(long snap, Address address);

	/**
	 * Get the entry recording the most recent state at the given snap and address
	 * 
	 * <p>
	 * The entry includes the entire entry at that snap. Parts occluded by more recent snaps are not
	 * subtracted from the entry's address range.
	 * 
	 * @param snap the time
	 * @param address the location
	 * @return the entry including the entire recorded range
	 */
	Entry<TraceAddressSnapRange, TraceMemoryState> getMostRecentStateEntry(long snap,
			Address address);

	/**
	 * Get the entry recording the most recent state at the given snap and address, following
	 * schedule forks
	 * 
	 * @param snap the time
	 * @param address the location
	 * @return the state
	 */
	Entry<TraceAddressSnapRange, TraceMemoryState> getViewMostRecentStateEntry(long snap,
			Address address);

	/**
	 * Get at least the subset of addresses having state satisfying the given predicate
	 * 
	 * <p>
	 * The implementation may provide a larger view than requested, but within the requested set,
	 * only ranges satisfying the predicate may be present. Use
	 * {@link AddressSetView#intersect(AddressSetView)} with {@code set} if a strict subset is
	 * required.
	 * 
	 * <p>
	 * Because {@link TraceMemoryState#UNKNOWN} is not explicitly stored in the map, to compute the
	 * set of {@link TraceMemoryState#UNKNOWN} addresses, use the predicate
	 * {@code state -> state != null && state != TraceMemoryState.UNKNOWN} and subtract the result
	 * from {@code set}.
	 * 
	 * @param snap the time
	 * @param set the set to examine
	 * @param predicate a predicate on state to search for
	 * @return the address set
	 */
	AddressSetView getAddressesWithState(long snap, AddressSetView set,
			Predicate<TraceMemoryState> predicate);

	/**
	 * Get the addresses having state satisfying the given predicate
	 * 
	 * <p>
	 * The implementation may provide a view that updates with changes. Behavior is not well defined
	 * for predicates testing for {@link TraceMemoryState#UNKNOWN}.
	 * 
	 * @param snap the time
	 * @param predicate a predicate on state to search for
	 * @return the address set
	 */
	AddressSetView getAddressesWithState(long snap, Predicate<TraceMemoryState> predicate);

	/**
	 * Get the addresses having state satisfying the given predicate at any time in the specified
	 * lifespan
	 * 
	 * <p>
	 * The implementation may provide a view that updates with changes. Behavior is not well defined
	 * for predicates testing for {@link TraceMemoryState#UNKNOWN} .
	 * 
	 * @param lifespan the span of time
	 * @param predicate a predicate on state to search for
	 * @return the address set
	 */
	AddressSetView getAddressesWithState(Range<Long> lifespan,
			Predicate<TraceMemoryState> predicate);

	/**
	 * Break a range of addresses into smaller ranges each mapped to its state at the given snap
	 * 
	 * <p>
	 * Note that {@link TraceMemoryState#UNKNOWN} entries will not appear in the result. Gaps in the
	 * returned entries are implied to be {@link TraceMemoryState#UNKNOWN}.
	 * 
	 * @param snap the time
	 * @param range the range to examine
	 * @return the map of ranges to states
	 */
	Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> getStates(long snap,
			AddressRange range);

	/**
	 * Break a range of addresses into smaller ranges each mapped to its most recent state at the
	 * given time
	 * 
	 * <p>
	 * Typically {@code within} is the box whose width is the address range to break down and whose
	 * height is from "negative infinity" to the "current" snap.
	 * 
	 * <p>
	 * In this context, "most recent" means the latest state other than
	 * {@link TraceMemoryState#UNKNOWN}.
	 * 
	 * @param within a box intersecting entries to consider
	 * @return an iterable over the snap ranges and states
	 */
	Iterable<Entry<TraceAddressSnapRange, TraceMemoryState>> getMostRecentStates(
			TraceAddressSnapRange within);

	/**
	 * @see #getMostRecentStates(TraceAddressSnapRange)
	 */
	default Iterable<Entry<TraceAddressSnapRange, TraceMemoryState>> getMostRecentStates(long snap,
			AddressRange range) {
		return getMostRecentStates(new ImmutableTraceAddressSnapRange(range.getMinAddress(),
			range.getMaxAddress(), Long.MIN_VALUE, snap));
	}

	/**
	 * Write bytes at the given snap and address
	 * 
	 * <p>
	 * This will attempt to read {@link ByteBuffer#remaining()} bytes starting at
	 * {@link ByteBuffer#position()} from the source buffer {@code buf} and write them into memory
	 * at the specified time and location. The affected region is also updated to
	 * {@link TraceMemoryState#KNOWN}. The written bytes are assumed effective for all future snaps
	 * up to the next write.
	 * 
	 * @param snap the time
	 * @param start the location
	 * @param buf the source buffer of bytes
	 * @return the number of bytes written
	 */
	int putBytes(long snap, Address start, ByteBuffer buf);

	/**
	 * Read the most recent bytes from the given snap and address
	 * 
	 * <p>
	 * This will attempt to read {@link ByteBuffer#remaining()} of the most recent bytes from memory
	 * at the specified time and location and write them into the destination buffer {@code buf}
	 * starting at {@link ByteBuffer#position()}. Where bytes in memory have no defined value,
	 * values in the destination buffer are unspecified. The implementation may leave those bytes in
	 * the destination buffer unmodified, or it may write zeroes.
	 * 
	 * @param snap the time
	 * @param start the location
	 * @param buf the destination buffer of bytes
	 * @return the number of bytes read
	 */
	int getBytes(long snap, Address start, ByteBuffer buf);

	/**
	 * Read the most recent bytes from the given snap and address, following schedule forks
	 * 
	 * <p>
	 * This behaves similarly to {@link #getBytes(long, Address, ByteBuffer)}, except it checks for
	 * the {@link TraceMemoryState#KNOWN} state among each involved snap range and reads the
	 * applicable address ranges, preferring the most recent. Where memory is never known the buffer
	 * is left unmodified.
	 * 
	 * @param snap the time
	 * @param start the location
	 * @param buf the destination buffer of bytes
	 * @return the number of bytes read
	 */
	int getViewBytes(long snap, Address start, ByteBuffer buf);

	/**
	 * Search the given address range at the given snap for a given byte pattern
	 * 
	 * <p>
	 * TODO: Implement me
	 * 
	 * @param snap the time to search
	 * @param range the address range to search
	 * @param data the values to search for
	 * @param mask a mask on the bits of {@code data}; or null to match all bytes exactly
	 * @param forward true to return the match with the lowest address in {@code range}, false for
	 *            the highest address.
	 * @param monitor a monitor for progress reporting and canceling
	 * @return the address of the match, or {@code null} if not found
	 */
	Address findBytes(long snap, AddressRange range, ByteBuffer data, ByteBuffer mask,
			boolean forward, TaskMonitor monitor);

	/**
	 * Remove bytes from the given time and location
	 * 
	 * <p>
	 * This deletes all observed bytes from the given address through length at the given snap. If
	 * there were no observations in the range at exactly the given snap, this has no effect. If
	 * there were, then those observations are removed. The next time those bytes are read, they
	 * will have a value from a previous snap, or no value at all. The affected region's state is
	 * also deleted, i.e., set to {@code null}, implying {@link TraceMemoryState#UNKNOWN}.
	 * 
	 * <p>
	 * Note, use of this method is discouraged. The more observations within the same range that
	 * follow the deleted observation, the more expensive this operation typically is, since all of
	 * those observations may need to be updated.
	 * 
	 * @param snap the time
	 * @param start the location
	 * @param len the number of bytes to remove
	 */
	void removeBytes(long snap, Address start, int len);

	/**
	 * Get a view of a particular snap as a memory buffer
	 * 
	 * <p>
	 * The bytes read by this buffer are the most recent bytes written before the given snap
	 * 
	 * @param snap the snap
	 * @param start the starting address
	 * @param byteOrder the byte ordering for this buffer
	 * @return the memory buffer
	 */
	MemBuffer getBufferAt(long snap, Address start, ByteOrder byteOrder);

	/**
	 * Get a view of a particular snap as a memory buffer using the base language's byte order
	 * 
	 * @see #getBufferAt(long, Address, ByteOrder)
	 */
	default MemBuffer getBufferAt(long snap, Address start) {
		return getBufferAt(snap, start,
			getTrace().getBaseLanguage().isBigEndian() ? ByteOrder.BIG_ENDIAN
					: ByteOrder.LITTLE_ENDIAN);
	}

	/**
	 * Optimize storage space
	 * 
	 * <p>
	 * This gives the implementation an opportunity to clean up garbage, apply compression, etc., in
	 * order to best use the storage space. Because memory observations can be sparse, a trace's
	 * memory is often compressible, and observations are not often modified or deleted, packing is
	 * recommended whenever the trace is saved to disk.
	 */
	void pack();
}
