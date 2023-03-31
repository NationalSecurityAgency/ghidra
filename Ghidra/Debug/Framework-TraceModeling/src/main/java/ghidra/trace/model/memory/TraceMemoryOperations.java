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

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.*;
import ghidra.trace.model.guest.TracePlatform;
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
	TraceMemoryRegion addRegion(String path, Lifespan lifespan, AddressRange range,
			Collection<TraceMemoryFlag> flags)
			throws TraceOverlappedRegionException, DuplicateNameException;

	/**
	 * @see #addRegion(String, Lifespan, AddressRange, Collection)
	 */
	default TraceMemoryRegion addRegion(String path, Lifespan lifespan,
			AddressRange range, TraceMemoryFlag... flags)
			throws TraceOverlappedRegionException, DuplicateNameException {
		return addRegion(path, lifespan, range, Arrays.asList(flags));
	}

	/**
	 * Add a region created at the given snap, with no specified destruction snap
	 * 
	 * @see #addRegion(String, Lifespan, AddressRange, Collection)
	 */
	default TraceMemoryRegion createRegion(String path, long snap, AddressRange range,
			Collection<TraceMemoryFlag> flags)
			throws TraceOverlappedRegionException, DuplicateNameException {
		return addRegion(path, Lifespan.nowOn(snap), range, flags);
	}

	/**
	 * @see #createRegion(String, long, AddressRange, Collection)
	 */
	default TraceMemoryRegion createRegion(String path, long snap, AddressRange range,
			TraceMemoryFlag... flags)
			throws TraceOverlappedRegionException, DuplicateNameException {
		return addRegion(path, Lifespan.nowOn(snap), range, flags);
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
	Collection<? extends TraceMemoryRegion> getRegionsIntersecting(Lifespan lifespan,
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
	 * @param snap the time
	 * @param set the set to examine
	 * @param predicate a predicate on state to search for
	 * @return the address set
	 * @see #getAddressesWithState(Lifespan, AddressSetView, Predicate)
	 */
	default AddressSetView getAddressesWithState(long snap, AddressSetView set,
			Predicate<TraceMemoryState> predicate) {
		return getAddressesWithState(Lifespan.at(snap), set, predicate);
	}

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
	AddressSetView getAddressesWithState(Lifespan span, AddressSetView set,
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
	AddressSetView getAddressesWithState(Lifespan lifespan,
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
	 * Check if a range addresses are all known
	 * 
	 * @param snap the time
	 * @param range the range to examine
	 * @return true if the entire range is {@link TraceMemoryState#KNOWN}
	 */
	default boolean isKnown(long snap, AddressRange range) {
		Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> states = getStates(snap, range);
		if (states.isEmpty()) {
			return false;
		}
		if (states.size() != 1) {
			return false;
		}
		AddressRange entryRange = states.iterator().next().getKey().getRange();
		if (!entryRange.contains(range.getMinAddress()) ||
			!entryRange.contains(range.getMaxAddress())) {
			return false;
		}
		return true;
	}

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
	 * @param snap the time to search
	 * @param range the address range to search
	 * @param data the values to search for
	 * @param mask a mask on the bits of {@code data}; or null to match all bytes exactly
	 * @param forward true to return the match with the lowest address in {@code range}, false for
	 *            the highest address.
	 * @param monitor a monitor for progress reporting and canceling
	 * @return the minimum address of the matched bytes, or {@code null} if not found
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
	 * Find the internal storage block that most-recently defines the value at the given snap and
	 * address, and return the block's snap.
	 * 
	 * <p>
	 * This method reveals portions of the internal storage so that clients can optimize difference
	 * computations by eliminating corresponding ranges defined by the same block. If the underlying
	 * implementation cannot answer this question, this returns the given snap.
	 * 
	 * @param snap the time
	 * @param address the location
	 * @return the most snap for the most recent containing block
	 */
	Long getSnapOfMostRecentChangeToBlock(long snap, Address address);

	/**
	 * Get the block size used by internal storage.
	 * 
	 * <p>
	 * This method reveals portions of the internal storage so that clients can optimize searches.
	 * If the underlying implementation cannot answer this question, this returns 0.
	 * 
	 * @return the block size
	 */
	int getBlockSize();

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

	/**
	 * Set the state of a given register at a given time
	 * 
	 * <p>
	 * Setting state to {@link TraceMemoryState#KNOWN} via this method is not recommended. Setting
	 * bytes will automatically update the state accordingly.
	 * 
	 * @param platform the platform whose language defines the register
	 * @param snap the time
	 * @param register the register
	 * @param state the state
	 */
	void setState(TracePlatform platform, long snap, Register register, TraceMemoryState state);

	/**
	 * Set the state of a given register at a given time
	 * 
	 * <p>
	 * Setting state to {@link TraceMemoryState#KNOWN} via this method is not recommended. Setting
	 * bytes will automatically update the state accordingly.
	 * 
	 * @param snap the time
	 * @param register the register
	 * @param state the state
	 */
	default void setState(long snap, Register register, TraceMemoryState state) {
		setState(getTrace().getPlatformManager().getHostPlatform(), snap, register, state);
	}

	/**
	 * Assert that a register's range has a single state at the given snap and get that state
	 * 
	 * @param platform the platform whose language defines the register
	 * @param snap the time
	 * @param register the register to examine
	 * @return the state
	 * @throws IllegalStateException if the register is mapped to more than one state. See
	 *             {@link #getStates(long, Register)}
	 */
	TraceMemoryState getState(TracePlatform platform, long snap, Register register);

	/**
	 * Assert that a register's range has a single state at the given snap and get that state
	 * 
	 * @param snap the time
	 * @param register the register to examine
	 * @return the state
	 * @throws IllegalStateException if the register is mapped to more than one state. See
	 *             {@link #getStates(long, Register)}
	 */
	default TraceMemoryState getState(long snap, Register register) {
		return getState(getTrace().getPlatformManager().getHostPlatform(), snap, register);
	}

	/**
	 * Break the register's range into smaller ranges each mapped to its state at the given snap
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space.
	 * 
	 * @param platform the platform whose language defines the register
	 * @param snap the time
	 * @param register the register to examine
	 * @return the map of ranges to states
	 */
	Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> getStates(TracePlatform platform,
			long snap, Register register);

	/**
	 * Break the register's range into smaller ranges each mapped to its state at the given snap
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space.
	 * 
	 * @param snap the time
	 * @param register the register to examine
	 * @return the map of ranges to states
	 */
	default Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> getStates(long snap,
			Register register) {
		return getStates(getTrace().getPlatformManager().getHostPlatform(), snap, register);
	}

	/**
	 * @see #setValue(long, RegisterValue)
	 * @param platform the platform whose language defines the register
	 * @param snap the snap
	 * @param value the register value
	 * @return the number of bytes written
	 */
	int setValue(TracePlatform platform, long snap, RegisterValue value);

	/**
	 * Set the value of a register at the given snap
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space. In those
	 * cases, the assignment affects all threads.
	 * 
	 * <p>
	 * <b>IMPORTANT:</b> The trace database cannot track the state ({@link TraceMemoryState#KNOWN},
	 * etc.) with per-bit accuracy. It only has byte precision. If the given value specifies, e.g.,
	 * only a single bit, then the entire byte will become marked {@link TraceMemoryState#KNOWN},
	 * even though the remaining 7 bits could technically be unknown.
	 * 
	 * @param snap the snap
	 * @param value the register value
	 * @return the number of bytes written
	 */
	default int setValue(long snap, RegisterValue value) {
		return setValue(getTrace().getPlatformManager().getHostPlatform(), snap, value);
	}

	/**
	 * @see #putBytes(long, Register, ByteBuffer)
	 * @param platform the platform whose language defines the register
	 * @param snap the snap
	 * @param register the register to modify
	 * @param buf the buffer of bytes to write
	 * @return the number of bytes written
	 */
	int putBytes(TracePlatform platform, long snap, Register register, ByteBuffer buf);

	/**
	 * Write bytes at the given snap and register address
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space. In those
	 * cases, the assignment affects all threads.
	 * 
	 * <p>
	 * Note that bit-masked registers are not properly heeded. If the caller wishes to preserve
	 * non-masked bits, it must first retrieve the current value and combine it with the desired
	 * value. The caller must also account for any bit shift in the passed buffer. Alternatively,
	 * consider {@link #setValue(long, RegisterValue)}.
	 * 
	 * @param snap the snap
	 * @param register the register to modify
	 * @param buf the buffer of bytes to write
	 * @return the number of bytes written
	 */
	default int putBytes(long snap, Register register, ByteBuffer buf) {
		return putBytes(getTrace().getPlatformManager().getHostPlatform(), snap, register, buf);
	}

	/**
	 * Get the most-recent value of a given register at the given time
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space.
	 * 
	 * @param platform the platform whose language defines the register
	 * @param snap the time
	 * @param register the register
	 * @return the value
	 */
	RegisterValue getValue(TracePlatform platform, long snap, Register register);

	/**
	 * Get the most-recent value of a given register at the given time
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space.
	 * 
	 * @param snap the time
	 * @param register the register
	 * @return the value
	 */
	default RegisterValue getValue(long snap, Register register) {
		return getValue(getTrace().getPlatformManager().getHostPlatform(), snap, register);
	}

	/**
	 * Get the most-recent value of a given register at the given time
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space.
	 * 
	 * @param platform the platform whose language defines the register
	 * @param snap the time
	 * @param register the register
	 * @return the value
	 */
	RegisterValue getViewValue(TracePlatform platform, long snap, Register register);

	/**
	 * Get the most-recent value of a given register at the given time, following schedule forks
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space.
	 * 
	 * @param snap the time
	 * @param register the register
	 * @return the value
	 */
	default RegisterValue getViewValue(long snap, Register register) {
		return getViewValue(getTrace().getPlatformManager().getHostPlatform(), snap, register);
	}

	/**
	 * Get the most-recent bytes of a given register at the given time
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space.
	 * 
	 * @param platform the platform whose language defines the register
	 * @param snap the time
	 * @param register the register
	 * @param buf the destination buffer
	 * @return the number of bytes read
	 */
	int getBytes(TracePlatform platform, long snap, Register register, ByteBuffer buf);

	/**
	 * Get the most-recent bytes of a given register at the given time
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space.
	 * 
	 * @param snap the time
	 * @param register the register
	 * @param buf the destination buffer
	 * @return the number of bytes read
	 */
	default int getBytes(long snap, Register register, ByteBuffer buf) {
		return getBytes(getTrace().getPlatformManager().getHostPlatform(), snap, register, buf);
	}

	/**
	 * @see #removeValue(long, Register)
	 * @param platform the platform whose language defines the register
	 * @param snap the snap
	 * @param register the register
	 */
	void removeValue(TracePlatform platform, long snap, Register register);

	/**
	 * Remove a value from the given time and register
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space.
	 * 
	 * <p>
	 * <b>IMPORANT:</b> The trace database cannot track the state ({@link TraceMemoryState#KNOWN},
	 * etc.) with per-bit accuracy. It only has byte precision. If the given register specifies,
	 * e.g., only a single bit, then the entire byte will become marked
	 * {@link TraceMemoryState#UNKNOWN}, even though the remaining 7 bits could technically be
	 * known.
	 * 
	 * @param snap the snap
	 * @param register the register
	 */
	default void removeValue(long snap, Register register) {
		removeValue(getTrace().getPlatformManager().getHostPlatform(), snap, register);
	}
}
