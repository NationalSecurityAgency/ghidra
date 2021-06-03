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

import java.util.*;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceObject;
import ghidra.util.exception.DuplicateNameException;

/**
 * A region of mapped target memory in a trace
 */
public interface TraceMemoryRegion extends TraceObject {

	/**
	 * Get the trace containing this region
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the "full name" of this region
	 * 
	 * <p>
	 * This is a unique key (within any snap) for retrieving the region, and may not be suitable for
	 * display on the screen.
	 * 
	 * @return the path
	 */
	String getPath();

	/**
	 * Set the "short name" of this region
	 * 
	 * <p>
	 * The given name should be suitable for display on the screen.
	 * 
	 * @param name the name
	 */
	void setName(String name);

	/**
	 * Get the "short name" of this region
	 * 
	 * <p>
	 * This defaults to the "full name," but can be modified via {@link #setName(String)}
	 * 
	 * @return the name
	 */
	String getName();

	/**
	 * Change the lifespan of this region
	 * 
	 * @param lifespan the new lifespan
	 * @throws TraceOverlappedRegionException if the specified lifespan would cause this region to
	 *             overlap another
	 * @throws DuplicateNameException if the specified lifespan would cause the full name of this
	 *             region to conflict with that of another whose lifespan would intersects this
	 *             region's
	 */
	void setLifespan(Range<Long> lifespan)
			throws TraceOverlappedRegionException, DuplicateNameException;

	/**
	 * Get the lifespan of this region
	 * 
	 * @return the lifespan
	 */
	Range<Long> getLifespan();

	/**
	 * @see #setLifespan(Range)
	 * 
	 * @param creationSnap the creation snap, or {@link Long#MIN_VALUE} for "since the beginning of
	 *            time"
	 */
	void setCreationSnap(long creationSnap)
			throws DuplicateNameException, TraceOverlappedRegionException;

	/**
	 * Get the creation snap of this region
	 * 
	 * @return the creation snap, or {@link Long#MIN_VALUE} for "since the beginning of time"
	 */
	long getCreationSnap();

	/**
	 * @see #setLifespan(Range)
	 * 
	 * @param destructionSnap the destruction snap, or {@link Long#MAX_VALUE} for "to the end of
	 *            time"
	 */
	void setDestructionSnap(long destructionSnap)
			throws DuplicateNameException, TraceOverlappedRegionException;

	/**
	 * @see #getLifespan()
	 * 
	 * @return the destruction snap, or {@link Long#MAX_VALUE} for "to the end of time"
	 */
	long getDestructionSnap();

	/**
	 * Set the virtual memory address range of this region
	 * 
	 * <p>
	 * The addresses in the range should be those the target's CPU would use to access the region,
	 * i.e., the virtual memory address if an MMU is involved, or the physical address if no MMU is
	 * involved.
	 * 
	 * @param range the address range
	 * @throws TraceOverlappedRegionException if the specified range would cause this region to
	 *             overlap another
	 */
	void setRange(AddressRange range) throws TraceOverlappedRegionException;

	/**
	 * Get the virtual memory address range of this region
	 * 
	 * @return the address range
	 */
	AddressRange getRange();

	/**
	 * @see #setRange(AddressRange)
	 */
	void setMinAddress(Address min) throws TraceOverlappedRegionException;

	/**
	 * @see #getRange()
	 */
	Address getMinAddress();

	/**
	 * @see #setRange(AddressRange)
	 */
	void setMaxAddress(Address max) throws TraceOverlappedRegionException;

	/**
	 * @see #getRange()
	 */
	Address getMaxAddress();

	/**
	 * Set the length, in bytes, of this region's address range
	 * 
	 * <p>
	 * This adjusts the max address of the range so that its length becomes that given
	 * 
	 * @see #setRange(AddressRange)
	 */
	void setLength(long length) throws AddressOverflowException, TraceOverlappedRegionException;

	/**
	 * Measure the length, in bytes, of this region's address range
	 * 
	 * @return the length
	 */
	long getLength();

	/**
	 * Set the flags, e.g., permissions, of this region
	 * 
	 * @param flags the flags
	 */
	void setFlags(Collection<TraceMemoryFlag> flags);

	/**
	 * @see #setFlags(Collection)
	 */
	default void setFlags(TraceMemoryFlag... flags) {
		setFlags(Arrays.asList(flags));
	}

	/**
	 * Add the given flags, e.g., permissions, to this region
	 * 
	 * @see #setFlags(Collection)
	 */
	void addFlags(Collection<TraceMemoryFlag> flags);

	/**
	 * @see #addFlags(Collection)
	 */
	default void addFlags(TraceMemoryFlag... flags) {
		addFlags(Arrays.asList(flags));
	}

	/**
	 * Remove the given flags, e.g., permissions, from this region
	 * 
	 * @see #setFlags(Collection)
	 */
	void clearFlags(Collection<TraceMemoryFlag> flags);

	/**
	 * @see #clearFlags(Collection)
	 */
	default void clearFlags(TraceMemoryFlag... flags) {
		clearFlags(Arrays.asList(flags));
	}

	/**
	 * Get the flags, e.g., permissions, of this region
	 * 
	 * @return the flags
	 */
	Set<TraceMemoryFlag> getFlags();

	/**
	 * Add or clear the {@link TraceMemoryFlag#READ} flag
	 * 
	 * @param read true to add, false to clear
	 */
	default void setRead(boolean read) {
		if (read) {
			addFlags(TraceMemoryFlag.READ);
		}
		else {
			clearFlags(TraceMemoryFlag.READ);
		}
	}

	/**
	 * Check if the {@link TraceMemoryFlag#READ} flag is present
	 * 
	 * @return true if present, false if absent
	 */
	default boolean isRead() {
		return getFlags().contains(TraceMemoryFlag.READ);
	}

	/**
	 * Add or clear the {@link TraceMemoryFlag#WRITE} flag
	 * 
	 * @param read true to add, false to clear
	 */
	default void setWrite(boolean write) {
		if (write) {
			addFlags(TraceMemoryFlag.WRITE);
		}
		else {
			clearFlags(TraceMemoryFlag.WRITE);
		}
	}

	/**
	 * Check if the {@link TraceMemoryFlag#WRITE} flag is present
	 * 
	 * @return true if present, false if absent
	 */
	default boolean isWrite() {
		return getFlags().contains(TraceMemoryFlag.WRITE);
	}

	/**
	 * Add or clear the {@link TraceMemoryFlag#EXECUTE} flag
	 * 
	 * @param read true to add, false to clear
	 */
	default void setExecute(boolean execute) {
		if (execute) {
			addFlags(TraceMemoryFlag.EXECUTE);
		}
		else {
			clearFlags(TraceMemoryFlag.EXECUTE);
		}
	}

	/**
	 * Check if the {@link TraceMemoryFlag#EXECUTE} flag is present
	 * 
	 * @return true if present, false if absent
	 */
	default boolean isExecute() {
		return getFlags().contains(TraceMemoryFlag.EXECUTE);
	}

	/**
	 * Add or clear the {@link TraceMemoryFlag#VOLATILE} flag
	 * 
	 * @param read true to add, false to clear
	 */
	default void setVolatile(boolean vol) {
		if (vol) {
			addFlags(TraceMemoryFlag.VOLATILE);
		}
		else {
			clearFlags(TraceMemoryFlag.VOLATILE);
		}
	}

	/**
	 * Check if the {@link TraceMemoryFlag#VOLATILE} flag is present
	 * 
	 * @return true if present, false if absent
	 */
	default boolean isVolatile() {
		return getFlags().contains(TraceMemoryFlag.VOLATILE);
	}

	/**
	 * Delete this region from the trace
	 */
	void delete();
}
