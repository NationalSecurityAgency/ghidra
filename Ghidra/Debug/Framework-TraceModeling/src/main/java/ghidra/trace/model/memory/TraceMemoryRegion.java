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

import ghidra.program.model.address.*;
import ghidra.trace.model.*;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInfo;

/**
 * A region of mapped target memory in a trace
 */

@TraceObjectInfo(
	schemaName = "MemoryRegion",
	shortName = "region",
	attributes = {
		TraceMemoryRegion.KEY_RANGE,
		TraceMemoryRegion.KEY_READABLE,
		TraceMemoryRegion.KEY_WRITABLE,
		TraceMemoryRegion.KEY_EXECUTABLE,
		TraceMemoryRegion.KEY_VOLATILE,
	},
	fixedKeys = {
		TraceObjectInterface.KEY_DISPLAY,
		TraceMemoryRegion.KEY_RANGE,
	})
public interface TraceMemoryRegion extends TraceUniqueObject, TraceObjectInterface {
	String KEY_RANGE = "_range";
	String KEY_READABLE = "_readable";
	String KEY_WRITABLE = "_writable";
	String KEY_EXECUTABLE = "_executable";
	String KEY_VOLATILE = "_volatile";

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
	 * @param lifespan the span of time
	 * @param name the name
	 */
	void setName(Lifespan lifespan, String name);

	/**
	 * Set the "short name" of this region
	 * 
	 * <p>
	 * The given name should be suitable for display on the screen.
	 * 
	 * @param snap the snap
	 * @param name the name
	 */
	void setName(long snap, String name);

	/**
	 * Get the "short name" of this region
	 * 
	 * <p>
	 * This defaults to the "full name," but can be modified via {@link #setName(long, String)}
	 * 
	 * @param snap the snap
	 * @return the name
	 */
	String getName(long snap);

	/**
	 * Set the virtual memory address range of this region
	 * 
	 * <p>
	 * The addresses in the range should be those the target's CPU would use to access the region,
	 * i.e., the virtual memory address if an MMU is involved, or the physical address if no MMU is
	 * involved.
	 * 
	 * @param lifespan the span of time
	 * @param range the address range
	 */
	void setRange(Lifespan lifespan, AddressRange range);

	/**
	 * Set the virtual memory address range of this region
	 * 
	 * <p>
	 * The addresses in the range should be those the target's CPU would use to access the region,
	 * i.e., the virtual memory address if an MMU is involved, or the physical address if no MMU is
	 * involved.
	 * 
	 * @param snap the snap
	 * @param range the address range
	 * @throws TraceOverlappedRegionException if the specified range would cause this region to
	 *             overlap another
	 */
	void setRange(long snap, AddressRange range) throws TraceOverlappedRegionException;

	/**
	 * Get the virtual memory address range of this region
	 * 
	 * @param snap the snap
	 * @return the address range
	 */
	AddressRange getRange(long snap);

	/**
	 * Set the minimum address of the range
	 * 
	 * <p>
	 * Note that this sets the range from the given snap on to the same range, no matter what
	 * changes may have occurred since.
	 * 
	 * @see #setRange(long, AddressRange)
	 * @param snap the snap
	 * @param min the new minimum
	 * @throws TraceOverlappedRegionException if extending the region would cause it to overlap
	 *             another
	 */
	void setMinAddress(long snap, Address min) throws TraceOverlappedRegionException;

	/**
	 * Get the minimum address of the range
	 * 
	 * @see #getRange(long)
	 * @param snap the snap
	 * @return the minimum address
	 */
	Address getMinAddress(long snap);

	/**
	 * Set the maximum address of the range
	 * 
	 * <p>
	 * Note that this sets the range from the given snap on to the same range, no matter what
	 * changes may have occurred since.
	 * 
	 * @see #setRange(long, AddressRange)
	 * @param snap the snap
	 * @param max the new minimum
	 * @throws TraceOverlappedRegionException if extending the region would cause it to overlap
	 *             another
	 */
	void setMaxAddress(long snap, Address max) throws TraceOverlappedRegionException;

	/**
	 * Get the maximum address of the range
	 * 
	 * @see #getRange(long)
	 * @param snap the snap
	 * @return the maximum address
	 */
	Address getMaxAddress(long snap);

	/**
	 * Set the length, in bytes, of this region's address range
	 * 
	 * <p>
	 * This adjusts the max address of the range so that its length becomes that given. Note that
	 * this sets the range from the given snap on to the same range, no matter what changes may have
	 * occurred since.
	 * 
	 * @see #setRange(long, AddressRange)
	 * @param snap the snap
	 * @param length the desired length of the range
	 * @throws AddressOverflowException if extending the range would cause the max address to
	 *             overflow
	 * @throws TraceOverlappedRegionException if extending the region would cause it to overlap
	 *             another
	 */
	void setLength(long snap, long length)
			throws AddressOverflowException, TraceOverlappedRegionException;

	/**
	 * Measure the length, in bytes, of this region's address range
	 * 
	 * @param snap the snap
	 * @return the length
	 */
	long getLength(long snap);

	/**
	 * Set the flags, e.g., permissions, of this region
	 * 
	 * @param lifespan the span of time
	 * @param flags the flags
	 */
	void setFlags(Lifespan lifespan, Collection<TraceMemoryFlag> flags);

	/**
	 * Set the flags, e.g., permissions, of this region
	 * 
	 * @param snap the snap
	 * @param flags the flags
	 */
	void setFlags(long snap, Collection<TraceMemoryFlag> flags);

	/**
	 * Set the flags, e.g., permissions, of this region
	 * 
	 * @param snap the snap
	 * @param flags the flags
	 */
	default void setFlags(long snap, TraceMemoryFlag... flags) {
		setFlags(snap, Arrays.asList(flags));
	}

	/**
	 * Add the given flags, e.g., permissions, to this region
	 * 
	 * @param lifespan the span of time
	 * @param flags the flags
	 */
	void addFlags(Lifespan lifespan, Collection<TraceMemoryFlag> flags);

	/**
	 * Add the given flags, e.g., permissions, to this region
	 * 
	 * @param snap the snap
	 * @param flags the flags
	 */
	void addFlags(long snap, Collection<TraceMemoryFlag> flags);

	/**
	 * Add the given flags, e.g., permissions, to this region
	 * 
	 * @param snap the snap
	 * @param flags the flags
	 */
	default void addFlags(long snap, TraceMemoryFlag... flags) {
		addFlags(snap, Arrays.asList(flags));
	}

	/**
	 * Remove the given flags, e.g., permissions, from this region
	 * 
	 * @param lifespan the span of time
	 * @param flags the flags
	 */
	void clearFlags(Lifespan lifespan, Collection<TraceMemoryFlag> flags);

	/**
	 * Remove the given flags, e.g., permissions, from this region
	 * 
	 * @param snap the snap
	 * @param flags the flags
	 */
	void clearFlags(long snap, Collection<TraceMemoryFlag> flags);

	/**
	 * Remove the given flags, e.g., permissions, from this region
	 * 
	 * @param snap the snap
	 * @param flags the flags
	 */
	default void clearFlags(long snap, TraceMemoryFlag... flags) {
		clearFlags(snap, Arrays.asList(flags));
	}

	/**
	 * Get the flags, e.g., permissions, of this region
	 * 
	 * @param snap the snap
	 * @return the flags
	 */
	Set<TraceMemoryFlag> getFlags(long snap);

	/**
	 * Add or clear the {@link TraceMemoryFlag#READ} flag
	 * 
	 * @param snap the snap
	 * @param read true to add, false to clear
	 */
	default void setRead(long snap, boolean read) {
		if (read) {
			addFlags(snap, TraceMemoryFlag.READ);
		}
		else {
			clearFlags(snap, TraceMemoryFlag.READ);
		}
	}

	/**
	 * Check if the {@link TraceMemoryFlag#READ} flag is present
	 * 
	 * @param snap the snap
	 * @return true if present, false if absent
	 */
	default boolean isRead(long snap) {
		return getFlags(snap).contains(TraceMemoryFlag.READ);
	}

	/**
	 * Add or clear the {@link TraceMemoryFlag#WRITE} flag
	 * 
	 * @param snap the snap
	 * @param write true to add, false to clear
	 */
	default void setWrite(long snap, boolean write) {
		if (write) {
			addFlags(snap, TraceMemoryFlag.WRITE);
		}
		else {
			clearFlags(snap, TraceMemoryFlag.WRITE);
		}
	}

	/**
	 * Check if the {@link TraceMemoryFlag#WRITE} flag is present
	 * 
	 * @param snap the snap
	 * @return true if present, false if absent
	 */
	default boolean isWrite(long snap) {
		return getFlags(snap).contains(TraceMemoryFlag.WRITE);
	}

	/**
	 * Add or clear the {@link TraceMemoryFlag#EXECUTE} flag
	 * 
	 * @param snap the snap
	 * @param execute true to add, false to clear
	 */
	default void setExecute(long snap, boolean execute) {
		if (execute) {
			addFlags(snap, TraceMemoryFlag.EXECUTE);
		}
		else {
			clearFlags(snap, TraceMemoryFlag.EXECUTE);
		}
	}

	/**
	 * Check if the {@link TraceMemoryFlag#EXECUTE} flag is present
	 * 
	 * @param snap the snap
	 * @return true if present, false if absent
	 */
	default boolean isExecute(long snap) {
		return getFlags(snap).contains(TraceMemoryFlag.EXECUTE);
	}

	/**
	 * Add or clear the {@link TraceMemoryFlag#VOLATILE} flag
	 * 
	 * @param snap the snap
	 * @param vol true to add, false to clear
	 */
	default void setVolatile(long snap, boolean vol) {
		if (vol) {
			addFlags(snap, TraceMemoryFlag.VOLATILE);
		}
		else {
			clearFlags(snap, TraceMemoryFlag.VOLATILE);
		}
	}

	/**
	 * Check if the {@link TraceMemoryFlag#VOLATILE} flag is present
	 * 
	 * @param snap the snap
	 * @return true if present, false if absent
	 */
	default boolean isVolatile(long snap) {
		return getFlags(snap).contains(TraceMemoryFlag.VOLATILE);
	}

	/**
	 * Delete this region from the trace
	 */
	void delete();

	/**
	 * Remove this region from the given snap on
	 * 
	 * @param snap
	 */
	void remove(long snap);

	/**
	 * Check if the region is valid at the given snapshot
	 * 
	 * <p>
	 * In object mode, a region's life may be disjoint, so checking if the snap occurs between
	 * creation and destruction is not quite sufficient. This method encapsulates validity. In
	 * object mode, it checks that the region object has a canonical parent at the given snapshot.
	 * In table mode, it checks that the lifespan contains the snap.
	 * 
	 * @param snap the snapshot key
	 * @return true if valid, false if not
	 */
	boolean isValid(long snap);
}
