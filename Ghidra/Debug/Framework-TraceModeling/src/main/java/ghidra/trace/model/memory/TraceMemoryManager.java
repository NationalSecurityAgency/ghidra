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

import java.util.Arrays;
import java.util.Collection;
import java.util.Map.Entry;
import java.util.function.Predicate;

import ghidra.program.model.address.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.exception.DuplicateNameException;

/**
 * A store of memory observations over time in a trace
 * 
 * <p>
 * The manager is not bound to any particular address space and may be used to access information
 * about any memory address. For register spaces, you must use
 * {@link #getMemoryRegisterSpace(TraceThread, int, boolean)}.
 */
public interface TraceMemoryManager extends TraceMemoryOperations {

	/**
	 * Create a new address space with the given name based upon the given space
	 * 
	 * <p>
	 * The purpose of overlay spaces in traces is often to store bytes for things other than memory
	 * or registers. Some targets may expose other byte-based storage, or provide alternative views
	 * of memory.
	 * 
	 * <p>
	 * NOTE: This also provides a transitional piece for recording a model (sub)tree directly into a
	 * trace, without mapping to a Ghidra language first. As we experiment with that mode, we will
	 * likely instantiate traces with the "DATA:BE:64:default" language and generate an overlay
	 * space named after the path of each memory being recorded. Of course, the mapping still needs
	 * to occur between the trace and parts of the display and during emulation.
	 * 
	 * <p>
	 * NOTE: We are also moving away from (space, thread, frame) triples to uniquely identify
	 * register storage. Instead, that will be encoded into the address space itself. Register
	 * overlays will overlay register space and be named after the register container object, which
	 * subsumes thread and frame when applicable.
	 * 
	 * @param name the name of the new address space
	 * @param base the space after which this is modeled
	 * @return the create space
	 * @throws DuplicateNameException if an address space with the name already exists
	 */
	AddressSpace createOverlayAddressSpace(String name, AddressSpace base)
			throws DuplicateNameException;

	/**
	 * Get or create an overlay address space
	 * 
	 * <p>
	 * If the space already exists, and it overlays the given base, the existing space is returned.
	 * If it overlays a different space, null is returned. If the space does not exist, it is
	 * created with the given base space.
	 * 
	 * @see #createOverlayAddressSpace(String, AddressSpace)
	 * @param name the name of the address space
	 * @param base the expected base space
	 * @return the space, or null
	 */
	AddressSpace getOrCreateOverlayAddressSpace(String name, AddressSpace base);

	/**
	 * Delete an overlay address space
	 * 
	 * <p>
	 * TODO: At the moment, this will not destroy manager spaces created for the deleted address
	 * space. We should assess this behavior, esp. wrt. re-creating the address space later, and
	 * decide whether or not to clean up.
	 * 
	 * @param name the name of the address space to delete
	 */
	void deleteOverlayAddressSpace(String name);

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
	 */
	TraceMemoryRegion addRegion(String path, Lifespan lifespan, AddressRange range,
			Collection<TraceMemoryFlag> flags) throws TraceOverlappedRegionException;

	/**
	 * @see #addRegion(String, Lifespan, AddressRange, Collection)
	 */
	default TraceMemoryRegion addRegion(String path, Lifespan lifespan,
			AddressRange range, TraceMemoryFlag... flags) throws TraceOverlappedRegionException {
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
	 * Obtain a memory space bound to a particular address space
	 * 
	 * @param space the address space
	 * @param createIfAbsent true to create the space if it's not already present
	 * @return the space, or {@code null} if absent and not created
	 */
	TraceMemorySpace getMemorySpace(AddressSpace space, boolean createIfAbsent);

	/**
	 * Obtain a "memory" space bound to the register address space for a given thread and stack
	 * frame
	 * 
	 * @param thread the given thread
	 * @param frame the "level" of the given stack frame. 0 is the innermost frame.
	 * @param createIfAbsent true to create the space if it's not already present
	 * @return the space, or {@code null} if absent and not created
	 */
	TraceMemorySpace getMemoryRegisterSpace(TraceThread thread, int frame,
			boolean createIfAbsent);

	/**
	 * Obtain a "memory" space bound to the register address space for frame 0 of a given thread
	 * 
	 * @see #getMemoryRegisterSpace(TraceThread, int, boolean)
	 * @param thread the given thread
	 * @param createIfAbsent true to create the space if it's not already present
	 * @return the space, or {@code null} if absent and not created
	 */
	TraceMemorySpace getMemoryRegisterSpace(TraceThread thread, boolean createIfAbsent);

	/**
	 * Obtain a "memory" space bound to the register address space for a stack frame
	 * 
	 * <p>
	 * Note this is simply a convenience, and does not in any way bind the space to the lifespan of
	 * the given frame. Nor, if the frame is moved, will this space move with it.
	 * 
	 * @see #getMemoryRegisterSpace(TraceThread, int, boolean)
	 * @param frame the stack frame
	 * @param createIfAbsent true to create the space if it's not already present
	 * @return the space, or {@code null} if absent and not created
	 */
	TraceMemorySpace getMemoryRegisterSpace(TraceStackFrame frame, boolean createIfAbsent);

	/**
	 * Collect all the state changes between two given snaps
	 * 
	 * @param from the earlier snap
	 * @param to the later snap
	 * @return the collection of state changes
	 */
	Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> getStateChanges(long from, long to);
}
