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
package ghidra.pcode.emu.taint.trace;

import java.util.Map.Entry;

import com.google.common.collect.Range;

import ghidra.pcode.emu.taint.full.TaintDebuggerSpace;
import ghidra.pcode.emu.taint.plain.TaintSpace;
import ghidra.pcode.exec.trace.TracePcodeExecutorState;
import ghidra.program.model.address.*;
import ghidra.taint.model.TaintSet;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.Trace;
import ghidra.trace.model.property.TracePropertyMap;
import ghidra.trace.model.property.TracePropertyMapSpace;
import ghidra.trace.model.thread.TraceThread;

/**
 * The storage space for taint sets in a trace's address space
 * 
 * <p>
 * This adds to {@link TaintSpace} the ability to load taint sets from a trace and the ability to
 * save them back into a trace.
 */
public class TaintTraceSpace extends TaintSpace {
	protected final AddressSpace space;
	protected final TracePropertyMapSpace<String> backing;
	protected final long snap;

	/**
	 * Create the space
	 * 
	 * @param space the address space
	 * @param backing if present, the backing object
	 * @param snap the source snap
	 */
	public TaintTraceSpace(AddressSpace space, TracePropertyMapSpace<String> backing, long snap) {
		this.space = space;
		this.backing = backing;
		this.snap = snap;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * The taint space will call this when the cache misses, allowing us to populate it with a taint
	 * set stored in the trace. Note that if the emulator writes to this offset <em>before</em>
	 * reading it, this will not get called for that offset. Here we simply load the string property
	 * from the map and parse the taint set. We'll also introduce a second extension point for when
	 * neither the cache nor the trace have a taint set.
	 */
	@Override
	protected TaintSet whenNull(long offset) {
		if (backing == null) {
			return whenTraceNull(offset);
		}
		String string = backing.get(snap, space.getAddress(offset));
		if (string == null) {
			return whenTraceNull(offset);
		}
		return TaintSet.parse(string);
	}

	/**
	 * Extension point: Behavior when there is neither an in-memory nor a trace-stored taint set at
	 * the given offset
	 * 
	 * <p>
	 * This will be overridden by {@link TaintDebuggerSpace} to implement loading from static mapped
	 * programs.
	 * 
	 * @param offset the offset
	 * @return the taint set to use
	 */
	protected TaintSet whenTraceNull(long offset) {
		return TaintSet.EMPTY;
	}

	/**
	 * Write this cache back down into a trace
	 * 
	 * <p>
	 * Here we simply iterate over every entry in this space, serialize the taint, and store it into
	 * the property map at the entry's offset. Because a backing object may not have existed when
	 * creating this space, we must re-fetch the backing object, creating it if it does not exist.
	 * We can safely create such spaces, since the client is required to have an open transaction on
	 * the destination trace while invoking this method (via
	 * {@link TracePcodeExecutorState#writeDown(Trace, long, TraceThread, int)}).
	 * 
	 * @param map the backing object, which must now exist
	 * @param snap the destination snap
	 * @param thread if a register space, the destination thread
	 * @param frame if a register space, the destination frame
	 */
	public void writeDown(TracePropertyMap<String> map, long snap, TraceThread thread, int frame) {
		if (space.isUniqueSpace()) {
			return;
		}
		TracePropertyMapSpace<String> backing;
		if (space.isRegisterSpace()) {
			backing = map.getPropertyMapRegisterSpace(thread, frame, true);
		}
		else {
			backing = map.getPropertyMapSpace(space, true);
		}
		for (Entry<Long, TaintSet> entry : taints.entrySet()) {
			TaintSet taint = entry.getValue();
			Range<Long> span = DBTraceUtils.atLeastMaybeScratch(snap);
			Address address = space.getAddress(entry.getKey());
			if (taint.isEmpty()) {
				backing.clear(span, new AddressRangeImpl(address, address));
			}
			else {
				backing.set(span, address, taint.toString());
			}
		}
	}
}
