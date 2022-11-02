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

import ghidra.pcode.emu.taint.plain.TaintSpace;
import ghidra.pcode.exec.trace.data.PcodeTracePropertyAccess;
import ghidra.program.model.address.*;
import ghidra.taint.model.TaintSet;

/**
 * The storage space for taint sets in a trace's address space
 * 
 * <p>
 * This adds to {@link TaintSpace} the ability to load taint sets from a trace and the ability to
 * save them back into a trace.
 */
public class TaintTraceSpace extends TaintSpace {
	protected final AddressSpace space;
	protected final PcodeTracePropertyAccess<String> property;

	/**
	 * Create the space
	 * 
	 * @param space the address space
	 * @param backing if present, the backing object
	 * @param snap the source snap
	 */
	public TaintTraceSpace(AddressSpace space, PcodeTracePropertyAccess<String> property) {
		this.space = space;
		this.property = property;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * The taint space will call this when the cache misses, allowing us to populate it with a taint
	 * set stored in the trace. Note that if the emulator writes to this offset <em>before</em>
	 * reading it, this will not get called for that offset. Here we simply get the string property
	 * and parse the taint set.
	 */
	@Override
	protected TaintSet whenNull(long offset) {
		String string = property.get(space.getAddress(offset));
		if (string == null) {
			return TaintSet.EMPTY;
		}
		return TaintSet.parse(string);
	}

	/**
	 * Write this cache back down into a trace
	 * 
	 * <p>
	 * Here we simply iterate over every entry in this space, serialize the taint, and put it into
	 * the property at the entry's offset. If the taint set is empty, we clear the property rather
	 * than putting the empty taint set into the property.
	 * 
	 * @param map the backing object, which must now exist
	 * @param snap the destination snap
	 * @param thread if a register space, the destination thread
	 * @param frame if a register space, the destination frame
	 */
	public void writeDown(PcodeTracePropertyAccess<String> into) {
		if (space.isUniqueSpace()) {
			return;
		}

		for (Entry<Long, TaintSet> entry : taints.entrySet()) {
			TaintSet taint = entry.getValue();
			Address address = space.getAddress(entry.getKey());
			if (taint.isEmpty()) {
				into.clear(new AddressRangeImpl(address, address));
			}
			else {
				into.put(address, taint.toString());
			}
		}
	}
}
