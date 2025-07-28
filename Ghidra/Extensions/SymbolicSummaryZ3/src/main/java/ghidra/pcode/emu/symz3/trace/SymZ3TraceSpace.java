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
package ghidra.pcode.emu.symz3.trace;

import ghidra.pcode.emu.symz3.plain.SymZ3Space;
import ghidra.pcode.exec.trace.data.PcodeTracePropertyAccess;
import ghidra.program.model.address.AddressSpace;

/**
 * The storage space for symbolic values in a trace's address space
 * 
 * <p>
 * This adds to {@link SymZ3Space} the ability to load symbolic values from a trace and the ability
 * to save them back into a trace.
 */
public abstract class SymZ3TraceSpace extends SymZ3Space {
	protected final AddressSpace space;
	protected final PcodeTracePropertyAccess<String> property;

	/**
	 * Create the space
	 * 
	 * @param space the address space
	 * @param property the property for storing and retrieving values in the trace
	 */
	public SymZ3TraceSpace(AddressSpace space, PcodeTracePropertyAccess<String> property) {
		this.space = space;
		this.property = property;
	}

	/**
	 * Write this cache back down into a trace
	 * 
	 * <p>
	 * Here we simply iterate over every entry in this space, serialize the value, and store it into
	 * the property map at the entry's offset. Because a backing object may not have existed when
	 * creating this space, we must re-fetch the backing object, creating it if it does not exist.
	 * 
	 * @param into the destination trace property accessor
	 */
	public abstract void writeDown(PcodeTracePropertyAccess<String> into);
}
