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
package ghidra.debug.api.modules;

import java.util.Objects;

import ghidra.program.model.address.*;

/**
 * A pair for describing sets of mapped addresses
 * 
 * <p>
 * Note, the natural order is by the <em>destination</em> address.
 */
public class MappedAddressRange implements Comparable<MappedAddressRange> {

	private final AddressRange srcRange;
	private final AddressRange dstRange;
	private final int hashCode;
	private final long shift;

	public MappedAddressRange(AddressRange srcRange, AddressRange dstRange) {
		this.srcRange = srcRange;
		this.dstRange = dstRange;
		this.hashCode = Objects.hash(dstRange, srcRange);
		this.shift = dstRange.getMinAddress().getOffset() -
			srcRange.getMinAddress().getOffset();
	}

	@Override
	public String toString() {
		return "<MappedRange " + srcRange + "::" + dstRange + ">";
	}

	/**
	 * Get the shift from the source address range to this address range
	 * 
	 * <p>
	 * The meaning depends on what returned this view. If this view is the "static" range, then
	 * this shift describes what was added to the offset of the "dynamic" address to get a
	 * particular address in the "static" range.
	 * 
	 * @return the shift
	 */
	public long getShift() {
		return shift;
	}

	/**
	 * Map an address in the source range to the corresponding address in the destination range
	 * 
	 * @param saddr the source address (not validated)
	 * @return the destination address
	 */
	public Address mapSourceToDestination(Address saddr) {
		return dstRange.getAddressSpace().getAddress(saddr.getOffset() + shift);
	}

	/**
	 * Map an address in the destination range to the corresponding address in the source range
	 * 
	 * @param daddr the destination address (not validated)
	 * @return the source address
	 */
	public Address mapDestinationToSource(Address daddr) {
		return srcRange.getAddressSpace().getAddress(daddr.getOffset() - shift);
	}

	/**
	 * Map a sub-range of the source to the corresponding sub-range of the destination
	 * 
	 * @param srng the source sub-range
	 * @return the destination sub-range
	 */
	public AddressRange mapSourceToDestination(AddressRange srng) {
		try {
			return new AddressRangeImpl(mapSourceToDestination(srng.getMinAddress()),
				srng.getLength());
		}
		catch (AddressOverflowException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Map a sub-range of the destination to the corresponding sub-range of the source
	 * 
	 * @param drng the destination sub-range
	 * @return the source sub-range
	 */
	public AddressRange mapDestinationToSource(AddressRange drng) {
		try {
			return new AddressRangeImpl(mapDestinationToSource(drng.getMinAddress()),
				drng.getLength());
		}
		catch (AddressOverflowException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Get the source address range
	 * 
	 * @return the address range
	 */
	public AddressRange getSourceAddressRange() {
		return srcRange;
	}

	/**
	 * Get the destination address range
	 * 
	 * @return the address range
	 */
	public AddressRange getDestinationAddressRange() {
		return dstRange;
	}

	@Override
	public int compareTo(MappedAddressRange that) {
		int c;
		c = this.dstRange.compareTo(that.dstRange);
		if (c != 0) {
			return c;
		}
		c = this.srcRange.compareTo(that.srcRange);
		if (c != 0) {
			return c;
		}
		return 0;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof MappedAddressRange)) {
			return false;
		}
		MappedAddressRange that = (MappedAddressRange) obj;
		if (!this.dstRange.equals(that.dstRange)) {
			return false;
		}
		if (!this.srcRange.equals(that.srcRange)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return hashCode;
	}
}
