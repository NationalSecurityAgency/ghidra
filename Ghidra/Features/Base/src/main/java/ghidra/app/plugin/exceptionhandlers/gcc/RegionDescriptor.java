/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.exceptionhandlers.gcc;

import ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.FrameDescriptionEntry;
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;

/**
 * RegionDescriptor holds information about a call frame.
 */
public class RegionDescriptor {

	private Address lsdaAddress;
	private LSDATable lsdaTable;
	private FrameDescriptionEntry fde;
	private AddressRange ipRange = new AddressRangeImpl(Address.NO_ADDRESS, Address.NO_ADDRESS);
	private MemoryBlock ehMemory;

	/**
	 * Constructor for a region descriptor.
	 * @param ehblock the exception handling memory block for the region to be described.
	 */
	public RegionDescriptor(MemoryBlock ehblock) {
		this.ehMemory = ehblock;
	}

	/**
	 * Gets the exception handling memory block associated with this region.
	 * @return the memory block
	 */
	public MemoryBlock getEHMemoryBlock() {
		return ehMemory;
	}

	/**
	 * Sets the address range of the IP (instructions) for this region.
	 * @param range the address range to associate with this region.
	 */
	public void setIPRange(AddressRange range) {
		this.ipRange = range;
	}

	/**
	 * Gets the address range of the IP (instructions) for this region.
	 * @return the instruction addresses
	 */
	public AddressRange getRange() {
		return ipRange;
	}

	/**
	 * Gets the start (minimum address) of the IP range for this region.
	 * @return the IP range start address
	 */
	public Address getRangeStart() {
		return ipRange.getMinAddress();
	}

	/**
	 * Gets the size of the address range for the IP.
	 * @return the IP address range size
	 */
	public long getRangeSize() {
		return ipRange.getLength();
	}

	/**
	 * Sets the address of the start of the LSDA.
	 * @param addr the LSDA address.
	 */
	public void setLSDAAddress(Address addr) {
		this.lsdaAddress = addr;
	}

	/**
	 * Gets the address of the start of the LSDA.
	 * @return the LSDA address.
	 */
	public Address getLSDAAddress(Address addr) {
		return lsdaAddress;
	}

	/**
	 * Sets the LSDA table for this frame region.
	 * @param lsdaTable the LSDA table
	 */
	public void setLSDATable(LSDATable lsdaTable) {
		this.lsdaTable = lsdaTable;
	}

	/**
	 * Gets the LSDA table for this frame region.
	 * @return the LSDA table
	 */
	public LSDATable getLSDATable() {
		return lsdaTable;
	}

	/**
	 * Gets the call site table for this region's frame.
	 * @return the call site table
	 */
	public LSDACallSiteTable getCallSiteTable() {
		LSDATable lsda = getLSDATable();
		if (lsda == null) {
			return null;
		}
		return lsda.getCallSiteTable();
	}

	/**
	 * Gets the action table for this region's frame.
	 * @return the action table or null if it hasn't been set for this region
	 */
	public LSDAActionTable getActionTable() {
		LSDATable lsda = getLSDATable();
		if (lsda == null) {
			return null;
		}
		return lsda.getActionTable();
	}

	/**
	 * Gets the type table for this region's frame.
	 * @return the LSDA type table or null if it hasn't been set for this region
	 */
	public LSDATypeTable getTypeTable() {
		LSDATable lsda = getLSDATable();
		if (lsda == null) {
			return null;
		}
		return lsda.getTypeTable();
	}

	/**
	 * Sets the FDE associated with the region.
	 * @param frameDescriptionEntry the FDE
	 */
	public void setFrameDescriptorEntry(FrameDescriptionEntry frameDescriptionEntry) {
		this.fde = frameDescriptionEntry;
	}

	/**
	 * Gets the FDE associated with this region.
	 * @return the FDE
	 */
	public FrameDescriptionEntry getFrameDescriptorEntry() {
		return fde;
	}

}
