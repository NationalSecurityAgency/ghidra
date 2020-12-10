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
package ghidra.dbg.sctl.protocol.common;

import ghidra.comm.packet.Packet;
import ghidra.comm.util.BitmaskSet;
import ghidra.dbg.sctl.client.SctlMemoryProtection;

public abstract class AbstractSctlRegion extends Packet {
	/**
	 * Set the name of the region
	 * 
	 * This may be a file path describing the module loaded here or any textual description of the
	 * region.
	 * 
	 * @param name the name
	 */
	public abstract void setName(String name);

	/**
	 * Get the name of the region
	 * 
	 * This may be a file path describing the module loaded here or any textual description of the
	 * region.
	 * 
	 * @return the name
	 */
	public abstract String getName();

	/**
	 * Set the start address of the region
	 * 
	 * @param address the address
	 */
	public abstract void setAddress(long address);

	/**
	 * Get the start address of the region
	 * 
	 * @return
	 */
	public abstract long getAddress();

	/**
	 * Set the length, in bytes, of the region
	 * 
	 * @param length the length
	 */
	public abstract void setLength(long length);

	/**
	 * Get the length, in bytes, of the region
	 * 
	 * @return the length
	 */
	public abstract long getLength();

	/**
	 * Set the region's protections (permissions)
	 * 
	 * @param flags the flags enumerating the protections
	 */
	public abstract void setProtections(BitmaskSet<SctlMemoryProtection> flags);

	/**
	 * Get the region's protections (permissions)
	 * 
	 * @return the flags enumerating the protections
	 */
	public abstract BitmaskSet<SctlMemoryProtection> getProtections();
}
