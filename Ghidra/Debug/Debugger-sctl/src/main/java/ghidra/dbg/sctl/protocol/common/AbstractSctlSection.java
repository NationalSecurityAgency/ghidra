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

public abstract class AbstractSctlSection extends Packet {
	/**
	 * Set the starting address of the section as loaded
	 * 
	 * @param address the address
	 */
	public abstract void setAddress(long address);

	/**
	 * Get the starting address of the section as loaded
	 * 
	 * @return the address
	 */
	public abstract long getAddress();

	/**
	 * Set the length, in bytes, of the section
	 * 
	 * @param length the length
	 */
	public abstract void setLength(long length);

	/**
	 * Get the length, in bytes, of the section
	 * 
	 * @return
	 */
	public abstract long getLength();

	/**
	 * Set the name of the section
	 * 
	 * @param name the name
	 */
	public abstract void setName(String name);

	/**
	 * Get the name of the section
	 * 
	 * @return the name
	 */
	public abstract String getName();
}
