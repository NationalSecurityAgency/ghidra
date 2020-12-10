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

/**
 * An attachable target process entry
 * 
 * This is a dialect-defined format.
 */
public abstract class AbstractSctlObjectEntry extends Packet {
	/**
	 * Get the object path
	 * 
	 * @return path the object path
	 */
	public abstract SctlString getPath();

	/**
	 * Set the object path
	 * 
	 * @param path the object path
	 */
	public abstract void setPath(SctlString path);

	/**
	 * Get the object path
	 * 
	 * @return path the object path
	 */
	public abstract SctlString getKey();

	/**
	 * Set the object path
	 * 
	 * @param path the object path
	 */
	public abstract void setKey(SctlString key);

	/**
	 * Get the object kind
	 * 
	 * @return path the object kind
	 */
	public abstract SctlString getKind();

	/**
	 * Set the object kind
	 * 
	 * @param path the object kind
	 */
	public abstract void setKind(SctlString kind);

	/**
	 * Get the object value
	 * 
	 * @return path the object value
	 */
	public abstract SctlString getValue();

	/**
	 * Set the object value if it exists
	 * 
	 * @param path the object value
	 */
	public abstract void setValue(SctlString value);

	/**
	 * Get the object type
	 * 
	 * @return path the object type
	 */
	public abstract SctlString getType();

	/**
	 * Set the object type if it exists
	 * 
	 * @param path the object type
	 */
	public abstract void setType(SctlString sctlString);

}
