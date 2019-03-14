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
package ghidra.framework.store;

import ghidra.framework.remote.GhidraServerHandle;

/**
 * <code>ChecoutType</code> identifies the type of checkout
 */
public enum CheckoutType {

	/**
	 * Checkout is a normal non-exclusive checkout
	 */
	NORMAL,

	/**
	 * Checkout is a persistent exclusive checkout which 
	 * ensures no other checkout can occur while this checkout
	 * persists.
	 */
	EXCLUSIVE,

	/**
	 * Similar to an EXCLUSIVE checkout, this checkout only 
	 * persists while the associated client-connection is
	 * alive.  This checkout is only permitted for remote
	 * versioned file systems which support its use.
	 */
	TRANSIENT;

	/**
	 *  Rely on standard Java serialization for enum
	 *  If the above enum naming/order is changed, the server
	 *  interface version must be changed
	 *  @see GhidraServerHandle
	 */
	public static final long serialVersionUID = 1L;

	/**
	 * Get the abbreviated/short name for this checkout type
	 * for use with serialization.
	 * @return short name
	 */
	public int getID() {
		return name().charAt(0);
	}

	/**
	 * Get the CheckoutType whose name corresponds to the specified ID
	 * @param typeID checkout type ID
	 * @return CheckoutType of null if ID is invalid
	 */
	public static CheckoutType getCheckoutType(int typeID) {
		for (CheckoutType type : values()) {
			if (type.name().charAt(0) == typeID) {
				return type;
			}
		}
		return null;
	}

}
