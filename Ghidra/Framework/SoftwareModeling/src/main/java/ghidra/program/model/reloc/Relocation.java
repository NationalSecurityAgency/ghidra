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
package ghidra.program.model.reloc;

import ghidra.program.model.address.Address;

/**
 * A class to store the information needed for a single
 * program relocation.
 */
public class Relocation {

	/**
	 * Relocation status.
	 */
	public enum Status {

		// NOTE: associated values must not change since they are retained within the database

		/**
		 * Relocation status is unknown and is assumed to have modified memory bytes.
		 * This status is intended for relocation data upgrades when actual status can not
		 * be determined.
		 */
		UNKNOWN(0, true),

		/**
		 * Relocation has be intentionally skipped and should not be treated as a failure.
		 */
		SKIPPED(1, false),

		/**
		 * Relocation type is not supported at the time relocations were applied.
		 */
		UNSUPPORTED(2, false),

		/**
		 * A supported relocation fail to apply properly.  This may be the result of an unexpected
		 * or unsupported condition which prevented its application.
		 */
		FAILURE(3, false),

		/**
		 * Relocation was processed successfully although relies on a subsequent relocation to 
		 * affect memory.
		 */
		PARTIAL(4, false),

		/**
		 * Relocation was applied successfully and resulted in the modification of memory bytes.
		 */
		APPLIED(5, true),

		/**
		 * Loaded memory has been altered during the load process and may, or may not, be directly
		 * associated with a standard relocation type.
		 */
		APPLIED_OTHER(6, true);

		private int value;
		private boolean hasBytes;

		private Status(int value, boolean hasBytes) {
			this.value = value;
			this.hasBytes = hasBytes;
		}

		/**
		 * @return true if relocation reflects original bytes that may have been modified, 
		 * else false.
		 */
		public boolean hasBytes() {
			return hasBytes;
		}

		/**
		 * Get storage value associated 
		 * @return storage value associated with status
		 */
		public int getValue() {
			return value;
		}

		/**
		 * Get the Status which corresponds to the specified value.
		 * @param value status value
		 * @return status enum
		 */
		public static Status getStatus(int value) {
			for (Status s : values()) {
				if (s.value == value) {
					return s;
				}
			}
			throw new IllegalArgumentException(
				"Undefined Status value: " + value);
		}
	}

	private Address addr;
	private Status status;
	private int type;
	private long[] values;
	private byte[] bytes;
	private String symbolName;

	/**
	 * Constructs a new relocation.
	 * 
	 * @param addr the address where the relocation is required
	 * @param status relocation status
	 * @param type the type of relocation to perform
	 * @param values the values needed when performing the relocation.  Definition of values is
	 * specific to loader used and relocation type.
	 * @param bytes  original instruction bytes affected by relocation
	 * @param symbolName the name of the symbol being relocated
	 */
	public Relocation(Address addr, Status status, int type, long[] values, byte[] bytes,
			String symbolName) {
		this.addr = addr;
		this.status = status;
		this.type = type;
		this.values = values;
		this.bytes = bytes;
		this.symbolName = symbolName;
	}

	/**
	 * Returns the address where the relocation is required.
	 * 
	 * @return the address where the relocation is required
	 */
	public Address getAddress() {
		return addr;
	}

	/**
	 * Return the relocation's application status within the program.
	 * 
	 * @return relocation's application status within the program.
	 */
	public Status getStatus() {
		return status;
	}

	/**
	 * Returns the type of the relocation to perform.
	 * 
	 * @return the type of the relocation to perform
	 */
	public int getType() {
		return type;
	}

	/**
	 * Returns the value needed when performing the relocation.
	 * 
	 * @return the value needed when performing the relocation
	 */
	public long[] getValues() {
		return values;
	}

	/**
	 * Returns the original instruction bytes affected by applied relocation.
	 * 
	 * @return original instruction bytes affected by relocation if it was successfully applied
	 * (i.e., {@link Status#APPLIED}, {@link Status#APPLIED_OTHER}), otherwise null may be returned.
	 */
	public byte[] getBytes() {
		return bytes;
	}

	/**
	 * Returns the number of original instruction bytes affected by applied relocation.
	 * 
	 * @return number of original instruction bytes affected by relocation if it was successfully applied
	 * (i.e., {@link Status#APPLIED}, {@link Status#APPLIED_OTHER}), otherwise null may be returned.
	 */
	public int getLength() {
		return bytes != null ? bytes.length : 0;
	}

	/**
	 * The name of the symbol being relocated or <code>null</code> if there is no symbol name.
	 * 
	 * @return the name of the symbol being relocated or <code>null</code> if there is no symbol name.
	 */
	public String getSymbolName() {
		return symbolName;
	}
}
