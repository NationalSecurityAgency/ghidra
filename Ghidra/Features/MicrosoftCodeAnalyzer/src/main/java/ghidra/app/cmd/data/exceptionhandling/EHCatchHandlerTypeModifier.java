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
package ghidra.app.cmd.data.exceptionhandling;

/**
 * This is a class for dealing with the adjectives (modifier flags) from an exception handling
 * HandlerType data type.
 * <br>
 * This is based on data type information from ehdata.h
 */
public class EHCatchHandlerTypeModifier {

	public static final EHCatchHandlerTypeModifier NO_MODIFIERS = new EHCatchHandlerTypeModifier(0);

	// Catch Handler Type Modifiers
	private static int CONST_BIT = 0x00000001;
	private static int VOLATILE_BIT = 0x00000002;
	private static int UNALIGNED_BIT = 0x00000004;
	private static int REFERENCE_BIT = 0x00000008;
	private static int RESUMABLE_BIT = 0x00000010;
	private static int ALL_CATCH_BIT = 0x00000040;
	private static int COMPLUS_BIT = 0x80000000;

	private int modifiers;

	/**
	 * Creates the object for dealing with the adjectives (modifier flags) from an exception handling
	 * HandlerType data type. It provides methods to check if modifiers are set for a handler type.
	 * @param modifiers the value of the adjectives (modifier flags) from the HandlerType data type.
	 */
	public EHCatchHandlerTypeModifier(int modifiers) {
		this.modifiers = modifiers;
	}

	private boolean isBitSet(int bitToCheck) {
		return (modifiers & bitToCheck) == bitToCheck;
	}

	/**
	 * Determine if the handler type referenced is a const.
	 * @return true if the handler type referenced is a const.
	 */
	public boolean isConst() {
		return isBitSet(CONST_BIT);
	}

	/**
	 * Determine if the handler type referenced is volatile.
	 * @return true if the handler type referenced is volatile.
	 */
	public boolean isVolatile() {
		return isBitSet(VOLATILE_BIT);
	}

	/**
	 * Determine if the handler type referenced is unaligned.
	 * @return true if the handler type referenced is unaligned.
	 */
	public boolean isUnaligned() {
		return isBitSet(UNALIGNED_BIT);
	}

	/**
	 * Determine if the catch type is by reference.
	 * @return true if the catch type is by reference.
	 */
	public boolean isByReference() {
		return isBitSet(REFERENCE_BIT);
	}

	/**
	 * Determine if the catch function can possibly resume.
	 * @return true if the function is resumable.
	 */
	public boolean isResumable() {
		return isBitSet(RESUMABLE_BIT);
	}

	/**
	 * Determine if the exception handler is a standard C++ all catch(...).
	 * @return true if the function is a catch(...).
	 */
	public boolean isAllCatch() {
		return isBitSet(ALL_CATCH_BIT);
	}

	/**
	 * Determine if this exception handler is complus.
	 * @return true if the handler is complus.
	 */
	public boolean isComplus() {
		return isBitSet(COMPLUS_BIT);
	}

	@Override
	public int hashCode() {
		return modifiers;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		EHCatchHandlerTypeModifier other = (EHCatchHandlerTypeModifier) obj;
		if (modifiers != other.modifiers)
			return false;
		return true;
	}
}
