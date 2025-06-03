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
package ghidra.program.model.data;

import java.math.BigInteger;
import java.util.NoSuchElementException;

import ghidra.docking.settings.Settings;
import ghidra.program.database.data.EnumSignedState;

public interface Enum extends DataType {

	/**
	 * Get the value for the given name.
	 * @param name name of the entry.
	 * @return the value.
	 * @throws NoSuchElementException if the name does not exist in this Enum.
	 */
	public long getValue(String name) throws NoSuchElementException;

	/**
	 * Get the name for the given value.
	 * @param value value of the enum entry.
	 * @return null if the name with the given value was not found.
	 */
	public String getName(long value);

	/**
	 * Returns all names that map to the given value.
	 * @param value value for the enum entries.
	 * @return all names; null if there is not name for the given value.
	 */
	public String[] getNames(long value);

	/**
	 * Get the comment for the given name.
	 * @param name name of the entry.
	 * @return the comment or the empty string if the name does not exist in this enum or if no
	 * comment is set.
	 */
	public String getComment(String name);

	/**
	 * Get the values of the enum entries.
	 * @return values sorted in ascending order
	 */
	public long[] getValues();

	/**
	 * Get the names of the enum entries.  The returned names are first sorted by the enum int
	 * value, then sub-sorted by name value where there are multiple name values per int value.
	 * @return the names of the enum entries.
	 */
	public String[] getNames();

	/**
	 * Get the number of entries in this Enum.
	 * @return the number of entries in this Enum.
	 */
	public int getCount();

	/**
	 * Add a enum entry.
	 * @param name name of the new entry
	 * @param value value of the new entry
	 */
	public void add(String name, long value);

	/**
	 * Add a enum entry.
	 * @param name name of the new entry
	 * @param value value of the new entry
	 * @param comment comment of the new entry
	 */
	public void add(String name, long value, String comment);

	/**
	 * Remove the enum entry with the given name.
	 * @param name name of entry to remove.
	 */
	public void remove(String name);

	/**
	 * Set the description for this Enum.
	 * @param description the description
	 */
	@Override
	public void setDescription(String description);

	/**
	 * Get enum representation of the big-endian value.
	 * @param bigInt BigInteger value with the appropriate sign
	 * @param settings integer format settings (PADDING, FORMAT, etc.)
	 * @param bitLength the bit length
	 * @return formatted integer string
	 */
	public String getRepresentation(BigInteger bigInt, Settings settings, int bitLength);

	/**
	 * Returns true if this enum has an entry with the given name.
	 * @param name the name to check for an entry
	 * @return true if this enum has an entry with the given name
	 */
	public boolean contains(String name);

	/**
	 * Returns true if this enum has an entry with the given value.
	 * @param value the value to check for an entry
	 * @return true if this enum has an entry with the given value 
	 */
	public boolean contains(long value);

	/**
	 * Returns true if the enum contains at least one negative value. Internally, enums have
	 * three states, signed, unsigned, and none (can't tell from the values). If any of
	 * the values are negative, the enum is considered signed. If any of the values are large
	 * unsigned values (upper bit set), then it is considered unsigned. This method will return
	 * true if the enum is signed, and false if it is either unsigned or none (meaning that it
	 * doesn't matter for the values that are contained in the enum.
	 * @return true if the enum contains at least one negative value
	 */
	public boolean isSigned();

	/**
	 * Returns the signed state.
	 * @return the signed state.
	 */
	public EnumSignedState getSignedState();

	/**
	 * Returns the maximum value that this enum can represent based on its size and signedness.
	 * @return the maximum value that this enum can represent based on its size and signedness.
	 */
	public long getMaxPossibleValue();

	/**
	 * Returns the maximum value that this enum can represent based on its size and signedness.
	 * @return the maximum value that this enum can represent based on its size and signedness.
	 */
	public long getMinPossibleValue();

	/**
	 * Returns the smallest length (size in bytes) this enum can be and still represent all of
	 * it's current values. Note that this will only return powers of 2 (1,2,4, or 8)
	 * @return the smallest length (size in bytes) this enum can be and still represent all of
	 * it's current values
	 */
	public int getMinimumPossibleLength();

}
