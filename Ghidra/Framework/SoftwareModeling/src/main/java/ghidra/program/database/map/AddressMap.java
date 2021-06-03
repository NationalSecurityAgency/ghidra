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
package ghidra.program.database.map;

import java.io.IOException;
import java.util.List;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.util.LanguageTranslator;

/**
 * Address map interface add methods need by the program database implementation to manage its address map.
 * NOTE: Objects implementing this interface are not intended for use outside of the
 * <code>ghidra.program.database</code> packages.
 */
public interface AddressMap {

	/**
	 * Reserved key for an invalid key.
	 */
	public static final long INVALID_ADDRESS_KEY = -1;

	/**
	 * Get the database key associated with the given relative address.
	 * This key uniquely identifies a relative location within the program.
	 * If the program's image base is moved to another address, this key will map to a new
	 * address that is the same distance to the new base as the old address was to the old base.
	 * If the requested key does not exist and create is false, INVALID_ADDRESS_KEY
	 * will be returned.  Note that nothing should ever be stored using the returned key unless
	 * create is true.
	 * @param addr the address for which to get a database key.
	 * @param create true if a new key may be generated
	 * @return the database key for the given address or INVALID_ADDRESS_KEY if 
	 * create is false and one does not exist for the specified addr.
	 */
	public long getKey(Address addr, boolean create);

	/**
	 * Get the database key associated with the given absolute address.
	 * This key uniquely identifies an absolute location within the program.
	 * If the requested key does not exist and create is false, INVALID_ADDRESS_KEY
	 * will be returned.  Note that nothing should ever be stored using the returned key unless
	 * create is true.
	 * @param addr the address for which to get a database key.
	 * @param create true if a new key may be generated
	 * @return the database key for the given address or INVALID_ADDRESS_KEY if 
	 * create is false and one does not exist for the specified addr.
	 */
	public long getAbsoluteEncoding(Address addr, boolean create);

	/**
	 * Search for addr within the "sorted" keyRangeList and return the index of the
	 * keyRange which contains the specified addr.
	 * @param keyRangeList
	 * @param addr address or null
	 * @return index of the keyRange within the keyRangeList which contains addr 
	 * if it is contained in the list; otherwise, <code>(-(<i>insertion point</i>) - 1)</code>. 
	 * The <i>insertion point</i> is defined as the point at which the
	 * addr would be inserted into the list: the index of the first keyRange
	 * greater than addr, or <code>keyRangeList.size()</code>, if all
	 * keyRanges in the list are less than the specified addr.  Note
	 * that this guarantees that the return value will be &gt;= 0 if
	 * and only if the addr is found within a keyRange.  
	 * An addr of null will always result in a returned index of -1.
	 */
	public int findKeyRange(List<KeyRange> keyRangeList, Address addr);

	/**
	 * Generates a properly ordered list of database key ranges for a
	 * a specified address range.  If absolute encodings are requested, 
	 * only memory addresses will be included.  Returned key ranges are 
	 * generally intended for read-only operations since new keys will 
	 * never be generated.  The returned key ranges will correspond 
	 * to those key ranges which have previously been created within 
	 * the specified address range and may represent a much smaller subset 
	 * of addresses within the specified range.
	 * @param start minimum address of range
	 * @param end maximum address of range
	 * @param create true if a new keys may be generated, otherwise returned 
	 * key-ranges will be limited to those already defined.
	 * @return "sorted" list of KeyRange objects
	 */
	public List<KeyRange> getKeyRanges(Address start, Address end, boolean create);

	/**
	 * Generates a properly ordered list of database key ranges for a
	 * a specified address set.  If absolute encodings are requested, 
	 * only memory addresses will be included.
	 * @param set address set or null for all real address.
	 * @param create true if a new keys may be generated, otherwise returned 
	 * key-ranges will be limited to those already defined.
	 * @return "sorted" list of KeyRange objects
	 */
	public List<KeyRange> getKeyRanges(AddressSetView set, boolean create);

	/**
	 * Returns the address that was used to generate the given long key. (If the image base was
	 * moved, then a different address is returned unless the value was encoded using the
	 * "absoluteEncoding" method.  If the program's default address space is segmented (i.e., SegmentedAddressSpace).
	 * the address returned will be always be normalized to defined segmented memory blocks if possible.
	 * @param value the long value to convert to an address.
	 */
	public Address decodeAddress(long value);

	/**
	 * Returns the address factory associated with this map.
	 * Null may be returned if map not associated with a specific address factory.
	 */
	public AddressFactory getAddressFactory();

	/**
	 * Generates a properly ordered list of database key ranges for a
	 * a specified address range.  If absolute encodings are requested, 
	 * only memory addresses will be included.
	 * @param start minimum address of range
	 * @param end maximum address of range
	 * @param absolute if true, absolute key encodings are returned, otherwise 
	 * standard/relocatable address key encodings are returned.
	 * @param create true if a new keys may be generated, otherwise returned 
	 * key-ranges will be limited to those already defined.
	 * @return "sorted" list of KeyRange objects
	 */
	public List<KeyRange> getKeyRanges(Address start, Address end, boolean absolute, boolean create);

	/**
	 * Generates a properly ordered list of database key ranges for a
	 * a specified address set.  If absolute encodings are requested, 
	 * only memory addresses will be included.
	 * @param set address set or null for all real address.
	 * @param absolute if true, absolute key encodings are returned, otherwise 
	 * standard/relocatable address key encodings are returned.
	 * @param create true if a new keys may be generated, otherwise returned 
	 * key-ranges will be limited to those already defined.
	 * @return "sorted" list of KeyRange objects
	 */
	public List<KeyRange> getKeyRanges(AddressSetView set, boolean absolute, boolean create);

	/**
	 * Returns an address map capable of decoding old address encodings.
	 */
	public AddressMap getOldAddressMap();

	/**
	 * Returns true if this address map has been upgraded.
	 */
	public boolean isUpgraded();

	/**
	 * Sets the image base, effectively changing the mapping between addresses and longs.
	 * @param base the new base address.
	 */
	public void setImageBase(Address base);

	/**
	 * Returns a modification number that always increases when the address map base table has
	 * changed.
	 */
	public int getModCount();

	/**
	 * Returns the current image base setting.
	 */
	public Address getImageBase();

	/**
	 * Converts the current base addresses to addresses compatible with the new language.
	 * @param newLanguage the new language to use.
	 * @param addrFactory the new AddressFactory.
	 * @param translator translates address spaces from the old language to the new language.
	 */
	public void setLanguage(Language newLanguage, AddressFactory addrFactory,
			LanguageTranslator translator) throws IOException;

	/**
	 * Clears any cached values.
	 * @throws IOException
	 */
	public void invalidateCache() throws IOException;

	/**
	 * Rename an existing overlay space.
	 * @param oldName old overlay name
	 * @param newName new overlay name (must be unique among all space names within this map)
	 * @throws IOException
	 */
	public void renameOverlaySpace(String oldName, String newName) throws IOException;

	/**
	 * Delete the specified overlay space from this address map.
	 * @param name overlay space name (must be unique among all space names within this map)
	 * @throws IOException
	 */
	public void deleteOverlaySpace(String name) throws IOException;

	/**
	 * Returns true if the two address keys share a common key base and can be 
	 * used within a single key-range.
	 * @param addrKey1
	 * @param addrKey2
	 */
	public boolean hasSameKeyBase(long addrKey1, long addrKey2);

	/**
	 * Returns true if the specified addrKey is the minimum key within
	 * its key-range.
	 * @param addrKey
	 */
	public boolean isKeyRangeMin(long addrKey);

	/**
	 * Returns true if the specified addrKey is the maximum key within
	 * its key-range.
	 * @param addrKey
	 */
	public boolean isKeyRangeMax(long addrKey);
}
