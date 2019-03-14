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
package ghidra.program.model.address;

/**
 * Generic implementation of the AddressSpace interface.
 */
public class GenericAddressSpace extends AbstractAddressSpace {

	/**
	 * Constructs a new GenericAddress space with the given name, bit size, type
	 * and unique value.
	 * 
	 * @param name
	 *            the name of the space.
	 * @param size
	 *            the number of bits required to represent the largest address
	 *            the space.
	 * @param type
	 *            the type of the space
	 * @param unique
	 *            the unique id for this space.
	 */
	public GenericAddressSpace(String name, int size, int type, int unique) {
		this(name, size, 1, type, unique);
	}

	/**
	 * Constructs a new GenericAddress space with the given name, bit size, type
	 * and unique value.
	 * 
	 * @param name
	 *            the name of the space.
	 * @param size
	 *            the number of bits required to represent the largest address
	 *            the space.
	 * @param type
	 *            the type of the space
	 * @param unique
	 *            the unique id for this space.
	 * @param showSpaceName
	 *            whether to show the space name in toString()
	 */
	public GenericAddressSpace(String name, int size, int type, int unique, boolean showSpaceName) {
		this(name, size, 1, type, unique);
		setShowSpaceName(showSpaceName);
	}

	/**
	 * Constructs a new GenericAddress space with the given name, bit size, type
	 * and unique value.
	 * 
	 * @param name
	 *            the name of the space.
	 * @param size
	 *            the number of bits required to represent the largest address
	 *            the space.
	 * @param unitSize
	 *            number of bytes contained at each addressable location (1, 2,
	 *            4 or 8)
	 * @param type
	 *            the type of the space
	 * @param unique
	 *            the unique id for this space.
	 */
	public GenericAddressSpace(String name, int size, int unitSize, int type, int unique) {
		super(name, size, unitSize, type, unique);
	}

	/**
	 * @see ghidra.program.model.address.AddressSpace#getAddress(long)
	 */
	@Override
	public Address getAddress(long offset) throws AddressOutOfBoundsException {
		return new GenericAddress(this, offset);
	}

	/**
	 * @see ghidra.program.model.address.AddressSpace#getAddressInThisSpaceOnly(long)
	 */
	@Override
	public Address getAddressInThisSpaceOnly(long offset) {
		return new GenericAddress(this, offset);
	}

	/**
	 * @see ghidra.program.model.address.AbstractAddressSpace#getUncheckedAddress(long)
	 */
	@Override
	protected Address getUncheckedAddress(long offset) {
		return new GenericAddress(offset, this);
	}

}
