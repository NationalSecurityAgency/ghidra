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
package ghidra.app.plugin.core.format;

import ghidra.app.plugin.core.byteviewer.MemoryByteBlock;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.HelpLocation;

import java.math.BigInteger;

/**
 * Converts byte values to Ascii representation.
 */
public class AddressFormatModel implements ProgramDataFormatModel {

	public final static String GOOD_ADDRESS = "\u278A";
	public final static String BAD_ADDRESS = ".";
	public final static String NON_ADDRESS = "?";

	private int symbolSize;
	private Listing listing;
	private Memory memory;

	public AddressFormatModel() {
		symbolSize = 1;
	}

	/**
	 * Get the name of this formatter.
	 */
	public String getName() {
		return "Address";
	}

	/**
	 * Get the number of bytes to make a unit; in this case it
	 * takes 1 byte to make an Ascii value.
	 */
	public int getUnitByteSize() {
		return 1;
	}

	/**
	 * Given a character position from 0 to data unit symbol size - 1
	 * it returns a number from 0 to unit byte size - 1 indicating which
	 * byte the character position was obtained from.
	 */
	public int getByteOffset(ByteBlock block, int position) {
		return 0;
	}

	/**
	 * Given the byte offset into a unit, get the column position.
	 */
	public int getColumnPosition(ByteBlock block, int byteOffset) {
		return 0;
	}

	/**
	 * Gets the number of characters required to display a
	 * unit.
	 */
	public int getDataUnitSymbolSize() {
		return symbolSize;
	}

	/**
	 * Gets the string representation at the given index in the block.
	 * @param block block to change
	 * @param index byte index into the block
	 * @throws ByteBlockAccessException if the block cannot be read
	 * @throws IndexOutOfBoundsException if index is not valid for the
	 * block
	 */
	public String getDataRepresentation(ByteBlock block, BigInteger index)
			throws ByteBlockAccessException {

		String str = NON_ADDRESS;

		if ((listing != null) && (block instanceof MemoryByteBlock)) {

			str = BAD_ADDRESS;

			MemoryByteBlock memBlock = (MemoryByteBlock) block;

			Address a = memBlock.getAddress(index);

			Address testAddress = getTestAddress(a);

			if ((testAddress != null) && (memory.contains(testAddress))) {
				str = GOOD_ADDRESS;
			}
		}
		return (str);
	}

	/**
	 * Given an address in memory, see if the byte at the named address and the
	 * three consecutive bytes form an address.  If any of the bytes is part
	 * of an instruction or defined data, then we terminate the check.  We are
	 * Interested in cleared bytes.
	 * @param a address that we need to see how represent it textually.
	 * @param string textual representation for the byte.
	 */
	private Address getTestAddress(Address a) {

		int size = a.getAddressSpace().getSize();
		int nbytes = size / 8;
		try {
			long value = 0;
			switch (nbytes) {
				case 8:
					value = memory.getLong(a);
					break;
				case 4:
					value = memory.getInt(a);
					break;
				case 2:
					value = memory.getShort(a);
					break;
				case 1:
					value = memory.getByte(a);
					break;
				default:
					return null;
			}
			return a.getNewAddress(value);
		}
		catch (MemoryAccessException ex) {
			// Do nothing... Tried to form an address that was not readable or
			// writeable.
		}
		catch (AddressOutOfBoundsException e) {
		}
		catch (IllegalArgumentException e) {
		}
		return null;
	}

	private boolean isUndefined(Address a) {

		int length = (a.getAddressSpace().getSize()) / 4;
		for (int i = 0; i < length; i++) {
			if (listing.getUndefinedDataAt(a) == null) {
				return false;
			}
			try {
				a = a.addNoWrap(1);
			}
			catch (AddressOverflowException e) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns true if the formatter allows values to be changed.
	 */
	public boolean isEditable() {
		return false;
	}

	/**
	 * Overwrite a value in a ByteBlock.
	 * @param block block to change
	 * @param index byte index into the block
	 * @param pos The position within the unit where c will be the
	 * new character.
	 * @param c new character to put at pos param
	 * @return true if the replacement is legal, false if the
	 * replacement value would not make sense for this format, e.g.
	 * attempt to put a 'z' in a hex unit.
	 * block
	 */
	public boolean replaceValue(ByteBlock block, BigInteger index, int charPosition, char c) {
		return false;
	}

	/**
	 * Get the number of characters separating units.
	 */
	public int getUnitDelimiterSize() {
		return 0;
	}

	/**
	 * Get number of units in a group. A group may represent
	 * multiple units shown as one entity. This format does not
	 * support groups.
	 */
	public int getGroupSize() {
		return 0;
	}

	/**
	 * Set the number of units in a group. This format does not
	 * support groups.
	 * @throws UnsupportedOperationException
	 */
	public void setGroupSize(int groupSize) {
		throw new UnsupportedOperationException("groups are not supported");
	}

	/**
	 * @see ghidra.app.plugin.core.format.DataFormatModel#validateBytesPerLine(int)
	 */
	public boolean validateBytesPerLine(int bytesPerLine) {
		return true;
	}

	/**
	 * Set the program.  This formatter is dependent upon listing from program.
	 * There are two cases where this depedency only appears.  All Formatters that
	 * are added as a view to Memory Viewer are created via a Factory within their
	 * respective Formatter Plugin.
	 */
	public void setProgram(Program program) {
		if (program == null) {
			listing = null;
			memory = null;
		}
		else {
			listing = program.getListing();
			memory = program.getMemory();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.format.DataFormatModel#getHelpLocation()
	 */
	public HelpLocation getHelpLocation() {
		return new HelpLocation("ByteViewerPlugin", "Address");
	}

	public void dispose() {
		listing = null;
		memory = null;
	}
}
