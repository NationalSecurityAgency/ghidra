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
package ghidra.app.plugin.core.format;

import java.math.BigInteger;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * Shows what bytes have been disassembled.
 */
public class DisassembledFormatModel implements ProgramDataFormatModel {

	// Character used to mark a byte that is not part of an instruction or defined
	// data.
	public final static String BLOCK = "\u25A1"; // unicode for "WHITE SQUARE"
	private int symbolSize;
	private Program program;
	private Listing listing;

	/**
	 * Constructor
	 */
	public DisassembledFormatModel() {
		symbolSize = 1;
	}

	/**
	 * Get the name of this formatter.
	 */
	@Override
	public String getName() {
		return "Disassembled";
	}

	/**
	 * Get the number of bytes to make a unit; in this case it
	 * takes 1 byte to make an Ascii value.
	 */
	@Override
	public int getUnitByteSize() {
		return 1;
	}

	/**
	 * Given a character position from 0 to data unit symbol size - 1
	 * it returns a number from 0 to unit byte size - 1 indicating which
	 * byte the character position was obtained from.
	 */
	@Override
	public int getByteOffset(ByteBlock block, int position) {
		return 0;
	}

	/**
	 * Given the byte offset into a unit, get the column position.
	 */
	@Override
	public int getColumnPosition(ByteBlock block, int byteOffset) {
		return 0;
	}

	/**
	 * Gets the number of characters required to display a
	 * unit.
	 */
	@Override
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
	@Override
	public String getDataRepresentation(ByteBlock block, BigInteger index)
			throws ByteBlockAccessException {

		String addrStr = block.getLocationRepresentation(index);

		String str = null;

		if (listing != null) {
			// Make sure that the given address is not a part of an Instruction or
			// Defined Data.
			Address a = null;
			if (addrStr != null) {
				a = program.getAddressFactory().getAddress(addrStr);
			}
			if (a == null) {
				str = "?";
			}
			else {
				if ((listing.getInstructionContaining(a) != null) ||
					(listing.getDefinedDataContaining(a) != null)) {
					str = "."; // Instruction or Defined Data
				}
				else {
					str = BLOCK; // Unassembled byte
				}
			}
		}
		else {
			str = "?"; // Listing not available
		}
		return str;
	}

	/**
	 * Returns true if the formatter allows values to be changed.
	 */
	@Override
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
	 * @throws ByteBlockAccessException if the block cannot be updated
	 * @throws IndexOutOfBoundsException if index is not valid for the
	 * block
	 */
	@Override
	public boolean replaceValue(ByteBlock block, BigInteger index, int charPosition, char c)
			throws ByteBlockAccessException {

		if (charPosition != 0) {
			return false;
		}

		byte cb = (byte) c;

		if (cb < 0x20 || cb == 0x7f) {
			return (false);
		}

		block.setByte(index, cb);
		return true;
	}

	/**
	 * Get number of units in a group. A group may represent
	 * multiple units shown as one entity. This format does not
	 * support groups.
	 */
	@Override
	public int getGroupSize() {
		return 0;
	}

	/**
	 * Set the number of units in a group. This format does not
	 * support groups.
	 * @throws UnsupportedOperationException 
	 */
	@Override
	public void setGroupSize(int groupSize) {
		throw new UnsupportedOperationException("groups are not supported");
	}

	/**
	 * Get the number of characters separating units.
	 */
	@Override
	public int getUnitDelimiterSize() {
		return 0; // no space between units
	}

	/**
	 * @see ghidra.app.plugin.core.format.DataFormatModel#validateBytesPerLine(int)
	 */
	@Override
	public boolean validateBytesPerLine(int bytesPerLine) {
		return true;
	}

	/**
	 * Set the program.  This formatter is dependent upon listing from program.  
	 * There are two cases where this dependency only appears.  All Formatters that
	 * are added as a view to Memory Viewer are created via a Factory within their
	 * respective Formatter Plugin.
	 * @param Program in use by the tool.
	 */
	@Override
	public void setProgram(Program program) {
		this.program = program;
		if (program == null) {
			this.listing = null;
		}
		else {
			this.listing = this.program.getListing();
		}
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("ByteViewerPlugin", "Disassembled");
	}

	@Override
	public void dispose() {
		listing = null;
		program = null;
	}

}
