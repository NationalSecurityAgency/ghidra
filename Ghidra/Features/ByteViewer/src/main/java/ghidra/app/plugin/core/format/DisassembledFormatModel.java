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
	 * Get the number of characters separating units.
	 */
	@Override
	public int getUnitDelimiterSize() {
		return 0; // no space between units
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
