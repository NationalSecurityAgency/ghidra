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
package ghidra.app.plugin.exceptionhandlers.gcc;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

/** 
 * Decodes a sequence of program bytes to Ghidra addressing types.
 */
public interface DwarfEHDecoder {

	/**
	 * Gets the exception handling data decoding format.
	 * 
	 * @return the data decoding format
	 */
	public DwarfEHDataDecodeFormat getDataFormat();

	/**
	 * Gets the data application mode.
	 * 
	 * @return the data application mode
	 */
	public DwarfEHDataApplicationMode getDataApplicationMode();

	/**
	 * Whether or not this decoder is for decoding signed or unsigned data.
	 * 
	 * @return true if the decoder is for signed data. false for unsigned
	 */
	public boolean isSigned();

	/**
	 * Gets the size of the encoded data.
	 * 
	 * @param program the program containing the data to be decoded.
	 * @return the size of the encoded data
	 */
	public int getDecodeSize(Program program);

	/**
	 * Decodes an integer value which is indicated by the context.
	 * 
	 * @param context Stores program location and decode parameters
	 * @return the value
	 * @throws MemoryAccessException if the data can't be read
	 */
	public long decode(DwarfDecodeContext context) throws MemoryAccessException;

	/**
	 * Decodes the address which is indicated by the context.
	 * 
	 * @param context Stores program location and decode parameters
	 * @return the address
	 * @throws MemoryAccessException if the data can't be read
	 */
	public Address decodeAddress(DwarfDecodeContext context) throws MemoryAccessException;

	/**
	 * Gets this decoder's encoded data type.
	 * 
	 * @param program the program containing the data to be decoded.
	 * @return the data type.
	 */
	public DataType getDataType(Program program);

	/**
	 * Sets the exception handling data application mode.
	 * @param mode the application mode
	 */
	public void setApplicationMode(DwarfEHDataApplicationMode mode);

	/**
	 * Sets whether or not the data is an indirect reference.
	 * @param isIndirect true for an indirect reference.
	 */
	public void setIndirect(boolean isIndirect);

}
