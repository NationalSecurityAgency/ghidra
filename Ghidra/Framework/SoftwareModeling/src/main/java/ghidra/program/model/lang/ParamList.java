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
package ghidra.program.model.lang;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Encoder;
import ghidra.xml.XmlParseException;
import ghidra.xml.XmlPullParser;

/**
 * A group of ParamEntry that form a complete set for passing parameters (in one direction)
 *
 */
public interface ParamList {
	public static class WithSlotRec {	// Object for passing back slot and slotsize
		int slot;
		int slotsize;
	}

	/**
	 * Given a list of datatypes, calculate the storage locations used for passing those data-types
	 * @param proto is the list of datatypes
	 * @param dtManage is the data-type manager
	 * @param res is the vector for holding the storage locations and other parameter properties
	 * @param addAutoParams if true add/process auto-parameters
	 */
	public void assignMap(PrototypePieces proto, DataTypeManager dtManage,
			ArrayList<ParameterPieces> res, boolean addAutoParams);

	public void encode(Encoder encoder, boolean isInput) throws IOException;

	public void restoreXml(XmlPullParser parser, CompilerSpec cspec) throws XmlParseException;

	/**
	 * Get a list of all parameter storage locations consisting of a single register
	 * @param prog is the controlling program
	 * @return an array of VariableStorage
	 */
	public VariableStorage[] getPotentialRegisterStorage(Program prog);

	/**
	 * Return the amount of alignment used for parameters passed on the stack, or -1 if there are no stack params
	 * @return the alignment
	 */
	public int getStackParameterAlignment();

	/**
	 * Find the boundary offset that separates parameters on the stack from other local variables
	 * This is usually the address of the first stack parameter, but if the stack grows positive, this is
	 * the first address AFTER the parameters on the stack
	 * @return the boundary offset
	 */
	public Long getStackParameterOffset();

	/**
	 * Determine if a particular address range is a possible parameter, and if so what slot(s) it occupies
	 * @param loc  is the starting address of the range
	 * @param size is the size of the range in bytes
	 * @param res  holds the resulting slot and slotsize
	 * @return  true if the range is a possible parameter
	 */
	public boolean possibleParamWithSlot(Address loc, int size, WithSlotRec res);

	/**
	 * @return the associated Language
	 */
	public Language getLanguage();

	/**
	 * Get the address space associated with any stack based parameters in this list.
	 * 
	 * @return the stack address space, if this models parameters passed on the stack, null otherwise
	 */
	public AddressSpace getSpacebase();

	/**
	 * Return true if the this pointer occurs before an indirect return pointer
	 * 
	 * The automatic parameters: this parameter and the hidden return value pointer both
	 * tend to be allocated from the initial general purpose registers reserved for parameter passing.
	 * This method returns true if the this parameter is allocated first.
	 * @return false if the hidden return value pointer is allocated first
	 */
	public boolean isThisBeforeRetPointer();

	/**
	 * Determine if this ParmList is equivalent to another instance
	 * @param obj is the other instance
	 * @return true if they are equivalent
	 */
	public boolean isEquivalent(ParamList obj);
}
