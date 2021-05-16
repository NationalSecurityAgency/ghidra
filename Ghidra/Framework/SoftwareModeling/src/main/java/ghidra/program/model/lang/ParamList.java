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

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
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
	 * Given a list of datatypes, calculate the storage locations used for passing those datatypes
	 * @param prog is the active progra
	 * @param proto is the list of datatypes
	 * @param isinput is true if this parameter list is being processed for input arguments, false for output
	 * @param res is the vector for holding the VariableStorage corresponding to datatypes
	 * @param addAutoParams if true add/process auto-parameters
	 */
	public void assignMap(Program prog, DataType[] proto, boolean isinput,
			ArrayList<VariableStorage> res, boolean addAutoParams);

	public void saveXml(StringBuilder buffer, boolean isInput);

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

	public boolean isThisBeforeRetPointer();
}
