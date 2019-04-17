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
package ghidra.program.model.listing;

import ghidra.program.model.data.DataType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Definition of a stack frame.
 * All offsets into a stack are from a zero base.  Usually
 * negative offsets are parameters and positive offsets are
 * locals.  That does not have to be the case, it depends on whether
 * the stack grows positively or negatively.  On an a 80x86 architecture,
 * the stack grows negatively.  When a value is pushed onto the stack,
 * the stack pointer is decremented by some size.
 *
 * <p>Each frame consists of a local sections, parameter section, and save
 * information (return address, saved registers, etc...).  A frame is said to
 * grow negative if the parameters are referenced with negative offsets from 0,
 * or positive if the parameters are referenced with negative offsets from 0.
 * <p> <pre>
 *
 *
 *  Negative Growth
 *                    -5      local2 (2 bytes)
 *                    -3      local1 (4 bytes)
 *   frame base        0      stuff (4 bytes)
 *   return offset     4      return addr (4 bytes)
 *   param offset      8      param2 (4 bytes)
 *                    12      param1
 *
 *       
 *  Positive Growth
 *                   -15     param offset 1
 *                   -11     param offset 2
 *   param offset     -8     
 *   return offset    -7     return address
 *                    -3     stuff 
 *   frame base        0     local 1
 *                     4     local 2
 *                     8     
 *</pre>
 *
 */
public interface StackFrame {
	/**
	 * Indicator for a Stack that grows negatively.
	 */
	public final static int GROWS_NEGATIVE = -1;
	/**
	 * Indicator for a Stack that grows positively.
	 */
	public final static int GROWS_POSITIVE = 1;
	/**
	 * Indicator for a unknown stack parameter offset
	 */
	public static final int UNKNOWN_PARAM_OFFSET = (128 * 1024);

	/**
	 * Get the function that this stack belongs to.
	 * This could return null if the stack frame isn't part of a function.
	 *
	 * @return the function
	 */
	public Function getFunction();

	/**
	 * Get the size of this stack frame in bytes.
	 *
	 * @return stack frame size
	 */
	public int getFrameSize();

	/**
	 * Get the local portion of the stack frame in bytes.
	 *
	 * @return local frame size
	 */
	public int getLocalSize();

	/**
	 * Get the parameter portion of the stack frame in bytes.
	 *
	 * @return parameter frame size
	 */
	public int getParameterSize();

	/**
	 * Get the offset to the start of the parameters.
	 *
	 * @return offset
	 */
	public int getParameterOffset();

//	/**
//	 * Set the offset on the stack of the parameters.
//	 *
//	 * @param offset the start offset of parameters on the stack
//	 */
//	public void setParameterOffset(int offset) throws InvalidInputException;

	/**
	 * Returns true if specified offset could correspond to a parameter
	 * @param offset
	 */
	public boolean isParameterOffset(int offset);

	/**
	 * Set the size of the local stack in bytes.
	 *
	 * @param size size of local stack
	 */
	public void setLocalSize(int size);

	/**
	 * Set the return address stack offset.
	 * @param offset offset of return address.
	 */
	public void setReturnAddressOffset(int offset);

	/**
	 * Get the return address stack offset.
	 *
	 * @return return address offset.
	 */
	public int getReturnAddressOffset();

	/**
	 * Get the stack variable containing offset.  This may fall in
	 * the middle of a defined variable.
	 *
	 * @param offset offset of on stack to get variable.
	 */
	public Variable getVariableContaining(int offset);

	/**
	 * Create a stack variable.  It could be a parameter or a local depending
	 * on the direction of the stack.
	 * <p><B>WARNING!</B> Use of this method to add parameters may force the function
	 * to use custom variable storage.  In addition, parameters may be appended even if the
	 * current calling convention does not support them.
	 * @throws DuplicateNameException if another variable(parameter or local) already
	 * exists in the function with that name.
	 * @throws InvalidInputException if data type is not a fixed length or variable name is invalid.
	 * @throws VariableSizeException if data type size is too large based upon storage constraints.
	 */
	public Variable createVariable(String name, int offset, DataType dataType, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Clear the stack variable defined at offset
	 *
	 * @param offset Offset onto the stack to be cleared.
	 */
	public void clearVariable(int offset);

	/**
	 * Get all defined stack variables.
	 * Variables are returned from least offset (-) to greatest offset (+)
	 *
	 * @return an array of parameters.
	 */
	public Variable[] getStackVariables();

	/**
	 * Get all defined parameters as stack variables.
	 *
	 * @return an array of parameters.
	 */
	public Variable[] getParameters();

	/**
	 * Get all defined local variables.
	 *
	 * @return an array of all local variables
	 */
	public Variable[] getLocals();

	/**
	 * A stack that grows negative has local references negative and
	 * parameter references positive.  A positive growing stack has
	 * positive locals and negative parameters.
	 *
	 * @return true if the stack grows in a negative direction.
	 */
	public boolean growsNegative();
}
