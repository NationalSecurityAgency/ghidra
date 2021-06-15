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
package ghidra.program.model.listing;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * 
 *  Defines an object that stores a value of some specific data type. The
 * variable has a name, type, size, and a comment.
 */
public interface Variable extends Comparable<Variable> {

	/**
	 * Get the Data Type of this variable
	 * 
	 * @return the data type of the variable
	 */
	public DataType getDataType();

	/**
	 * Set the Data Type of this variable and the associated storage whose size matches the 
	 * data type length.
	 * <p>NOTE: The storage and source are ignored if the function does not have custom storage enabled.
	 * @param type the data type
	 * @param storage properly sized storage for the new data type
	 * @param force overwrite conflicting variables
	 * @param source variable storage source (used only for function parameters and return)
	 * @throws InvalidInputException if data type is not a fixed length or violates storage constraints.
	 * @throws VariableSizeException if force is false and data type size causes a conflict 
	 * with other variables
	 */
	public void setDataType(DataType type, VariableStorage storage, boolean force, SourceType source)
			throws InvalidInputException;

	/**
	 * Set the Data Type of this variable using the default alignment behavior (implementation specific). 
	 * The given dataType must have a fixed length.  If contained within a stack-frame, data-type size
	 * will be constrained by existing variables (e.g., equivalent to force=false)
	 * Note: stack offset will be maintained for stack variables.
	 * @param type the data type
	 * @param source signature source 
	 * @throws InvalidInputException if data type is not a fixed length or violates storage constraints.
	 * @throws VariableSizeException if data type size causes a conflict with other variables
	 * @see #setDataType(DataType, boolean, boolean, SourceType)
	 */
	public void setDataType(DataType type, SourceType source) throws InvalidInputException;

	/**
	 * Set the Data Type of this variable. The given dataType must have a fixed length.
	 * @param type the data type
	 * @param alignStack maintain proper stack alignment/justification if supported by implementation.
	 * 			If false and this is a stack variable, the current stack address/offset will not change.
	 * 			If true, the affect is implementation dependent since alignment can
	 * 			not be performed without access to a compiler specification.
	 * @param force overwrite conflicting variables
	 * @param source signature source
	 * @throws InvalidInputException if data type is not a fixed length or violates storage constraints.
	 * @throws VariableSizeException if force is false and data type size causes a conflict 
	 * with other variables
	 * 
	 */
	public void setDataType(DataType type, boolean alignStack, boolean force, SourceType source)
			throws InvalidInputException;

	/**
	 * Get the Name of this variable or null if not assigned or not-applicable
	 *
	 * @return the name of the variable
	 */
	public String getName();

	/**
	 * Get the length of this variable
	 *
	 * @return the length of the variable
	 */
	public int getLength();

	/**
	 * Verify that the variable is valid 
	 * (i.e., storage is valid and size matches variable data type size)
	 * @return true if variable is valid
	 */
	public boolean isValid();

	/**
	 * Returns the function that contains this Variable.  May be null if the variable is not in
	 * a function.
	 * @return containing function or null
	 */

	public Function getFunction();

	/**
	 * Returns the program that contains this variable or is the intended target
	 * @return the program.
	 */
	public Program getProgram();

	/**
	 * Get the source of this variable
	 * @return the source of this variable
	 */
	public SourceType getSource();

	/**
	 * Set the name of this variable.
	 * @param name the name
	 * @param source the source of this variable name
	 * @throws DuplicateNameException
	 * 		if the name collides with the name of another variable.
	 * @throws InvalidInputException
	 * 		if name contains blank characters, is zero length, or is null
	 */
	public void setName(String name, SourceType source) throws DuplicateNameException,
			InvalidInputException;

	/**
	 * Get the Comment for this variable
	 *
	 * @return the comment
	 */
	public String getComment();

	/**
	 * Set the comment for this variable
	 * @param comment the comment
	 */
	public void setComment(String comment);

	/**
	 * Get the variable storage associated with this variable.
	 * @return the variable storage for this variable
	 */
	public VariableStorage getVariableStorage();

	/**
	 * Get the first storage varnode for this variable
	 * @return the first storage varnode associated with this variable
	 * @see #getVariableStorage()
	 */
	public Varnode getFirstStorageVarnode();

	/**
	 * Get the last storage varnode for this variable
	 * @return the last storage varnode associated with this variable
	 * @see #getVariableStorage()
	 */
	public Varnode getLastStorageVarnode();

	/** 
	 * @return true if this is a simple variable consisting of a single stack varnode
	 * which will be returned by either the {@link #getFirstStorageVarnode()} or 
	 * {@link #getLastStorageVarnode()} methods. The stack offset can be obtained using:
	 * <pre>
	 * 		getFirstStorageVarnode().getOffset()
	 *  </pre>
	 */
	public boolean isStackVariable();

	/**
	 * @return true if this variable uses simple or compound storage which contains a stack element.  
	 * If true, the last storage varnode will always be the stack element.
	 * @see #getLastStorageVarnode()
	 */
	public boolean hasStackStorage();

	/** 
	 * @return true if this is a simple variable consisting of a single register varnode
	 * which will be returned by either the {@link #getFirstStorageVarnode()} or 
	 * {@link #getLastStorageVarnode()} methods.  The register can be obtained using the 
	 * {@link #getRegister()} method.
	 */
	public boolean isRegisterVariable();

	/**
	 * @return first storage register associated with this variable, else null is returned.
	 * A variable with compound storage may have more than one register or other storage
	 * in addition to the register returned by this method.
	 * @see #isRegisterVariable()
	 */
	public Register getRegister();

	/**
	 * @return all storage register(s) associated with this variable, else null is returned if 
	 * no registers are used.  A variable with compound storage may have more than one register 
	 * or other storage in addition to the register(s) returned by this method.
	 * @see #isRegisterVariable()
	 * @see #isCompoundVariable()
	 */
	public List<Register> getRegisters();

	/**
	 * @return the minimum address corresponding to the first varnode of this storage
	 * or null if this is a special empty storage: {@link VariableStorage#BAD_STORAGE},
	 * {@link VariableStorage#UNASSIGNED_STORAGE}, {@link VariableStorage#VOID_STORAGE}
	 */
	public Address getMinAddress();

	/**
	 * @return the stack offset associated with simple stack variable (i.e., {@link #isStackVariable()} 
	 * returns true). 
	 * @throws UnsupportedOperationException if storage is not a simple stack variable
	 */
	public int getStackOffset();

	/** 
	 * @return true if this is a simple variable consisting of a single storage memory element
	 * which will be returned by either the {@link #getFirstStorageVarnode()} or 
	 * {@link #getVariableStorage()} methods.
	 */
	public boolean isMemoryVariable();

	/** 
	 * @return true if this is a simple variable consisting of a single storage unique/hash element
	 * which will be returned by either the {@link #getFirstStorageVarnode()} or 
	 * {@link #getVariableStorage()} methods.  The unique hash can be obtained from the 
	 * storage address offset corresponding to the single storage element.
	 */
	public boolean isUniqueVariable();

	/**
	 * @return true if this variable uses compound storage consisting of two or more storage elements
	 * which will be returned by the {@link #getVariableStorage()} method.  Compound variables will
	 * always use a register(s) optionally followed by other storage (i.e., stack).
	 */
	public boolean isCompoundVariable();

	/**
	 * @return true if this variable has been assigned storage.  This is equivalent to 
	 * {@link #getVariableStorage()} != null
	 */
	public boolean hasAssignedStorage();

	/**
	 * @return the first use offset relative to the function entry point. 
	 */
	public int getFirstUseOffset();

	/**
	 * @return the symbol associated with this variable or null if no symbol 
	 * associated.  Certain dynamic variables such as auto-parameters do not
	 * have a symbol and will return null. 
	 */
	public Symbol getSymbol();

	/**
	 * Determine is another variable is equivalent to this variable.
	 * @param variable other variable
	 * @return true if the specified variable is equivalent to this variable
	 */
	public boolean isEquivalent(Variable variable);

}
