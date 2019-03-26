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

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.util.exception.InvalidInputException;

/**
 * <code>ReturnParameterImpl</code> represent the function return value.
 * This is special type of parameter whose ordinal is -1 and allows for the use
 * of the 'void' datatype.
 */
public class ReturnParameterImpl extends ParameterImpl {

	/**
	 * Construct a return parameter from another.
	 * @param param parameter to be copied
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated
	 */
	public ReturnParameterImpl(Parameter param, Program program) throws InvalidInputException {
		super(RETURN_NAME, RETURN_ORIDINAL, param.getDataType(),
			param.getVariableStorage().clone(program), false, program, null);
	}

	/**
	 * Construct a return parameter which has no specific storage specified.
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated
	 */
	public ReturnParameterImpl(DataType dataType, Program program) throws InvalidInputException {
		super(RETURN_NAME, RETURN_ORIDINAL, dataType, null, null, null, null, false, program, null);
	}

	/**
	 * Construct a return parameter at the specified stack offset.
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param stackOffset stack offset
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 */
	public ReturnParameterImpl(DataType dataType, int stackOffset, Program program)
			throws InvalidInputException {
		super(RETURN_NAME, RETURN_ORIDINAL, dataType, null, null, stackOffset, null, false, program,
			null);
	}

	/**
	 * Construct a return parameter using the specified register.
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param register storage register
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 */
	public ReturnParameterImpl(DataType dataType, Register register, Program program)
			throws InvalidInputException {
		super(RETURN_NAME, RETURN_ORIDINAL, dataType, null, null, null, register, false, program,
			null);
	}

	/**
	 * Construct a return parameter with a single varnode at the specified address.  
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storageAddr storage address or null if no storage has been identified
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 */
	public ReturnParameterImpl(DataType dataType, Address storageAddr, Program program)
			throws InvalidInputException {
		super(RETURN_NAME, RETURN_ORIDINAL, dataType, null, storageAddr, null, null, false, program,
			null);
	}

	/**
	 * Construct a return parameter with one or more associated storage elements.  Storage elements
	 * may get slightly modified to adjust for the resolved datatype size.
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storage variable storage or null for unassigned storage
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * element is specified, or error while resolving storage element for specified datatype
	 */
	public ReturnParameterImpl(DataType dataType, VariableStorage storage, Program program)
			throws InvalidInputException {
		super(RETURN_NAME, RETURN_ORIDINAL, dataType, storage, false, program, null);
	}

	/**
	 * Construct a return parameter with one or more associated storage elements.  Storage elements
	 * may get slightly modified to adjust for the resolved datatype size.
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storage variable storage or null for unassigned storage
	 * @param force if true storage will be forced even if incorrect size
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * element is specified, or error while resolving storage element for specified datatype
	 */
	public ReturnParameterImpl(DataType dataType, VariableStorage storage, boolean force,
			Program program) throws InvalidInputException {
		super(RETURN_NAME, RETURN_ORIDINAL, dataType, storage, force, program, null);
	}

	@Override
	protected boolean isVoidAllowed() {
		return true;
	}

}
