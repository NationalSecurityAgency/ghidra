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
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.InvalidInputException;

/**
 * Generic implementation of Parameter.
 */
public class ParameterImpl extends VariableImpl implements Parameter {

	protected int ordinal;

	/**
	 * Construct a parameter from another.
	 * @param param parameter to be copied
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated
	 */
	public ParameterImpl(Parameter param, Program program) throws InvalidInputException {
		this(param.getName(), param.getOrdinal(), param.getDataType(),
			param.getVariableStorage().clone(program), null, null, null, false, program,
			param.getSource());
	}

	/**
	 * Construct a parameter which has no specific storage specified.
	 * Ordinal assignment is not established (UNASSIGNED_ORDINAL).
	 * @param name variable name or null for default name
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated
	 */
	public ParameterImpl(String name, DataType dataType, Program program)
			throws InvalidInputException {
		this(name, UNASSIGNED_ORDINAL, dataType, null, null, null, null, false, program, null);
	}

	/**
	 * Construct a parameter which has no specific storage specified.
	 * Ordinal assignment is not established (UNASSIGNED_ORDINAL).
	 * @param name variable name or null for default name
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param program target program
	 * @param sourceType name source type
	 * @throws InvalidInputException if dataType restrictions are violated
	 */
	public ParameterImpl(String name, DataType dataType, Program program, SourceType sourceType)
			throws InvalidInputException {
		this(name, UNASSIGNED_ORDINAL, dataType, null, null, null, null, false, program,
			sourceType);
	}

	/**
	 * Construct a stack parameter at the specified stack offset.
	 * Ordinal assignment is not established (UNASSIGNED_ORDINAL).
	 * @param name variable name or null for default name
	 * @param dataType a fixed-length datatype. (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param stackOffset
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 * @throws AddressOutOfBoundsException if invalid stack offset specified
	 */
	public ParameterImpl(String name, DataType dataType, int stackOffset, Program program)
			throws InvalidInputException {
		this(name, UNASSIGNED_ORDINAL, dataType, null, null, stackOffset, null, false, program,
			null);
	}

	/**
	 * Construct a stack parameter at the specified stack offset.
	 * Ordinal assignment is not established (UNASSIGNED_ORDINAL).
	 * @param name variable name or null for default name
	 * @param dataType a fixed-length datatype. (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param stackOffset
	 * @param program target program
	 * @param sourceType name source type
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 * @throws AddressOutOfBoundsException if invalid stack offset specified
	 */
	public ParameterImpl(String name, DataType dataType, int stackOffset, Program program,
			SourceType sourceType) throws InvalidInputException {
		this(name, UNASSIGNED_ORDINAL, dataType, null, null, stackOffset, null, false, program,
			sourceType);
	}

	/**
	 * Construct a register parameter using the specified register.
	 * Ordinal assignment is not established (UNASSIGNED_ORDINAL).
	 * @param name variable name or null for default name
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param register
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 */
	public ParameterImpl(String name, DataType dataType, Register register, Program program)
			throws InvalidInputException {
		this(name, UNASSIGNED_ORDINAL, dataType, null, null, null, register, false, program, null);
	}

	/**
	 * Construct a register parameter using the specified register.
	 * Ordinal assignment is not established (UNASSIGNED_ORDINAL).
	 * @param name variable name or null for default name
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param register
	 * @param program target program
	 * @param sourceType name source type
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 */
	public ParameterImpl(String name, DataType dataType, Register register, Program program,
			SourceType sourceType) throws InvalidInputException {
		this(name, UNASSIGNED_ORDINAL, dataType, null, null, null, register, false, program,
			sourceType);
	}

	/**
	 * Construct a parameter with a single storage element at the specified address.  If address 
	 * is contained within a register it may get realigned to the register based upon the resolved 
	 * datatype length.  Variable storage will be aligned to the least-significant portion of the 
	 * register.  Ordinal assignment is not established (UNASSIGNED_ORDINAL).
	 * @param name variable name or null for default name
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storageAddr storage address or null if no storage has been identified
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 */
	public ParameterImpl(String name, DataType dataType, Address storageAddr, Program program)
			throws InvalidInputException {
		this(name, UNASSIGNED_ORDINAL, dataType, null, storageAddr, null, null, false, program,
			null);
	}

	/**
	 * Construct a parameter with a single storage element at the specified address.  If address 
	 * is contained within a register it may get realigned to the register based upon the resolved 
	 * datatype length.  Variable storage will be aligned to the least-significant portion of the 
	 * register.  Ordinal assignment is not established (UNASSIGNED_ORDINAL).
	 * @param name variable name or null for default name
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storageAddr storage address or null if no storage has been identified
	 * @param program target program
	 * @param sourceType name source type
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 */
	public ParameterImpl(String name, DataType dataType, Address storageAddr, Program program,
			SourceType sourceType) throws InvalidInputException {
		this(name, UNASSIGNED_ORDINAL, dataType, null, storageAddr, null, null, false, program,
			sourceType);
	}

	/**
	 * Construct a parameter with one or more associated storage elements.  Storage elements
	 * may get slightly modified to adjust for the resolved datatype size.  Ordinal assignment
	 * is not established (UNASSIGNED_ORDINAL).
	 * @param name variable name or null for default name
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storage variable storage or null for unassigned storage
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * element is specified, or error while resolving storage element for specified datatype
	 */
	public ParameterImpl(String name, DataType dataType, VariableStorage storage, Program program)
			throws InvalidInputException {
		this(name, UNASSIGNED_ORDINAL, dataType, storage, null, null, null, false, program, null);
	}

	/**
	 * Construct a parameter with one or more associated storage elements.  Storage elements
	 * may get slightly modified to adjust for the resolved datatype size.  Ordinal assignment
	 * is not established (UNASSIGNED_ORDINAL).
	 * @param name variable name or null for default name
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storage variable storage or null for unassigned storage
	 * @param program target program
	 * @param sourceType name source type
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * element is specified, or error while resolving storage element for specified datatype
	 */
	public ParameterImpl(String name, DataType dataType, VariableStorage storage, Program program,
			SourceType sourceType) throws InvalidInputException {
		this(name, UNASSIGNED_ORDINAL, dataType, storage, null, null, null, false, program,
			sourceType);
	}

	/**
	 * Construct a parameter with one or more associated storage elements.  Storage elements
	 * may get slightly modified to adjust for the resolved datatype size.
	 * @param name variable name or null for default name
	 * @param ordinal parameter ordinal (-1 for return ordinal)
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storage variable storage or null for unassigned storage
	 * @param force if true storage will be forced even if incorrect size
	 * @param program target program
	 * @param sourceType name source type
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * element is specified, or error while resolving storage element for specified datatype
	 */
	protected ParameterImpl(String name, int ordinal, DataType dataType, VariableStorage storage,
			boolean force, Program program, SourceType sourceType) throws InvalidInputException {
		this(name, ordinal, dataType, storage, null, null, null, force, program, sourceType);
	}

	/**
	 * Construct a local variable.  Only one storage/location may be specified (storage, storageAddr,
	 * stackOffset, register) - all others should be null.  If no storage/location is specified
	 * or is UNASSIGNED, a Void data type may be specified and will be assumed if this type returns
	 * true for {@link #isVoidAllowed()}.
	 * @param name variable name
	 * @param ordinal parameter ordinal (-1 for return ordinal)
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storage variable storage or null for unassigned storage (may be null)
	 * @param storageAddr storage address or null if no storage has been identified (may be null)
	 * @param stackOffset signed stack offset (may be null)
	 * @param register register storage (may be null)
	 * @param force if true storage will be forced even if mismatch with datatype size
	 * @param program target program
	 * @param sourceType source type
	 * @throws InvalidInputException if dataType restrictions are violated or an error occurs while 
	 * resolving storage for specified datatype
	 * @throws AddressOutOfBoundsException if invalid stack offset specified
	 */
	ParameterImpl(String name, int ordinal, DataType dataType, VariableStorage storage,
			Address storageAddr, Integer stackOffset, Register register, boolean force,
			Program program, SourceType sourceType) throws InvalidInputException {
		super(name, dataType, storage, storageAddr, stackOffset, register, force, program,
			sourceType);
		this.ordinal = ordinal;
	}

	@Override
	protected final boolean hasDefaultName() {
		return SymbolUtilities.isDefaultParameterName(getName());
	}

	@Override
	public final int getOrdinal() {
		return ordinal;
	}

	@Override
	public final int getFirstUseOffset() {
		return 0;
	}

	@Override
	public DataType getDataType() {
		DataType dt = getFormalDataType();
		VariableStorage varStorage = getVariableStorage();
		if (varStorage.isForcedIndirect()) {
			Program program = getProgram();
			DataTypeManager dtm = program.getDataTypeManager();
			int ptrSize = varStorage.size();
			if (ptrSize != dtm.getDataOrganization().getPointerSize()) {
				dt = dtm.getPointer(dt, ptrSize);
			}
			else {
				dt = dtm.getPointer(dt);
			}
		}
		return dt;
	}

	@Override
	public DataType getFormalDataType() {
		return super.getDataType();
	}

	@Override
	public boolean isForcedIndirect() {
		VariableStorage varStorage = getVariableStorage();
		return varStorage != null ? varStorage.isForcedIndirect() : false;
	}

	@Override
	public boolean isAutoParameter() {
		VariableStorage varStorage = getVariableStorage();
		return varStorage != null ? varStorage.isAutoStorage() : false;
	}

	@Override
	public AutoParameterType getAutoParameterType() {
		VariableStorage varStorage = getVariableStorage();
		return varStorage != null ? varStorage.getAutoParameterType() : null;
	}

}
