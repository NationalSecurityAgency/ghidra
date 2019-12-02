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
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

public class LocalVariableImpl extends VariableImpl implements LocalVariable {

	private int firstUseOffset;

	/**
	 * Construct a stack variable at the specified stack offset with a first-use offset of 0.
	 * @param name variable name or null for default naming
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param stackOffset signed stack offset
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 * @throws AddressOutOfBoundsException if invalid stack offset specified
	 */
	public LocalVariableImpl(String name, DataType dataType, int stackOffset, Program program)
			throws InvalidInputException {
		this(name, 0, dataType, null, null, stackOffset, null, false, program, null);
	}

	/**
	 * Construct a stack variable at the specified stack offset with a first-use offset of 0.
	 * @param name variable name
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param stackOffset
	 * @param program target program
	 * @param sourceType name source type
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 * @throws AddressOutOfBoundsException if invalid stack offset specified
	 */
	public LocalVariableImpl(String name, DataType dataType, int stackOffset, Program program,
			SourceType sourceType) throws InvalidInputException {
		this(name, 0, dataType, null, null, stackOffset, null, false, program, sourceType);
	}

	/**
	 * Construct a register variable with the specified register storage.
	 * @param name variable name or null for default naming
	 * @param firstUseOffset first use function-relative offset (i.e., start of scope).
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param register the register used for the storage.
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * element is specified, or error while resolving storage element for specified datatype
	 */
	public LocalVariableImpl(String name, int firstUseOffset, DataType dataType, Register register,
			Program program) throws InvalidInputException {
		this(name, firstUseOffset, dataType, null, null, null, register, false, program, null);
	}

	/**
	 * Construct a variable with one or more associated storage elements.  Storage elements
	 * may get slightly modified to adjust for the resolved datatype size.
	 * @param name variable name
	 * @param firstUseOffset first use function-relative offset (i.e., start of scope).
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param register the register used for the storage.
	 * @param program target program
	 * @param sourceType name source type
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * element is specified, or error while resolving storage element for specified datatype
	 */
	public LocalVariableImpl(String name, int firstUseOffset, DataType dataType, Register register,
			Program program, SourceType sourceType) throws InvalidInputException {
		this(name, firstUseOffset, dataType, null, null, null, register, false, program,
			sourceType);
	}

	/**
	 * Construct a variable with a single storage element at the specified address.  If address 
	 * is contained within a register it may get realigned to the register based upon the resolved 
	 * datatype length.  Variable storage will be aligned to the least-significant portion of the 
	 * register.
	 * @param name variable name or null for default naming
	 * @param firstUseOffset first use function-relative offset (i.e., start of scope).   
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storageAddr storage address or null if no storage has been identified
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 */
	public LocalVariableImpl(String name, int firstUseOffset, DataType dataType,
			Address storageAddr, Program program) throws InvalidInputException {
		this(name, firstUseOffset, dataType, null, storageAddr, null, null, false, program, null);
	}

	/**
	 * Construct a variable with a single storage element at the specified address.  If address 
	 * is contained within a register it may get realigned to the register based upon the resolved 
	 * datatype length.  Variable storage will be aligned to the least-significant portion of the 
	 * register.
	 * @param name variable name
	 * @param firstUseOffset first use function-relative offset (i.e., start of scope).
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storageAddr storage address or null if no storage has been identified
	 * @param program target program
	 * @param sourceType name source type
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 */
	public LocalVariableImpl(String name, int firstUseOffset, DataType dataType,
			Address storageAddr, Program program, SourceType sourceType)
					throws InvalidInputException {
		this(name, firstUseOffset, dataType, null, storageAddr, null, null, false, program,
			sourceType);
	}

	/**
	 * Construct a variable with one or more associated storage elements.  Storage elements
	 * may get slightly modified to adjust for the resolved datatype size.
	 * @param name variable name or null for default naming
	 * @param firstUseOffset first use function-relative offset (i.e., start of scope).
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storage variable storage (may not be null)
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * element is specified, or error while resolving storage element for specified datatype
	 */
	public LocalVariableImpl(String name, int firstUseOffset, DataType dataType,
			VariableStorage storage, Program program) throws InvalidInputException {
		this(name, firstUseOffset, dataType, storage, null, null, null, false, program, null);
	}

	/**
	 * Construct a variable with one or more associated storage elements.  Storage elements
	 * may get slightly modified to adjust for the resolved datatype size.
	 * @param name variable name or null for default naming
	 * @param firstUseOffset first use function-relative offset (i.e., start of scope).
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storage variable storage (may not be null)
	 * @param force if true storage will be forced even if incorrect size
	 * @param program target program
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * element is specified, or error while resolving storage element for specified datatype
	 */
	public LocalVariableImpl(String name, int firstUseOffset, DataType dataType,
			VariableStorage storage, boolean force, Program program) throws InvalidInputException {
		this(name, firstUseOffset, dataType, storage, null, null, null, force, program, null);
	}

	/**
	 * Construct a variable with one or more associated storage elements.  Storage elements
	 * may get slightly modified to adjust for the resolved datatype size.
	 * @param name variable name
	 * @param firstUseOffset first use function-relative offset (i.e., start of scope).
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storage variable storage (may not be null)
	 * @param force if true storage will be forced even if incorrect size
	 * @param program target program
	 * @param sourceType name source type
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * element is specified, or error while resolving storage element for specified datatype
	 */
	public LocalVariableImpl(String name, int firstUseOffset, DataType dataType,
			VariableStorage storage, boolean force, Program program, SourceType sourceType)
					throws InvalidInputException {
		this(name, firstUseOffset, dataType, storage, null, null, null, force, program, sourceType);
	}

	/**
	 * Construct a local variable.  Only one storage/location may be specified (storage, storageAddr,
	 * stackOffset, register) - all others should be null.  If no storage/location is specified
	 * or is UNASSIGNED, a Void data type may be specified and will be assumed if this type returns
	 * true for {@link #isVoidAllowed()}.
	 * @param name variable name
	 * @param firstUseOffset first use function-relative offset (i.e., start of scope).
	 * Must be 0 when stack locations are specified.
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
	private LocalVariableImpl(String name, int firstUseOffset, DataType dataType,
			VariableStorage storage, Address storageAddr, Integer stackOffset, Register register,
			boolean force, Program program, SourceType sourceType) throws InvalidInputException {
		super(name, dataType, storage, storageAddr, stackOffset, register, force, program,
			sourceType);
		this.firstUseOffset = firstUseOffset;
		if (hasStackStorage() && firstUseOffset != 0) {
			throw new InvalidInputException("Stack-based variable must have firstUseOffset of 0");
		}
	}

	@Override
	public int getFirstUseOffset() {
		return firstUseOffset;
	}

	@Override
	public boolean setFirstUseOffset(int firstUseOffset) {
		this.firstUseOffset = firstUseOffset;
		return true;
	}

}
