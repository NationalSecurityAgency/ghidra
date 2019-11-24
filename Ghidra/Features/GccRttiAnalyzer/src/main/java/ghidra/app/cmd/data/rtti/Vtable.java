package ghidra.app.cmd.data.rtti;

import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public interface Vtable {
	
	public static final Vtable NO_VTABLE = VtableModel.NO_VTABLE;

	/**
	 * Returns the TypeInfo Model this vtable points to.
	 * 
	 * @return the pointed to TypeInfo Model.
	 */
	public ClassTypeInfo getTypeInfo() throws InvalidDataTypeException;

	/**
	 * Checks if this is a valid vtable.
	 * 
	 * @throws InvalidDataTypeException in the vftable is not valid.
	 */
	public void validate() throws InvalidDataTypeException;

	/**
	 * Gets the addresses of this vtable's function tables.
	 * 
	 * @return the addresses of this vtable's function tables.
	 * @throws InvalidDataTypeException
	 */
	public Address[] getTableAddresses() throws InvalidDataTypeException;

	/**
	 * Gets the function tables in this vtable.
	 * 
	 * @return this vtable's function tables.
	 * @throws InvalidDataTypeException
	 */
	public Function[][] getFunctionTables()throws InvalidDataTypeException;

	/**
	 * Checks if this vtable contains the specified function.
	 * 
	 * @param function
	 * @return true if this vtable contains the specified function.
	 * @throws InvalidDataTypeException
	 */
	public boolean containsFunction(Function function)throws InvalidDataTypeException;
}