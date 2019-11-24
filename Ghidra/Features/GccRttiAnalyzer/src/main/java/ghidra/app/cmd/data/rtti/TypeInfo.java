package ghidra.app.cmd.data.rtti;

import ghidra.program.model.data.DataType;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;

/**
 * Interface for modeling std::type_info and its derivatives.
 * <br>
 * All implemented models are based on dwarf information from libstdc++.a
 */
public interface TypeInfo {

	static final String SYMBOL_NAME = "typeinfo";

	/**
	 * Gets name for the TypeInfo DataType Model
	 * 
	 * @throws InvalidDataTypeException
	 */
	String getName() throws InvalidDataTypeException;

	/**
	 * Gets the namespace for this TypeInfo
	 * 
	 * @throws InvalidDataTypeException
	 */
	 Namespace getNamespace() throws InvalidDataTypeException;

	/**
	 * Gets The TypeInfo's typename string
	 * 
	 * @throws InvalidDataTypeException
	 */
	String getTypeName() throws InvalidDataTypeException;

	/**
	 * Gets The TypeInfo's Identifier String ie "St9type_info"
	 * 
	 */
	String getIdentifier();

	/**
	 * Gets corresponding structure for this TypeInfo Model
	 * 
	 */
	DataType getDataType();

	/**
	 * Gets the DataType represented by this TypeInfo
	 * 
	 * @return the represented DataType
	 * @throws InvalidDataTypeException
	 */
	DataType getRepresentedDataType() throws InvalidDataTypeException;

	/**
	 * Gets the address of this TypeInfo structure.
	 * 
	 * @return the TypeInfo structure's address.
	 */ 
	Address getAddress();

	/**
	 * Checks if the TypeInfo is a valid type_info structure.
	 * 
	 * @throws InvalidDataTypeException
	 */
	void validate() throws InvalidDataTypeException;

}