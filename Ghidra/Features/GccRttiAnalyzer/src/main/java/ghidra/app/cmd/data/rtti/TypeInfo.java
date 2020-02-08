package ghidra.app.cmd.data.rtti;

import ghidra.program.model.data.DataType;
import ghidra.program.model.symbol.Namespace;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.TypeInfoModel;
import ghidra.program.model.address.Address;

/**
 * Interface for modeling std::type_info and its derivatives.
 * <br>
 * All derived models are based on dwarf information from libstdc++.a
 */
public interface TypeInfo {

    static final String SYMBOL_NAME = "typeinfo";

    /**
     * Gets name for the TypeInfo DataType Model
	 * @return the TypeInfo's name
     */
    String getName();

    /**
     * Gets the namespace for this TypeInfo
	 * @return the TypeInfo's namespace
     */
     Namespace getNamespace();

    /**
     * Gets The TypeInfo's typename string
	 * @return the TypeInfo's typename
     */
    String getTypeName();

    /**
     * Gets The TypeInfo's Identifier String
	 * @return the TypeInfo's ID_STRING field
	 * @see TypeInfoModel#ID_STRING
     */
	String getIdentifier();

    /**
     * Gets corresponding structure for this TypeInfo Model
	 * @return the type_info or subclasses DataType
     */
    DataType getDataType();

    /**
     * Gets the DataType represented by this TypeInfo
     * @return the represented DataType
     */
    DataType getRepresentedDataType();

    /**
	 * Gets the address of this TypeInfo structure.
     * @return the TypeInfo's address.
     */ 
    Address getAddress();
}