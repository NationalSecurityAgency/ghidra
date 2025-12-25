package ghidra.app.util.bin.format.stabs;

import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.program.model.data.DataType;

public interface StabsSymbolDescriptor {

	/**
	 * Gets the name of the symbol
	 * @return the symbol's name
	 */
	String getName();

	/**
	 * Gets the original stab string field
	 * @return the original stab
	 */
	String getStab();
	
	/**
	 * Gets the DataType corresponding to this symbol
	 * @return the symbol's DataType or null if there is none
	 */
	DataType getDataType();

	/**
	 * Gets the file this symbol was declared in
	 * @return the StabFile containing this symbol
	 */
	StabsFile getFile();

	/**
	 * Gets the symbol descriptor type
	 * @return the type for this symbol descriptor
	 */
	StabsSymbolDescriptorType getSymbolDescriptorType();

	/**
	 * Gets the type information field following the symbol descriptor if any
	 * @return the type information or null if there is none
	 */
	StabsTypeDescriptor getTypeInformation();
}
