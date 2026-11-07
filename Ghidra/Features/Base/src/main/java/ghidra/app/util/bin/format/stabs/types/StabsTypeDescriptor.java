package ghidra.app.util.bin.format.stabs.types;

import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsTypeDescriptorType;
import ghidra.program.model.data.DataType;

public interface StabsTypeDescriptor {

	/**
	 * Gets the DataType being described
	 * @return the described DataType
	 */
	DataType getDataType();

	/**
	 * Gets the SymbolDescriptor this descriptor is located in
	 * @return this descriptors SymbolDescriptor
	 */
	StabsSymbolDescriptor getSymbolDescriptor();

	/**
	 * Gets the original stab string field
	 * @return the original stab
	 */
	String getStab();

	/**
	 * Gets the type descriptor type
	 * @return the type for this type descriptor
	 */
	StabsTypeDescriptorType getType();

	/**
	 * Gets the length of this descriptor
	 * @return this descriptor's length
	 */
	int getLength();
}
