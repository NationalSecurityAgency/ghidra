package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.app.util.demangler.DemangledFunctionReference;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Program;


/**
 * Model for the __function_type_info class.
 */
public final class FunctionTypeInfoModel extends AbstractTypeInfoModel {

	public static final String STRUCTURE_NAME = "__function_type_info";
	public static final String ID_STRING = "N10__cxxabiv120__function_type_infoE";
	private static final String DESCRIPTION = "Model for Function Type Info";

	private DataType typeInfoDataType;

	/**
	 * Constructs a new FunctionTypeInfoModel.
	 * 
	 * @param program the program containing the __function_type_info.
	 * @param address the address of the __function_type_info.
	 */
	public FunctionTypeInfoModel(Program program, Address address) {
		super(program, address);
	}

	@Override
	public String getIdentifier() {
		return ID_STRING;
	}

	/**
	 * Gets the __function_type_info datatype.
	 * 
	 * @return __function_type_info datatype.
	 */
	@Override
	public DataType getDataType() {
		if (typeInfoDataType == null) {
			typeInfoDataType = getDataType(STRUCTURE_NAME, DESCRIPTION);
		}
		return typeInfoDataType;
	}

	/**
	 * Gets the __function_type_info datatype.
	 * 
	 * @param dtm
	 * @return __function_type_info datatype.
	 */
	public static DataType getDataType(DataTypeManager dtm) {
		return getDataType(dtm, STRUCTURE_NAME, DESCRIPTION);
	}

	/**
	 * Gets the function signature of the Function this __function_type_info represents.
	 * 
	 * @return the represented functions signature.
	 * @throws InvalidDataTypeException
	 */
	public String getFunctionSignature() throws InvalidDataTypeException {
		FunctionDefinitionDataType dataType =
				(FunctionDefinitionDataType) ((Pointer) getRepresentedDataType()).getDataType();
		DemangledFunctionReference method = getDemangledFunction(dataType.getPrototypeString());
		return method.toSignature(getNamespace().getName(true));
	}

}
