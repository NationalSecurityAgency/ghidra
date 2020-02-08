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
 * Model for the {@value #STRUCTURE_NAME} class.
 */
public final class FunctionTypeInfoModel extends AbstractTypeInfoModel {

    public static final String STRUCTURE_NAME = "__function_type_info";
    public static final String ID_STRING = "N10__cxxabiv120__function_type_infoE";
    private static final String DESCRIPTION = "Model for Function Type Info";

    private DataType typeInfoDataType;

	/**
	 * Gets a new FunctionTypeInfoModel
	 * @param program the program containing the {@value #STRUCTURE_NAME}
	 * @param address the address of the {@value #STRUCTURE_NAME}
	 * @return the new FunctionTypeInfoModel
	 * @throws InvalidDataTypeException if the data at the address
	 * is not a valid {@value #STRUCTURE_NAME}
	 */
	public static FunctionTypeInfoModel getModel(Program program, Address address)
		throws InvalidDataTypeException {
			if (isValid(program, address, ID_STRING)) {
				return new FunctionTypeInfoModel(program, address);
			}
			throw new InvalidDataTypeException(getErrorMessage(address));
	}

    private FunctionTypeInfoModel(Program program, Address address) {
        super(program, address);
    }

    @Override
    public String getIdentifier() {
        return ID_STRING;
    }

    /**
     * Gets the __function_type_info datatype.
     */
    @Override
    public DataType getDataType() {
        if (typeInfoDataType == null) {
            typeInfoDataType = getDataType(STRUCTURE_NAME, DESCRIPTION);
        }
        return typeInfoDataType;
    }

    /**
     * Gets the {@value #STRUCTURE_NAME} datatype
     * @param dtm the DataTypeManager
     * @return the {@value #STRUCTURE_NAME} datatype
     */
    public static DataType getDataType(DataTypeManager dtm) {
        return getDataType(dtm, STRUCTURE_NAME, DESCRIPTION);
    }

    /**
     * Gets the function signature of the Function this __function_type_info represents.
     * 
     * @return the represented functions signature.
     */
    public String getFunctionSignature() {
        FunctionDefinitionDataType dataType =
                (FunctionDefinitionDataType) ((Pointer) getRepresentedDataType()).getDataType();
        DemangledFunctionReference method = getDemangledFunction(dataType.getPrototypeString());
        return method.toSignature(getNamespace().getName(true));
    }

}
