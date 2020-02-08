package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Program;

/**
 * Model for the {@value #STRUCTURE_NAME} class.
 */
public final class ArrayTypeInfoModel extends AbstractTypeInfoModel {

    private static final String DESCRIPTION = "Model for Array Type Info";
	public static final String STRUCTURE_NAME = "__array_type_info";

    public static final String ID_STRING = "N10__cxxabiv117__array_type_infoE";
    private static final Pattern ARRAY_PATTERN = Pattern.compile(".*A(\\d*)_(.*)");
    
    private DataType dataType;
	private DataType typeInfoDataType;
	
	/**
	 * Gets a new ArrayTypeInfoModel
	 * @param program the program containing the {@value #STRUCTURE_NAME}
	 * @param address the address of the {@value #STRUCTURE_NAME}
	 * @return the new ArrayTypeInfoModel
	 * @throws InvalidDataTypeException if the data at the address
	 * is not a valid {@value #STRUCTURE_NAME}
	 */
	public static ArrayTypeInfoModel getModel(Program program, Address address)
		throws InvalidDataTypeException {
			if (isValid(program, address, ID_STRING)) {
				return new ArrayTypeInfoModel(program, address);
			}
			throw new InvalidDataTypeException(getErrorMessage(address));
	}

    private ArrayTypeInfoModel(Program program, Address address) {
        super(program, address);
    }

    /**
     * Gets the __array_type_info datatype.
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

    @Override
    public String getIdentifier() {
        return ID_STRING;
    }

    @Override
    public DataType getRepresentedDataType() {
        if (dataType == null) {
            Matcher matcher = ARRAY_PATTERN.matcher(getTypeName());
            if (matcher.matches()) {
                int length = Integer.valueOf(matcher.group(1));
                DataType baseDt = parseDataType(matcher.group(2));
                dataType = new ArrayDataType(baseDt, length, baseDt.getLength());
            }
        }
        return dataType;
    }

}
