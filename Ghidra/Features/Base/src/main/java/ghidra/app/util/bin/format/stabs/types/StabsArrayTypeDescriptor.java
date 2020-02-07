package ghidra.app.util.bin.format.stabs.types;

import ghidra.app.util.bin.format.stabs.*;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;

import static ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptorFactory.getTypeDescriptor;

/**
 * Array implementation of the StabTypeDescriptor
 */
public final class StabsArrayTypeDescriptor extends AbstractStabsTypeDescriptor {

	private static enum Groups {
		LOWER,
		UPPER,
		CONTENTS
	}

	private static final String INDEX_TYPE_PATTERN = String.format(
		"(?:(?:@s?\\d+;)?(?:r(?:%1$s));-?\\d+;\\d+;)", StabsTypeNumber.TYPE_NUMBER_PATTERN);
	private static final String LOWER_PATTERN = "(?<%%s>\\d+)";
	private static final String UPPER_PATTERN = "(?<%%s>-?\\d+)";
	private static final String CONTENTS_TYPE_PATTERN = "(?<%%s>%1$s(?:=.+)?)";

	private static final String PATTERN =
		String.format(
			"ar(?:%1$s)=?"+INDEX_TYPE_PATTERN+"?;"+LOWER_PATTERN+";"
			+UPPER_PATTERN+";"+CONTENTS_TYPE_PATTERN,
			StabsTypeNumber.TYPE_NUMBER_PATTERN);

	private static final StabsTokenizer<Groups> TOKENIZER =
		new StabsTokenizer<>(PATTERN, Groups.class);

	private final StabsToken<Groups> token;
	private final DataType dt;
	private final StabsTypeDescriptor subType;
	private boolean isTrailingArray = false;

	/**
	 * Constructs a new StabsArrayTypeDescriptor
	 * @param symbol the symbol this descriptor is located in
	 * @param stab the portion of the stab containing this descriptor
	 * @throws StabsParseException if the descriptor or one it relies on is invalid
	 */
	StabsArrayTypeDescriptor(StabsSymbolDescriptor symbol, String stab) throws StabsParseException {
		super(symbol, stab);
		this.token = TOKENIZER.getToken(stab);
		this.subType = getSubType();
		this.dt = makeArray();
	}

	private StabsTypeDescriptor getSubType() throws StabsParseException {
		String subStab = stab.substring(token.start(Groups.CONTENTS));
		return getTypeDescriptor(symbol, subStab);
	}

	private DataType makeArray() throws StabsParseException {
		DataType elementType = subType.getDataType();
		// minimum index, maximum index, type number
		if (Long.valueOf(token.get(Groups.LOWER)) == 0) {
			// sanity check

			// the overflow allows the case where 0xffffffff is
			// used as the max for a trailing array
			int size = (int) ((Long.valueOf(token.get(Groups.UPPER))+1) & 0xffffffff);
			if (size == 0) {
				isTrailingArray = true;
				return elementType;
			}
			return new ArrayDataType(elementType, size, elementType.getLength());
		}
		throw new StabsParseException(symbol.getName(), stab);
	}

	@Override
	public DataType getDataType() {
		return dt;
	}

	@Override
	public StabsTypeDescriptorType getType() {
		return StabsTypeDescriptorType.ARRAY;
	}

	@Override
	public int getLength() {
		return (token.getLength() - token.start(Groups.CONTENTS)) + subType.getLength();
	}

	/**
	 * Checks if this array may be a trailing array
	 * @return true if this is a trailing array.
	 * @see ghidra.program.model.data.Structure#hasFlexibleArrayComponent()
	 * Structure.hasFlexibleArrayComponent()
	 */
	public boolean isTrailingArray() {
		return isTrailingArray;
	}
}
