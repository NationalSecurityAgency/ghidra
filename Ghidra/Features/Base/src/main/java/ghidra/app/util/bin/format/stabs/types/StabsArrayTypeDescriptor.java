package ghidra.app.util.bin.format.stabs.types;

import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsToken;
import ghidra.app.util.bin.format.stabs.StabsTokenizer;
import ghidra.app.util.bin.format.stabs.StabsTypeDescriptorType;
import ghidra.app.util.bin.format.stabs.StabsTypeNumber;
import ghidra.program.model.data.*; // so Structure doesn't need to be imported for docs

import static ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptorFactory.getTypeDescriptor;

/**
 * Array implementation of the StabTypeDescriptor
 */
public final class StabsArrayTypeDescriptor extends AbstractStabsTypeDescriptor {

	private static enum Groups {
		START,
		END,
		TYPE
	}

	private static final String PATTERN_1 =
		String.format("ar(%1$s);(?<%%s>\\d+);(?<%%s>(?:\\d+)|(?:\\-1));(?<%%s>%1$s)",
			StabsTypeNumber.TYPE_NUMBER_PATTERN);
	
	private static final String PATTERN_2 =
		String.format("ar(%1$s)=(?:(?:@s\\d+);)?r(\\1);\\-?\\d+;\\d+;+"
			+"(?<%%s>\\d+);(?<%%s>(?:\\d+)|(?:\\-1));(?<%%s>%1$s)",
			StabsTypeNumber.TYPE_NUMBER_PATTERN);
	
	private static final StabsTokenizer<Groups> TOKENIZER_1 =
		new StabsTokenizer<>(PATTERN_1, Groups.class);

	private static final StabsTokenizer<Groups> TOKENIZER_2 =
		new StabsTokenizer<>(PATTERN_2, Groups.class);

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
		if (TOKENIZER_1.canTokenize(stab)) {
			this.token = TOKENIZER_1.getToken(stab);
		} else if (TOKENIZER_2.canTokenize(stab)) {
			this.token = TOKENIZER_2.getToken(stab);
		} else {
			throw new StabsParseException(symbol.getName(), stab);
		}
		this.subType = getSubType();
		this.dt = makeArray();
	}

	private StabsTypeDescriptor getSubType() throws StabsParseException {
		final String subStab = stab.substring(token.start(Groups.TYPE));
		return getTypeDescriptor(symbol, subStab);
	}

	private DataType makeArray() throws StabsParseException {	
		final DataType elementType = subType.getDataType();
		// minimum index, maximum index, type number
		if (Integer.valueOf(token.get(Groups.START)) == 0) {
			// sanity check
			final int size = Integer.valueOf(token.get(Groups.END))+1;
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
		return (token.getLength() - token.start(Groups.TYPE)) + subType.getLength();
	}

	/**
	 * Checks if this array may be a trailing array
	 * @return true if this is a trailing array.
	 * @see Structure#hasFlexibleArrayComponent()
	 */
	public boolean isTrailingArray() {
		return isTrailingArray;
	}
}
