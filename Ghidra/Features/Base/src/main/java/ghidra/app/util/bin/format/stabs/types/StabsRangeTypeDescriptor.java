package ghidra.app.util.bin.format.stabs.types;

import java.math.BigInteger;

import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsToken;
import ghidra.app.util.bin.format.stabs.StabsTokenizer;
import ghidra.app.util.bin.format.stabs.StabsTypeDescriptorType;
import ghidra.app.util.bin.format.stabs.StabsTypeNumber;
import ghidra.app.util.bin.format.stabs.StabsUtils;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.BuiltIn;
import ghidra.program.model.data.DataType;

/**
 * Range Type implementation of the StabTypeDescriptor
 */
public final class StabsRangeTypeDescriptor extends AbstractStabsTypeDescriptor {

	private static enum Groups {
		TYPE,
		LOWER,
		UPPER
	}

	private static final String PATTERN = String.format(
		"r(?<%%s>%s);(?<%%s>\\-?\\d+);(?<%%s>\\d+)", StabsTypeNumber.TYPE_NUMBER_PATTERN);

	private static final StabsTokenizer<Groups> TOKENIZER =
		new StabsTokenizer<>(PATTERN, Groups.class);

	private final StabsToken<Groups> token;
	private BigInteger start;
	private BigInteger end;
	private final DataType dt;

	/**
	 * Constructs a new StabsRangeTypeDescriptor
	 * @param symbol the token this descriptor is located in
	 * @param stab the portion of the stab containing this descriptor
	 * @throws StabsParseException if this descriptor is invalid
	 */
	StabsRangeTypeDescriptor(StabsSymbolDescriptor symbol, String stab) throws StabsParseException {
		super(symbol, stab);
		this.token = TOKENIZER.getToken(stab);
		if (StabsUtils.isBuiltin(symbol.getName())) {
			this.dt = StabsUtils.getBuiltin(symbol.getName()).clone(dtm);
		} else {
			this.start = new BigInteger(token.get(Groups.LOWER));
			this.end = new BigInteger(token.get(Groups.UPPER));
			this.dt = doGetDataType();
		}
	}

	private DataType doGetDataType() {
		int size = StabsUtils.getIntegerSize(getEnd());
		if (start.compareTo(BigInteger.ZERO) < 0) {
			// signed
			return AbstractIntegerDataType.getSignedDataType(size, dtm);
		}
		return AbstractIntegerDataType.getUnsignedDataType(size, dtm);
	}

	@Override
	public DataType getDataType() {
		return dt;
	}

	@Override
	public StabsTypeDescriptorType getType() {
		return StabsTypeDescriptorType.RANGE;
	}

	@Override
	public int getLength() {
		return token.getLength();
	}

	/**
	 * Gets the start of the range
	 * @return the range start
	 */
	public BigInteger getStart() {
		return start;
	}

	/**
	 * Gets the end of the range
	 * @return the range end
	 */
	public BigInteger getEnd() {
		return end;
	}

	/**
	 * Checks if this is describing a builtin datatype
	 * @return true if this is a builtin type
	 */
	public boolean isBuiltin() {
		return dt instanceof BuiltIn;
	}
}
