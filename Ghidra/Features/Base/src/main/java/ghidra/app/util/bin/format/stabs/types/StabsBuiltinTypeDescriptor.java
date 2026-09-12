package ghidra.app.util.bin.format.stabs.types;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsTypeDescriptorType;
import ghidra.app.util.bin.format.stabs.StabsTypeNumber;
import ghidra.program.model.data.*;

/**
 * Builtin Type implementation of the StabTypeDescriptor
 */
public final class StabsBuiltinTypeDescriptor extends AbstractStabsTypeDescriptor {

	private static final Pattern INTEGER_PATTERN = Pattern.compile("b([su])(c)?\\d+;\\d+;(\\d+);");
	private static final Pattern NEGATIVE_PATTERN = Pattern.compile("(\\-\\d+).*");

	private final int length;
	private final BuiltinType type;
	private final DataType dt;

	/**
	 * Constructs a new StabsBuiltinTypeDescriptor
	 * @param symbol the token this descriptor is located in
	 * @param stab the portion of the stab containing this descriptor
	 * @throws StabsParseException if this descriptor is invalid
	 */
	StabsBuiltinTypeDescriptor(StabsSymbolDescriptor symbol, String stab) throws StabsParseException {
		super(symbol, stab);
		this.type = doGetBuiltinType(stab.charAt(0));
		this.length = type.getLength(symbol, stab);
		switch (type) {
			case FLOAT:
				this.dt = getFloatDataType();
				break;
			case INTEGRAL:
				this.dt = getIntegerDataType();
				break;
			case NEGATIVE:
				this.dt = getNegativeDataType();
				break;
			case WIDE_CHAR:
				this.dt = WideCharDataType.dataType.clone(dtm);
				break;
			case AIX_FLOAT:
				this.dt = getAixFloatDataType();
				break;
			case COMPLEX:
				this.dt = getAixComplexDataType();
				break;
			default:
				throw getError();
		}
	}

	private DataType getNegativeDataType() throws StabsParseException {
		Matcher matcher = NEGATIVE_PATTERN.matcher(stab);
		if (matcher.matches()) {
			switch (Integer.valueOf(matcher.group(1))) {
				case -1:
				case -15:
				case -29:
					return IntegerDataType.dataType.clone(dtm);
				case -2:
					return CharDataType.dataType.clone(dtm);
				case -3:
				case -28:
					return ShortDataType.dataType.clone(dtm);
				case -4:
					return LongDataType.dataType.clone(dtm);
				case -5:
					return ByteDataType.dataType.clone(dtm);
				case -6:
				case -21:
				case -27:
					return SignedByteDataType.dataType.clone(dtm);
				case -7:
					return UnsignedShortDataType.dataType.clone(dtm);
				case -8:
				case -9:
					return UnsignedIntegerDataType.dataType.clone(dtm);
				case -10:
					return UnsignedLongDataType.dataType.clone(dtm);
				case -11:
					return DataType.VOID;
				case -12:
					return FloatDataType.dataType.clone(dtm);
				case -13:
					return DoubleDataType.dataType.clone(dtm);
				case -14:
					return LongDoubleDataType.dataType.clone(dtm);
				case -16:
					return BooleanDataType.dataType.clone(dtm);
				case -17:
					return FloatComplexDataType.dataType.clone(dtm);
				case -18:
					return DoubleComplexDataType.dataType.clone(dtm);
				case -19:
					return dtm.getPointer(StringDataType.dataType);
				case -20:
					return CharDataType.dataType.clone(dtm);
				case -22:
					return WordDataType.dataType;
				case -23:
				case -24:
					return DWordDataType.dataType;
				case -25:
					return Complex8DataType.dataType.clone(dtm);
				case -26:
					return Complex16DataType.dataType.clone(dtm);
				case -30:
					return WideCharDataType.dataType.clone(dtm);
				case -31:
					return LongLongDataType.dataType.clone(dtm);
				case -32:
					return UnsignedLongLongDataType.dataType.clone(dtm);
				case -33:
					return QWordDataType.dataType;
				case -34:
					return SignedQWordDataType.dataType;
				default:
					break;
			}
		}
		throw getError();
	}

	private DataType getIntegerDataType() throws StabsParseException {
		Matcher matcher = INTEGER_PATTERN.matcher(stab);
		if (matcher.matches()) {
			if (matcher.group(2) != null) {
				return CharDataType.dataType.clone(dtm);
			}
			int size = Integer.valueOf(matcher.group(4));
			if (size == 0) {
				return DataType.VOID;
			}
			if (matcher.group(1).charAt(0) == 's') {
				return AbstractIntegerDataType.getSignedDataType(size, dtm);
			}
			return AbstractIntegerDataType.getUnsignedDataType(size, dtm);
		}
		throw getError();
	}

	private DataType getAixFloatDataType() {
		int index = stab.indexOf(';');
		String def = stab.substring(index+1);
		return AbstractFloatDataType.getFloatDataType(Integer.valueOf(def), dtm);
	}

	private DataType getAixComplexDataType() throws StabsParseException {
		int index = stab.indexOf(';');
		String def = stab.substring(index+1);
		switch (Integer.valueOf(def)) {
			case 8:
				return Complex8DataType.dataType.clone(dtm);
			case 16:
				return Complex16DataType.dataType.clone(dtm);
			case 32:
				return Complex32DataType.dataType.clone(dtm);
			default:
				throw getError();
		}
	}

	private DataType getFloatDataType() throws StabsParseException {
		switch (stab.charAt(1)) {
			case '1':
				return FloatDataType.dataType.clone(dtm);
			case '2':
				return DoubleDataType.dataType.clone(dtm);
			case '3':
				return Complex8DataType.dataType.clone(dtm);
			case '4':
				return Complex16DataType.dataType.clone(dtm);
			case '5':
				return Complex32DataType.dataType.clone(dtm);
			case '6':
				return LongDoubleDataType.dataType.clone(dtm);
			default:
				throw getError();
		}
	}

	private BuiltinType doGetBuiltinType(char c) throws StabsParseException {
		switch (c) {
			case 'b':
				return BuiltinType.INTEGRAL;
			case 'c':
				return BuiltinType.COMPLEX;
			case 'g':
				return BuiltinType.AIX_FLOAT;
			case 'R':
				return BuiltinType.FLOAT;
			case 'w':
				return BuiltinType.WIDE_CHAR;
			case '-':
				return BuiltinType.NEGATIVE;
			default:
				throw getError();
		}
	}

	@Override
	public DataType getDataType() {
		return dt;
	}

	@Override
	public StabsTypeDescriptorType getType() {
		return StabsTypeDescriptorType.BUILTIN;
	}

	@Override
	public int getLength() {
		return length;
	}

	/**
	 * Gets the BuiltinType this descriptor represents
	 * @return the BuiltinType
	 */
	public BuiltinType getBuiltinType() {
		return type;
	}

	/** Potential types represented by a StabBuiltinTypeDescriptor */
	public static enum BuiltinType {
		FLOAT("R\\d;\\d+;"),
		AIX_FLOAT(String.format("g%s;\\d+", StabsTypeNumber.TYPE_NUMBER_PATTERN)),
		INTEGRAL(INTEGER_PATTERN),
		COMPLEX(String.format("c%s\\d+", StabsTypeNumber.TYPE_NUMBER_PATTERN)),
		NEGATIVE(NEGATIVE_PATTERN),
		WIDE_CHAR("w");

		private final Pattern pattern;
		private BuiltinType(String pattern) {
			this.pattern = Pattern.compile(pattern);
		}

		private BuiltinType(Pattern pattern) {
			this.pattern = pattern;
		}

		private int getLength(StabsSymbolDescriptor symbol, String stab) throws StabsParseException {
			Matcher matcher = pattern.matcher(stab);
			if (matcher.lookingAt()) {
				return matcher.group().length();
			}
			throw new StabsParseException(symbol.getName(), stab);
		}
	}
}
