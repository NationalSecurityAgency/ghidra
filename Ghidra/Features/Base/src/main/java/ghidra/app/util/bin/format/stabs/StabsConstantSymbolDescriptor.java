package ghidra.app.util.bin.format.stabs;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

/**
 * Constant implementation of the StabSymbolDescriptor
 */
public class StabsConstantSymbolDescriptor extends AbstractStabsSymbolDescriptor {

	/** Potential constant types */
	public enum ConstantType {
		VALUE,
		TYPE,
		STRING,
		NONE
	}

	/** Potential constant value types */
	public enum ValueType {
		/** true or false */
		BOOL,
		/** character value */
		CHARACTER,
		/** byte, short, int, long, etc. */
		INTEGER,
		/** float, double */
		REAL,
		/** not a value type constant */
		NONE
	}

	private static final Pattern PATTERN = Pattern.compile("c=([bcirseS])(.*)");

	private final ConstantType type;
	private final ValueType vType;

	/**
	 * Constructs a new StabsConstantSymbolDescriptor
	 * @param stab the portion of the stab containing this descriptor
	 * @param file the file containing this descriptor
	 * @throws StabsParseException if the descriptor or one it relies on is invalid
	 */
	StabsConstantSymbolDescriptor(String stab, StabsFile file) {
		super(stab, file);
		this.type = doGetConstantType();
		this.vType = doGetValueType();
	}

	@Override
	public DataType getDataType() {
		switch (type) {
			case STRING:
				return StringDataType.dataType;
			case VALUE:
				switch (vType) {
					case BOOL:
						return BooleanDataType.dataType;
					case CHARACTER:
						return CharDataType.dataType;
					case INTEGER:
						// implicit int. for others e is used
						return IntegerDataType.dataType;
					case REAL:
						return FloatDataType.dataType;
					case NONE:
					default:
						break;
				}
				break;
			case TYPE:
				return getTypeDataType();
			default:
				break;
		}
		return DataType.VOID;
	}

	@Override
	public StabsSymbolDescriptorType getSymbolDescriptorType() {
		return StabsSymbolDescriptorType.CONSTANT;
	}

	private char getTypeCharacter() {
		Matcher matcher = PATTERN.matcher(stab);
		if (matcher.find()) {
			return matcher.group(1).charAt(0);
		}
		return '\0';
	}

	private ConstantType doGetConstantType() {
		switch (getTypeCharacter()) {
			case 'b':
			case 'c':
			case 'i':
			case 'r':
				return ConstantType.VALUE;
			case 's':
				return ConstantType.STRING;
			case 'e':
			case 'S':
				return ConstantType.TYPE;
			default:
				break;
		}
		Msg.warn(this, "Unknown constant type in stab string:\n" + getStab());
		return ConstantType.NONE;
	}

	private DataType getTypeDataType() {
		StabsTypeNumber num = new StabsTypeNumber(stab);
		StabsTypeDescriptor type = file.getType(num);
		return type != null ? type.getDataType() : DataType.VOID;
	}

	/**
	 * Gets the type of constant this descriptor represents
	 * @return the constant type
	 */
	public ConstantType getConstantType() {
		return type;
	}

	/**
	 * Gets the value type this constant value type descriptor represents
	 * @return the value type
	 */
	public ValueType getValueType() {
		return vType;
	}

	private ValueType doGetValueType() {
		if (type.equals(ConstantType.VALUE)) {
			switch (getTypeCharacter()) {
				case 'b':
					return ValueType.BOOL;
				case 'c':
					return ValueType.CHARACTER;
				case 'i':
					return ValueType.INTEGER;
				case 'r':
					return ValueType.REAL;
				default:
					break;
			}
		}
		return ValueType.NONE;
	}
}
