package ghidra.app.util.bin.format.stabs.types;

import ghidra.app.util.bin.format.stabs.StabsToken;
import ghidra.app.util.bin.format.stabs.StabsTokenizer;
import ghidra.app.util.bin.format.stabs.StabsTypeDescriptorType;
import ghidra.app.util.bin.format.stabs.StabsTypeNumber;
import ghidra.program.model.data.DataType;

import static ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptorFactory.getTypeDescriptor;

import ghidra.app.util.bin.format.stabs.StabsParseException;

final class StabsParameterTypeDescriptor extends AbstractStabsTypeDescriptor {

	private static enum Groups {
		NAME,
		TYPE
	}

	private static final String PATTERN =
		String.format("(?<%%s>(.*?)(?=(?:(?<!:):(?!:))):)?(?<%%s>%s)",
			StabsTypeNumber.TYPE_NUMBER_PATTERN);

	private static final StabsTokenizer<Groups> TOKENIZER =
		new StabsTokenizer<>(PATTERN, Groups.class);

	private final StabsToken<Groups> token;
	private final StabsTypeDescriptor type;

	/**
	 * Constructs a new StabsParameterTypeDescriptor
	 * @param function the function containing this parameter
	 * @param stab the portion of the stab containing this descriptor
	 * @throws StabsParseException if this descriptor is invalid
	 */
	StabsParameterTypeDescriptor(StabsFunctionTypeDescriptor function, String stab)
		throws StabsParseException {
			super(function.getSymbolDescriptor(), stab);
			this.token = TOKENIZER.getToken(stab);
			int index = stab.indexOf(token.get(Groups.TYPE));
			this.type = getTypeDescriptor(symbol, stab.substring(index));
	}

	@Override
	public DataType getDataType() {
		return type.getDataType();
	}

	@Override
	public StabsTypeDescriptorType getType() {
		return null;
	}

	@Override
	public int getLength() {
		String name = getName();
		return name != null ? name.length()+type.getLength() : type.getLength();
	}

	/**
	 * Gets the name of this parameter
	 * @return the parameter's name
	 */
	String getName() {
		return token.get(Groups.NAME);
	}
}
