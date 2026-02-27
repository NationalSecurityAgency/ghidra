package ghidra.app.util.bin.format.stabs.types;

import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsToken;
import ghidra.app.util.bin.format.stabs.StabsTokenizer;
import ghidra.app.util.bin.format.stabs.StabsTypeDescriptorType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;

import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;

/**
 * Cross Reference (Forward Declaration) implementation of the StabTypeDescriptor
 */
public final class StabsCrossReferenceTypeDescriptor extends AbstractStabsTypeDescriptor {

	private static enum Groups {
		TYPE,
		NAME
	}

	private static final String PATTERN = "[ix](?<%s>[esu])(?<%s>.*?)(:|$)";
	private static final StabsTokenizer<Groups> TOKENIZER =
		new StabsTokenizer<>(PATTERN, Groups.class);

	private final StabsToken<Groups> token;
	private final DataType dt;

	/**
	 * Constructs a new StabsCrossReferenceTypeDescriptor
	 * @param symbol the token this descriptor is located in
	 * @param stab the portion of the stab containing this descriptor
	 * @throws StabsParseException if this descriptor is invalid
	 */
	StabsCrossReferenceTypeDescriptor(StabsSymbolDescriptor symbol, String stab) throws StabsParseException {
		super(symbol, stab);
		this.token = TOKENIZER.getToken(stab);
		this.dt = doGetDataType();
	}

	private DataType doGetDataType() throws StabsParseException {
		 DataType dt;
		switch (stab.charAt(1)) {
			case 'e':
				// the size will doesn't matter as it will get replaced later
				dt = new EnumDataType(path, token.get(Groups.NAME), 1, dtm);
				break;
			case 's':
				dt = new StructureDataType(path, token.get(Groups.NAME), 0, dtm);
				break;
			case 'u':
				dt = new UnionDataType(path, token.get(Groups.NAME), dtm);
				break;
			default:
				throw getError();
		}
		return dtm.resolve(dt, KEEP_HANDLER);
	}

	@Override
	public DataType getDataType() {
		return dt;
	}

	@Override
	public StabsTypeDescriptorType getType() {
		return StabsTypeDescriptorType.CROSS_REFERENCE;
	}

	@Override
	public int getLength() {
		return token.getLength();
	}
}