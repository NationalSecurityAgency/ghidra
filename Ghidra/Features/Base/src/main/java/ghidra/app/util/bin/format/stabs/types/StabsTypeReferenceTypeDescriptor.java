package ghidra.app.util.bin.format.stabs.types;

import java.util.function.Predicate;
import java.util.regex.Pattern;

import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsTypeDescriptorType;
import ghidra.app.util.bin.format.stabs.StabsTypeNumber;
import ghidra.program.model.data.DataType;

/**
 * Type Descriptor which is a reference to a previously parsed type descriptor
 */
public final class StabsTypeReferenceTypeDescriptor extends AbstractStabsTypeReferenceTypeDescriptor {

	private static final Predicate<String> IS_VOID = Pattern.compile(
		String.format("(%s)=\\1", StabsTypeNumber.TYPE_NUMBER_PATTERN)).asMatchPredicate();

	private final StabsTypeDescriptor subType;

	/**
	 * Constructs a new StabsTypeReferenceTypeDescriptor
	 * @param symbol the token this descriptor is located in
	 * @param stab the portion of the stab containing this descriptor
	 * @throws StabsParseException if this descriptor or what it references is invalid
	 */
	StabsTypeReferenceTypeDescriptor(StabsSymbolDescriptor symbol, String stab) throws StabsParseException {
		super(symbol, stab);
		this.subType = doGetSubType();
	}

	@Override
	public DataType getDataType() {
		return IS_VOID.test(stab) ? DataType.VOID : subType.getDataType();
	}

	@Override
	public StabsTypeDescriptorType getType() {
		return StabsTypeDescriptorType.TYPE_REFERENCE;
	}

	@Override
	public StabsTypeDescriptor getSubType() {
		return subType;
	}
}
