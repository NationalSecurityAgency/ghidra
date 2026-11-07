package ghidra.app.util.bin.format.stabs.cpp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsToken;
import ghidra.app.util.bin.format.stabs.StabsTokenizer;
import ghidra.app.util.bin.format.stabs.StabsTypeDescriptorType;
import ghidra.app.util.bin.format.stabs.StabsClassSymbolDescriptor.Visibility;
import ghidra.app.util.bin.format.stabs.types.StabsArrayTypeDescriptor;
import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.app.util.bin.format.stabs.types.StabsTypeReferenceTypeDescriptor;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;

import static ghidra.app.util.demangler.DemanglerUtil.demangle;
import static ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptorFactory.getTypeDescriptor;

/**
 * Helper Class for Composite and C++ Class Members
 */
public final class StabsMemberSymbolDescriptor {

	private static enum Groups {
		NAME,
		MODIFIER,
		STAB,
		MANGLED,
		BITPOS,
		BITSIZE
	}

	private static final String PATTERN =
		"(?<%s>[A-Za-z_]\\w*)\\s*(?=(?:(?<!:):(?!:))):(?:/(?<%s>[0129]))?(?<%s>[^,].*?)"
		+"((?::(?<%s>.*?)|(?:,(?<%s>\\d+),(?<%s>\\d+))));+";
	private static final StabsTokenizer<Groups> TOKENIZER =
		new StabsTokenizer<>(PATTERN, Groups.class);

	private final Program program;
	private final StabsToken<Groups> token;
	private final DemangledObject demangled;
	private final StabsTypeDescriptor type;

	/**
	 * Gets a list of all found composite members in the provided stab
	 * @param symbol the stab descriptor
	 * @param stab the stab
	 * @return a list of all found members
	 * @throws StabsParseException if an error occurs while parsing the stab
	 */
	public static List<StabsMemberSymbolDescriptor> getMembers(StabsSymbolDescriptor symbol,
		String stab) throws StabsParseException {
			List<StabsToken<Groups>> tokens = TOKENIZER.getTokens(stab);
			if (!tokens.isEmpty()) {
				List<StabsMemberSymbolDescriptor> members = new ArrayList<>(tokens.size());
				for (StabsToken<Groups> token : tokens) {
					members.add(new StabsMemberSymbolDescriptor(symbol, token));
				}
				members = new ArrayList<>(members);
				return Collections.unmodifiableList(members);	
			}
			return Collections.emptyList();
	}

	private StabsMemberSymbolDescriptor(StabsSymbolDescriptor symbol, StabsToken<Groups> token)
		throws StabsParseException {
			this.program = symbol.getFile().getProgram();
			this.token = token;
			this.demangled = doGetDemangledObject();
			this.type = getTypeDescriptor(symbol, token.get(Groups.STAB));
	}

	private DemangledObject doGetDemangledObject() {
		if (token.get(Groups.MANGLED) != null) {
			return demangle(program, token.get(Groups.MANGLED));
		}
		return null;
	}

	/**
	 * Gets the name of this class member
	 * @return the class members name
	 */
	public String getName() {
		return token.get(Groups.NAME);
	}

	/**
	 * Gets the DataType of this class member
	 * @return the class member's data type
	 */
	public DataType getDataType() {
		return type.getDataType().clone(program.getDataTypeManager());
	}

	/**
	 * Gets the access modifier for this class member
	 * @return the class member's access modifier
	 */
	public Visibility getModifier() {
		return Visibility.getVisibility(token.get(Groups.MODIFIER));
	}

	/**
	 * Gets the demangled object for the mangled portion of the stab
	 * @return the demangled object or null if there was no mangled string
	 */
	public DemangledObject getDemangledObject() {
		return demangled;
	}

	/**
	 * Gets the bit position of this composite member
	 * @return the bit position or -1 if not specified
	 */
	public int getBitPosition() {
		if (token.get(Groups.BITPOS) != null) {
			return Integer.parseInt(token.get(Groups.BITPOS));
		}
		return -1;
	}

	/**
	 * Gets the bit size of this composite member
	 * @return the bit size or -1 if not specified
	 */
	public int getBitSize() {
		if (token.get(Groups.BITSIZE) != null) {
			return Integer.parseInt(token.get(Groups.BITSIZE));
		}
		return -1;
	}

	/**
	 * Checks if this member is a flexible array component
	 * @return true if a flexible array component
	 * @see StabsArrayTypeDescriptor#isTrailingArray()
	 */
	public boolean isFlexibleArray() {
		StabsTypeDescriptor subType = type;
		if (subType.getType() == StabsTypeDescriptorType.TYPE_REFERENCE) {
			subType = ((StabsTypeReferenceTypeDescriptor) subType).getSubType();
			if (subType.getType() == StabsTypeDescriptorType.ARRAY) {
				return ((StabsArrayTypeDescriptor) subType).isTrailingArray();
			}
		}
		return false;
	}

	/**
	 * Gets the length of this descriptor
	 * @return the length of this descriptor
	 */
	public int getLength() {
		return token.getLength();
	}
}
