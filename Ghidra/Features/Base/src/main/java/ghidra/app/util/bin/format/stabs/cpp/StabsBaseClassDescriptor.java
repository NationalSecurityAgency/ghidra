package ghidra.app.util.bin.format.stabs.cpp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.bin.format.stabs.StabsClassSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsToken;
import ghidra.app.util.bin.format.stabs.StabsTokenizer;
import ghidra.app.util.bin.format.stabs.StabsTypeNumber;
import ghidra.app.util.bin.format.stabs.StabsClassSymbolDescriptor.Visibility;
import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.program.model.data.DataType;

import static ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptorFactory.getTypeDescriptor;

/**
 * Helper Class for C++ Inherited Base Classes
 */
public final class StabsBaseClassDescriptor {

	private static final Pattern BASE_PATTERN = Pattern.compile("(?<!(operator))!(\\d+),");

	private static enum Groups {
		VIRTUAL,
		MODIFIER,
		OFFSET,
		TYPE
	}
	
	private static final String PATTERN =
		String.format("(?<%%s>[01])(?<%%s>[0129])(?<%%s>\\-?\\d+),(?<%%s>(%s)(=xs\\w+:)?);",
			StabsTypeNumber.TYPE_NUMBER_PATTERN);

	private static final StabsTokenizer<Groups> TOKENIZER =
		new StabsTokenizer<>(PATTERN, Groups.class);

	private final StabsToken<Groups> token;
	private final StabsTypeDescriptor type;

	/**
	 * Gets a list of all found base classes in the provided stab
	 * @param symbol the class descriptor
	 * @param stab the stab
	 * @return a list of all found base classes
	 * @throws StabsParseException if an error occurs while parsing the stab
	 */
	public static List<StabsBaseClassDescriptor> getBases(StabsClassSymbolDescriptor symbol,
		String stab) throws StabsParseException {
			int index = getBaseStartIndex(stab);
			if (index != -1) {
				List<StabsToken<Groups>> tokens =
					TOKENIZER.getTokens(stab.substring(index));
				List<StabsBaseClassDescriptor> bases = new ArrayList<>(tokens.size());
				for (StabsToken<Groups> token : tokens) {
					bases.add(new StabsBaseClassDescriptor(symbol, token));
				}
				return Collections.unmodifiableList(bases);	
			}
			return Collections.emptyList();
	}

	/**
	 * Gets the starting index of the first base class in the stab string
	 * @param stab the stab string
	 * @return the index in the stab string or -1 if none are found
	 */
	public static int getBaseStartIndex(String stab) {
		Matcher matcher = BASE_PATTERN.matcher(stab);
		if (matcher.find()) {
			return matcher.end();
		}
		return -1;
	}

	private StabsBaseClassDescriptor(StabsSymbolDescriptor symbol, StabsToken<Groups> token)
		throws StabsParseException {
			this.token = token;
			String subStab = token.toString().substring(token.start(Groups.TYPE));
			this.type = getTypeDescriptor(symbol, subStab);
	}

	/**
	 * @return the isVirtual
	 */
	public boolean isVirtual() {
		return token.get(Groups.VIRTUAL).charAt(0) == '1';
	}

	/**
	 * @return the modifier
	 */
	public Visibility getModifier() {
		return Visibility.getVisibility(token.get(Groups.MODIFIER));
	}

	/**
	 * @return the offset
	 */
	public int getOffset() {
		// divide by 8 to convert bits to bytes
		return (int) Long.parseLong(token.get(Groups.OFFSET)) >> 3;
	}

	/**
	 * Gets the DataType of this base class
	 * @return the base classes data type
	 */
	public DataType getDataType() {
		return type.getDataType();
	}

	/**
	 * Gets the length of this descriptor
	 * @return the length of this descriptor
	 */
	public int getLength() {
		return token.getLength();
	}
}