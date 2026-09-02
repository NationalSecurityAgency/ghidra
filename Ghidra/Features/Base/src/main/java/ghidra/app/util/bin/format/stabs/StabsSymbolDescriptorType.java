package ghidra.app.util.bin.format.stabs;

/**
 * Enum constants for possible Stab Symbol Descriptor Types
 */
public enum StabsSymbolDescriptorType {
	/** Variable Symbol */
	VARIABLE,
	/** Function Parameter Symbol */
	PARAMETER,
	/** Constant Symbol */
	CONSTANT,
	/** Exception Symbol */
	EXCEPTION,
	/** Function Symbol */
	FUNCTION,
	/** Composite: Structure, Union, Enum Symbols */
	COMPOSITE,
	/** C++ Class Symbol*/
	CLASS,
	/** Typedef Symbol */
	TYPEDEF,
	/** Invalid or Unknown Symbol */
	NONE;

	private static enum Groups {
		NAME,
		CODE
	}
	
	private static final String PATTERN = String.format(
		"(?<%%s>%s)(?<%%s>[\\d\\-\\(abcCdDfFGiIJLmpPQRrSstTvVX])", StabsParser.NAME_PATTERN);

	private static final StabsTokenizer<Groups> TOKENIZER =
		new StabsTokenizer<>(PATTERN, Groups.class);

	/**
	 * Gets the appropriate StabSymbolDescriptorType based on the provided stab
	 * @param stab the stab string
	 * @return the appropriate StabSymbolDescriptorType
	 */
	public static StabsSymbolDescriptorType getSymbolType(String stab) {
		StabsToken<Groups> token = TOKENIZER.getToken(stab);
		StabsSymbolDescriptorType result = getSymbolType(token.getChar(Groups.CODE));
		if (result == COMPOSITE) {
			if (StabsClassSymbolDescriptor.isClass(stab.toString())) {
				return CLASS;
			}
			if (stab.charAt(token.getLength()) == 't') {
				char c = stab.charAt(token.getLength()+1);
				if (c >= '0' && c <= '9') {
					// gcc2 does this
					return TYPEDEF;
				}
			}
		}
		return result;
	}

	/**
	 * Gets the appropriate StabSymbolDescriptorType for the provided character
	 * @param c the symbol descriptor character
	 * @return the appropriate StabSymbolDescriptorType
	 */
	public static StabsSymbolDescriptorType getSymbolType(char c) {
		switch(c) {
			case 'c': // constant
				return CONSTANT;
			case 'C': // caught exception
				return EXCEPTION;
			// PARAMETERS
			case 'p': // stack
			case 'P': // register (GNU)
			case 'R': // register (IBM)
			case 'v': // passed by reference in arg list
			case 'a': // passed by reference in register
				return PARAMETER;
			// FUNCTIONS
			case 'f': // file
			case 'F': // global
			case 'I': // nested
			case 'J': // nested
			case 'm': // module
			case 'Q': // static
				return FUNCTION;
			// VARIABLES
			case '(': // stack (this is really no char '')
			case '-': // stack
			case '0': // 0 - 9 are stack
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
			case 'b': // based (fortran array allocated via malloc)
			case 'd': // float register
			case 'r': // register
			case 'G': // global
			case 's': // local
			case 'S': // global static
			case 'V': // local static
				return VARIABLE;
			case 't':
				return TYPEDEF;
			case 'T':
				return COMPOSITE;
			default:
				// otherwise the info should be handled by an analyzer
				return NONE;
		}
	}
}
