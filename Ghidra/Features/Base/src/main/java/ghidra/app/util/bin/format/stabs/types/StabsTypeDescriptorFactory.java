package ghidra.app.util.bin.format.stabs.types;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.util.Msg;

public class StabsTypeDescriptorFactory {

	private static final Pattern PATTERN =
		Pattern.compile("([\\(\\d\\-#\\*&@aAbBcCdDeEfFgGikKMnNopPrRsSuvwxYz])");

	private StabsTypeDescriptorFactory() {
		// static factory
	}

	/**
	 * Gets the appropriate StabTypeDescriptor (Internal Use Only)
	 * @param token the token containing the descriptor
	 * @param stab the type descriptor sub-portion of the stab
	 * @return the type descriptor
	 * @throws StabsParseException if the stab cannot be parsed
	 */
	public static StabsTypeDescriptor getTypeDescriptor(StabsSymbolDescriptor token, String stab)
			throws StabsParseException {
		Matcher matcher = PATTERN.matcher(stab);
		if (matcher.lookingAt()) {
			switch(stab.charAt(0)) {
				case 'r': // builtin integer range
					return new StabsRangeTypeDescriptor(token, stab);
				case '(': // type reference
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					return new StabsTypeReferenceTypeDescriptor(token, stab);
				// Pointers
				case '@': // Pointer to Class Member (GNU)
					// peek at next char. If not a number it's an attribute
					char nextChar = stab.charAt(1);
					if (nextChar > '9' || nextChar < '0') {
						return null;
					}
				case '*': // Pointer
				case '&': // Reference
					return new StabsReferenceTypeDescriptor(token, stab);
				// Arrays
				case 'a': // array
				case 'A': // open
				case 'D': // dynamic
				case 'E': // sub array
				case 'P': // packed
					return new StabsArrayTypeDescriptor(token, stab);
				// Function
				case '#': // method
					return new StabsMethodTypeDescriptor(token, stab);
				case 'f': // function
				case 'F': // function parameter (Pascal)
				case 'p': // procedure
					return new StabsFunctionTypeDescriptor(token, stab);
				// Composite (Anonymous)
				case 'Y': // struct (IBM) warn on potential incorrect result.
					// Limited information on this one
					Msg.warn(StabsTypeDescriptorFactory.class,
							 "Limited information available on IBM struct stab.\n"
							+"Potential incorrect result");
				case 'e': // enum
				case 's': // struct
				case 'u': // union
					return new StabsCompositeTypeDescriptor(token, stab);
				// Cross-Reference
				/* Be careful here. These are token references
				   to tokens which haven't been parsed yet. */
				case 'i': // Imported (AIX)
				case 'x': // cross-reference
					return new StabsCrossReferenceTypeDescriptor(token, stab);
				// Strings
				case 'n': // string
				case 'N': // string*
				case 'z': // gstring ;)
					break;
				// Builtins
				case '-': // builtin (AIX)
				case 'c': // complex (AIX)
				case 'g': // float (AIX)
				case 'R': // float
				case 'w': // wide char (AIX)
					return new StabsBuiltinTypeDescriptor(token, stab);
				// COBOL
				/*
				case 'C': // picture
				case 'G': // group
				case 'K': // file
				*/
				// Misc
				case 'k': // const
				case 'B': // volatile
				case 'b': // space (Pascal)
					return new StabsTypeModifierTypeDescriptor(token, stab);
				/*
				case 'd': // file
				case 'M': // multiple instance
				case 'S': // set
				*/
				default:
					break;
			}
		}
		throw new StabsParseException(token.getName(), stab);
	}
}
