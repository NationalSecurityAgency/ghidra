/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package mdemangler;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

import mdemangler.MDContext.MDContextType;
import mdemangler.datatype.MDDataType;
import mdemangler.datatype.modifier.MDArrayBasicType;
import mdemangler.datatype.modifier.MDCVMod;
import mdemangler.naming.MDFragmentName;
import mdemangler.naming.MDQualification;
import mdemangler.object.MDMangObjectParser;
import mdemangler.object.MDObjectCPP;
import mdemangler.template.MDTemplateArgumentsList;

/**
 * A class for demangling symbols created by Microsoft Visual Studio. The
 * demangled symbols are output according to the MD interpretation. Other
 * derived classes can output according to some other interpretation, such as
 * MSFT VS2015 or MSFT VS2013.
 */
public class MDMang {
	public static final char DONE = MDCharacterIterator.DONE;

	protected String mangled;
	protected MDCharacterIterator iter;
	protected String errorMessage = "";
	protected MDParsableItem item;

	protected List<MDContext> contextStack = new ArrayList<>();

	/**
	 * Demangles the string passed in.
	 *
	 * @param mangledIn
	 *            the string to be demangled.
	 * @param errorOnRemainingChars
	 *            boolean flag indicating whether remaining characters causes an
	 *            error.
	 */
	public MDParsableItem demangle(String mangledIn, boolean errorOnRemainingChars)
			throws MDException {
		if (mangledIn == null || mangledIn.isEmpty()) {
			throw new MDException("Invalid mangled symbol.");
		}
		setMangledSymbol(mangledIn);
		return demangle(errorOnRemainingChars);
	}

	/**
	 * Demangles the string passed in.
	 *
	 * @param errorOnRemainingChars
	 *            boolean flag indicating whether remaining characters causes an
	 *            error.
	 */
	public MDParsableItem demangle(boolean errorOnRemainingChars) throws MDException {
		if (mangled == null) {
			throw new MDException("MDMang: Mangled string is null.");
		}
		pushContext();
		item = MDMangObjectParser.parse(this);
		item.parse();
		if (item instanceof MDObjectCPP) {
			// MDMANG SPECIALIZATION USED.
			item = getEmbeddedObject((MDObjectCPP) item);
		}
		int numCharsRemaining = getNumCharsRemaining();
		popContext();
		if (errorOnRemainingChars && (numCharsRemaining > 0)) {
			throw new MDException(
				"MDMang: characters remain after demangling: " + numCharsRemaining + ".");
		}
		return item;
	}

	/**
	 * Sets the mangled string to be demangled.
	 *
	 * @param mangledIn
	 *            the string to be demangled.
	 */
	public void setMangledSymbol(String mangledIn) {
		this.mangled = mangledIn;
		iter = new MDCharacterIterator(mangled);
	}

	/**
	 * Gets the mangled string being demangled.
	 *
	 * @return the string being demangled.
	 */
	public String getMangledSymbol() {
		return mangled;
	}

	/**
	 * Returns the error message when demangle() returns null.
	 *
	 * @return the error message for the demangle() call.
	 */
	public String getErrorMessage() {
		return errorMessage;
	}

	/**
	 * Returns the number of unprocessed mangled characters. Note that
	 * demangle() has a flag controlling whether remaining characters causes an
	 * error.
	 *
	 * @return the integer number of characters that remain.
	 */
	public int getNumCharsRemaining() {
		return iter.getLength() - iter.getIndex();
	}

	/******************************************************************************/
	/******************************************************************************/

	// /**
	// * Routine used while debugging a symbol. Create a new 'if'
	// * condition for the character index you want to stop
	// * at, and then set a breakpoint on the 'a = index + 1' line.
	// * Note: the break point can get hit multiple times for any
	// * given index, as the index can move backwards or might not
	// * move at all between sequential calls.
	// * @return the modified 'a' value, but purely a junk value
	// * that is not to be used by the calling routine.
	// */
	protected int debugCheck(int lookAhead) {
		int a = iter.getIndex() + lookAhead;
		int b = a;
		if (a == 32) {
			b++;
		}
		if (a == 179) {
			b++;
		}
		if (a == 150) {
			b++;
		}
		// if (index == 152) {
		// b++;
		// }
		return b;
	}

	/**
	 * Returns the current index.
	 *
	 * @return the current index.
	 */
	public int getIndex() {
		return iter.getIndex();
	}

	/**
	 * Returns the next character without incrementing the current index.
	 *
	 * @return the next character without incrementing the current index
	 */
	public char peek() {
		debugCheck(0);
		return iter.peek();
	}

	/**
	 * Peeks at the character current index + lookAhead. Returns DONE if the
	 * computed position is out of range.
	 *
	 * @param lookAhead
	 *            number of characters to look ahead
	 * @return the character at index+lookAhead
	 */
	public char peek(int lookAhead) {
		debugCheck(lookAhead);
		return iter.peek(lookAhead);
	}

	/**
	 * Increments the current index by one and returns the character at the new
	 * index. If the resulting index is greater or equal to the end index, the
	 * current index is reset to the end index and a value of DONE is returned.
	 * For extended reasons, the user should try not to use this method--and use
	 * of it should be selective, based on extended class reasons.
	 *
	 * @return the character at the new position or DONE
	 */
	public char next() {
		debugCheck(1);
		return iter.next();
	}

	/**
	 * Returns the character at the current index and then increments the index
	 * by one. If the resulting index is greater or equal to the end index, the
	 * current index is reset to the end index and a value of DONE is returned.
	 *
	 * @return the character at the new position or DONE
	 */
	public char getAndIncrement() {
		debugCheck(0);
		return iter.getAndIncrement();
	}

	/**
	 * Increments the index by one. Does no testing for whether the index
	 * surpasses the length of the string.
	 */
	public void increment() {
		debugCheck(0);
		iter.increment();
	}

	/**
	 * Moves to the next character in the iterator.
	 * Does no testing for whether it surpasses the length of the string.
	 *
	 * @param count
	 *            number of characters to move ahead
	 */
	public void increment(int count) {
		iter.increment(count);
	}

	/**
	 * Returns true if substring is found at the current index.
	 *
	 * @return true if substring is found at the current index
	 */
	public boolean positionStartsWith(String substring) {
		return iter.positionStartsWith(substring);
	}

	// NOTE: We do not want to expose the iter.previous() method, as we would
	// then have
	// to deal with big fallout for MDMangParseInfo tracking of characters. It
	// used to
	// be exposed, but we were able to eliminate all uses.

	/******************************************************************************/
	/******************************************************************************/
	public MDContext getContext() {
		return contextStack.get(contextStack.size() - 1);
	}

	public void pushContext() {
		MDContext context = new MDContext();
		contextStack.add(context);
		return;
	}

	public void pushModifierContext() {
		contextStack.add(new MDContext(getContext(), MDContextType.MODIFIER));
	}

	public void pushFunctionContext() {
		contextStack.add(new MDContext(getContext(), MDContextType.FUNCTION));
	}

	public void pushTemplateContext() {
		contextStack.add(new MDContext(getContext(), MDContextType.TEMPLATE));
	}

	public void popContext() {
		contextStack.remove(contextStack.size() - 1);
	}

	public void addBackrefName(String name) {
		MDContext context = getContext();
		context.addBackrefName(name);
	}

	public String getBackreferenceName(int index) throws MDException {
		MDContext context = getContext();
		return context.getBackrefName(index);
	}

	public void addBackrefFunctionParameterMDDataType(MDDataType dt) {
		MDContext context = getContext();
		context.addBackrefFunctionParameterMDDataType(dt);
	}

	public void addBackrefTemplateParameterMDDataType(MDDataType dt) {
		MDContext context = getContext();
		context.addBackrefTemplateParameterMDDataType(dt);
	}

	public MDDataType getBackreferenceFunctionParameterMDDataType(int index) throws MDException {
		MDContext context = getContext();
		return context.getBackrefFunctionParameterMDDataType(index);
	}

	public MDDataType getBackreferenceTemplateParameterMDDataType(int index) throws MDException {
		MDContext context = getContext();
		return context.getBackrefTemplateParameterMDDataType(index);
	}

	/******************************************************************************/
	/******************************************************************************/
	// Might be temporary until we find out what to call within the MDParsableItem
	// classes.  We want it in MDMangParseInfo extension to MDMang.
	public void parseInfoPushPop(int startIndexOffset, String objectName) {
		// Purposefully empty for base class.  Conents exist for a derived class.
	}

	// Might be temporary until we find out what to call within the MDParsableItem
	// classes.  We want it in MDMangParseInfo extension to MDMang.
	public void parseInfoPush(int startIndexOffset, String objectName) {
		// Purposefully empty for base class.  Conents exist for a derived class.
	}

	// Might be temporary until we find out what to call within the MDParsableItem
	// classes.  We want it in MDMangParseInfo extension to MDMang.
	public void parseInfoPop() {
		// Purposefully empty for base class.  Conents exist for a derived class.
	}

	/******************************************************************************/
	/******************************************************************************/
	private static final char SPACE = ' ';

	public void insertSpacedString(StringBuilder builder, String string) {
		if (builder.length() != 0 && string.length() != 0) {
			if (builder.charAt(0) == ' ') {
				if (string.charAt(string.length() - 1) == ' ') {
					builder.deleteCharAt(0);
				}
			}
			else if (string.charAt(string.length() - 1) != ' ') {
				builder.insert(0, SPACE);
			}
			// else there is a space at end of string.
		}
		builder.insert(0, string);
	}

	// This used to be more complicated; we recently simplified it, and it might
	// go away
	// altogether.
	public boolean isEffectivelyEmpty(StringBuilder builder) {
		if (builder.length() == 0) {
			return true;
		}
		return false;
	}

	public void insertString(StringBuilder builder, String string) {
		if (builder.length() != 0 && string.length() != 0) {
			if (builder.charAt(0) == ' ') {
				if (string.charAt(string.length() - 1) == ' ') {
					builder.deleteCharAt(0);
				}
			}
		}
		builder.insert(0, string);
	}

	public void appendString(StringBuilder builder, String string) {
		if (builder.length() != 0 && string.length() != 0) {
			if (builder.charAt(builder.length() - 1) == ' ') {
				if (string.charAt(0) == ' ') {
					builder.deleteCharAt(builder.length() - 1);
				}
			}
		}
		builder.append(string);
	}

	// This routine is to take care of '\0' characters that we purposefully
	// allow
	// to be inserted for Based5 (Based Pointer to Based Pointer) to match MSFT
	// processing.
	// TODO: Future would be for this (inserting of '\0' and subsequent
	// clean-up)
	// to only happen for MDMangVS2015. The other implementations should throw
	// some sort of "invalid" mangled symbol data.
	public void cleanOutput(StringBuilder builder) {
		if (builder != null) {
			for (int i = 0; i < builder.length(); i++) {
				if (builder.charAt(i) == '\0') {
					builder.setLength(i);
					break;
				}
			}
		}
	}

	/******************************************************************************/
	/******************************************************************************/
	// SPECIALIZATION METHODS
	private static final Charset UTF8 = Charset.forName("UTF-8");
	private static final Charset UTF16 = Charset.forName("UTF-16");

	// private static final Charset WIN1252 = Charset.forName("windows-1252");
	public void insert(StringBuilder builder, MDString mdstring) {
		insertString(builder, mdstring.getString(UTF8, UTF16));
	}

	public void insert(StringBuilder builder, MDQualification qualification) {
		qualification.insert_MdVersion(builder);
	}

	public boolean emptyFirstArgComma(MDTemplateArgumentsList args) {
		return false;
	}

	public boolean templateBackrefComma(MDTemplateArgumentsList args) {
		return true;
	}

	public void insertManagedPropertiesSuffix(StringBuilder builder, MDCVMod cvMod) {
		cvMod.insertManagedPropertiesSuffix(builder);
	}

	public void parseEmbeddedObjectSuffix() {
		if (peek() == '@') {
			increment();
		}
	}

	public void insertCLIArrayRefSuffix(StringBuilder builder, StringBuilder refBuilder) {
		insertSpacedString(builder, refBuilder.toString());
	}

	public String parseFragmentName(MDFragmentName fn) throws MDException {
		return fn.parseFragmentName_Md();
	}

	public void appendArrayNotation(StringBuilder builder, MDArrayBasicType arrayBasicType) {
		// default empty
	}

	public boolean allowMDTypeInfoParserDefault() {
		return false;
	}

	public boolean allowCVModLRefRRef() {
		return true;
	}

	// TODO: Work in progress. The plan was to have this return "true" and be
	// overridden
	// with "false" elsewhere, but for now, the return here is also "false," as
	// there
	// is a conflict between how to do processing for the following tests:
	// testWin10_0022127(), which wants ?C in MDQual to be an MDEncodedNumber
	// and
	// testWin10_6798753(), which wants ?C in MDQual to be an MDFragment with
	// stripped '@'
	public boolean processQualCAsSpecialFragment() {
		// return true;
		return false;
	}

	/**
	 * This method is meant to be overridden as needed to return (or not) the
	 *  embedded object (see MDBasicName).  In this default case, we do not
	 *  return the embedded object, but just return the object itself.  A
	 *  derived class can elect to return the embedded.
	 * @param obj the object from which to the embedded object is retrieved for return.
	 * @return An MDObjectCPP representing the original or the embedded object.
	 */
	public MDObjectCPP getEmbeddedObject(MDObjectCPP obj) {
		return obj;
	}

	/**
	 * This method is meant to be overridden as needed to process a hashed
	 *  object.  In this default case (MDMang), we properly process the
	 *  hashed object.  Overridden methods might just throw an exception,
	 *  allowing a failed demangling.
	 * @param obj the MDObjectCPP for which to process as a hashed object
	 * @throws MDException on parsing error.
	 */
	public void processHashedObject(MDObjectCPP obj) throws MDException {
		obj.processHashedObject();
	}

}

/******************************************************************************/
/******************************************************************************/
