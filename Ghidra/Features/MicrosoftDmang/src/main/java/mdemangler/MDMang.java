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

import org.apache.commons.lang3.StringUtils;

import mdemangler.MDContext.MDContextType;
import mdemangler.datatype.MDDataType;
import mdemangler.datatype.MDDataTypeParser;
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

	private MDOutputOptions outputOptions = new MDOutputOptions();

	protected int architectureSize = 32;
	protected boolean isFunction = false;

	protected String mangled;
	protected MDCharacterIterator iter;
	protected String errorMessage;
	protected MDParsableItem item;

	protected List<MDContext> contextStack;

	protected boolean errorOnRemainingChars = false;

	public enum ProcessingMode {
		DEFAULT_STANDARD, LLVM
	}

	private ProcessingMode processingMode;

	//==============================================================================================
	// Mangled Context

	/**
	 * Sets the mangled string to be demangled
	 * @param mangledIn the string to be demangled
	 */
	public void setMangledSymbol(String mangledIn) {
		this.mangled = mangledIn;
	}

	/**
	 * Gets the mangled string being demangled
	 * @return the string being demangled
	 */
	public String getMangledSymbol() {
		return mangled;
	}

	/**
	 * Sets the architecture size.  Default is 64 bits
	 * @param size the architecture size
	 */
	public void setArchitectureSize(int size) {
		architectureSize = size;
	}

	/**
	 * Returns the architecture size (bits)
	 * @return the architecture size
	 */
	public int getArchitectureSize() {
		return architectureSize;
	}

	/**
	 * Sets whether the symbol is known to be for a function
	 * @param isFunction {@code true} if known to be a symbol for a function
	 */
	public void setIsFunction(boolean isFunction) {
		this.isFunction = isFunction;
	}

	/**
	 * Returns whether the symbol is known to be for a function
	 * @return {@code true} if known to be a symbol for a function
	 */
	public boolean isFunction() {
		return isFunction;
	}

	//==============================================================================================
	// Output Options
	public MDOutputOptions getOutputOptions() {
		return outputOptions;
	}

	//==============================================================================================
	// Demangling options

	/**
	 * Controls whether an exception is thrown if there are remaining characters after demangling.
	 * Default is {@code false}
	 * @param errorOnRemainingCharsArg {@code true} to error if characters remaining
	 */
	public void setErrorOnRemainingChars(boolean errorOnRemainingCharsArg) {
		errorOnRemainingChars = errorOnRemainingCharsArg;
	}

	/**
	 * Returns {@code true} if the process will throw an exception if characters remain after
	 * demangling
	 * @return {@code true} if errors will occur on remaining characters
	 */
	public boolean errorOnRemainingChars() {
		return errorOnRemainingChars;
	}

	/**
	 * Returns the error message when demangle() returns null.
	 * @return the error message for the demangle() call.
	 */
	public String getErrorMessage() {
		return errorMessage;
	}

	/**
	 * Returns the number of unprocessed mangled characters. Note that
	 * demangle() has a flag controlling whether remaining characters causes an
	 * error
	 * @return the integer number of characters that remain
	 */
	public int getNumCharsRemaining() {
		return iter.getLength() - iter.getIndex();
	}

	//==============================================================================================
	// Processing

	/**
	 * Demangles the string already stored and returns a parsed item
	 * @return item detected and parsed
	 * @throws MDException upon error parsing item
	 */
	public MDParsableItem demangle() throws MDException {
		initState();
		item = MDMangObjectParser.determineItemAndParse(this);
		if (item instanceof MDObjectCPP) {
			// MDMANG SPECIALIZATION USED.
			item = getEmbeddedObject((MDObjectCPP) item);
		}
		int numCharsRemaining = getNumCharsRemaining();
		if (errorOnRemainingChars && (numCharsRemaining > 0)) {
			throw new MDException(
				"MDMang: characters remain after demangling: " + numCharsRemaining + ".");
		}
		return item;
	}

	/**
	 * Demangles the mangled "type" name already stored and returns a parsed MDDataType
	 * @return the parsed MDDataType
	 * @throws MDException upon parsing error
	 */
	public MDDataType demangleType() throws MDException {
		initState();
		MDDataType mdDataType = MDDataTypeParser.determineAndParseDataType(this, false);
		item = mdDataType;
		int numCharsRemaining = getNumCharsRemaining();
		if (errorOnRemainingChars && (numCharsRemaining > 0)) {
			throw new MDException(
				"MDMang: characters remain after demangling: " + numCharsRemaining + ".");
		}
		return mdDataType;
	}

	//==============================================================================================
	// Internal processing control

	public void setProcessingMode(ProcessingMode processingMode) {
		this.processingMode = processingMode;
	}

	public ProcessingMode getProcessingMode() {
		return processingMode;
	}

	public boolean isLlvmProcessingModeIndex0() {
		return processingMode == ProcessingMode.LLVM && (getIndex() == 0);
	}

	public boolean isLlvmProcessingMode() {
		return processingMode == ProcessingMode.LLVM;
	}

	/**
	 * Variables that get set at the very beginning.
	 * @throws MDException if mangled name is not set
	 */
	protected void initState() throws MDException {
		if (StringUtils.isBlank(mangled)) {
			throw new MDException("MDMang: Mangled string is null or blank.");
		}
		errorMessage = "";
		processingMode = ProcessingMode.DEFAULT_STANDARD;
		iter = new MDCharacterIterator(mangled);
		resetState();
	}

	/**
	 * Variables that can get reset for a second (or more?) passes with different modes.
	 */
	public void resetState() {
		contextStack = new ArrayList<>();
		setIndex(0);
	}

	//==============================================================================================

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
	 * @return the current index.
	 */
	public int getIndex() {
		return iter.getIndex();
	}

	/**
	 * Sets the current index.  Can set index to just beyond the text to represent the iterator
	 * being at the end of the text
	 * @param index the position to set
	 * @throws IllegalArgumentException if index is not in range from 0 to string.length()
	 */
	public void setIndex(int index) {
		iter.setIndex(index);
	}

	/**
	 * Returns true if there are no more characters to iterate
	 * @return {@code true} if done
	 */
	public boolean done() {
		return peek() == DONE;
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
