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
package ghidra.program.util;

import java.awt.Color;
import java.math.BigInteger;
import java.util.*;

import javax.swing.text.*;

import ghidra.program.database.properties.UnsupportedMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.TypeMismatchException;
import ghidra.util.*;
import ghidra.util.exception.NoValueException;

/**
 * ProgramDiffDetails is used to determine the detailed differences between
 * two programs at a particular address. The differences are determined for
 * the extent of the code units from each program at a particular address.
 */
public class ProgramDiffDetails {

	private static final int INDENT_SIZE = 4;
	private static final String STANDARD_NEW_LINE = "\n";

	public static Color RED = new Color(0xff, 0x00, 0x00);
	public static Color MAROON = new Color(0x99, 0x00, 0x00);
	public static Color GREEN = new Color(0x00, 0x99, 0x00);
	public static Color BLUE = new Color(0x00, 0x00, 0x99);
	public static Color PURPLE = new Color(0x99, 0x00, 0x99);
	public static Color DARK_CYAN = new Color(0x00, 0x99, 0x99);
	public static Color OLIVE = new Color(0x99, 0x99, 0x00);
	public static Color ORANGE = new Color(0xff, 0x99, 0x00);
	public static Color PINK = new Color(0xff, 0x99, 0x99);
	public static Color YELLOW = new Color(0xff, 0xff, 0x00);
	public static Color GRAY = new Color(0x88, 0x88, 0x88);
	private static final Color EMPHASIZE_COLOR = GREEN;
	private static final Color ADDRESS_COLOR = DARK_CYAN;
	private static final Color COMMENT_COLOR = GREEN;

	private static final BookmarkComparator BOOKMARK_COMPARATOR = new BookmarkComparator();

	private Program p1;
	private Program p2;
	private Address currentP1Address;
	private Address currentP2Address;
	private Listing l1;
	private Listing l2;
	private CodeUnit cu1;
	private CodeUnit cu2;
	private CodeUnit cu1At;
	private CodeUnit cu2At;
	private Address minP1Address;
	private Address maxP1Address;
	private AddressSet checkP1AddressSet;
	private boolean noDifferences;
	private boolean noMem;
	private String newLine = STANDARD_NEW_LINE;
	protected String indent1 = getIndentString(1);
	protected String indent2 = getIndentString(2);
	protected String indent3 = getIndentString(3);
	protected String indent4 = getIndentString(4);
	private StyledDocument detailsDoc;
	private SimpleAttributeSet textAttrSet;
	private int maxRegisterName;

	private boolean hasProgramContextDiffs = false;
	private boolean hasByteDiffs = false;
	private boolean hasCodeUnitDiffs = false;
	private boolean hasFunctionDiffs = false;
	private boolean hasSymbolDiffs = false;
	private boolean hasEquateDiffs = false;
	private boolean hasRefDiffs = false;
	private boolean hasPlateCommentDiffs = false;
	private boolean hasPreCommentDiffs = false;
	private boolean hasEolCommentDiffs = false;
	private boolean hasRepeatableCommentDiffs = false;
	private boolean hasPostCommentDiffs = false;
	private boolean hasBookmarkDiffs = false;
	private boolean hasTagDiffs = false;
	private boolean hasUserDefinedDiffs = false;

	/**
	 * Constructor for ProgramDiffDetails.
	 * @param p1 the original program
	 * @param p2 the program to diff against.
	 */
	public ProgramDiffDetails(Program p1, Program p2) {
		this.p1 = p1;
		this.p2 = p2;
		// FUTURE : Add checks to make sure programs are comparable.
		//          Throw exception if not comparable.
		initDetails();
		initAttributes();
	}

	private static String getIndentString(int indentCount) {
		int indentChars = indentCount * INDENT_SIZE;
		StringBuffer buf = new StringBuffer(indentChars);
		for (int i = 0; i < indentChars; i++) {
			buf.append(' ');
		}
		return buf.toString();
	}

	/**
	 *
	 */
	private void initAttributes() {
		textAttrSet = new SimpleAttributeSet();
		textAttrSet.addAttribute(StyleConstants.FontSize, new Integer(12));
	}

	/**
	 * Gets a string indicating the types of differences for the code units at the indicated
	 * address. The string contains information from each program where there are differences.
	 * It containing multiple lines separated by newline characters)
	 * @param p1 the original program
	 * @param p2 the program to diff against.
	 * @param p1DiffAddress the address that difference details are needed for.
	 * This address should be derived from program1.
	 * @return a string indicating the differences.
	 */
	static public String getDiffDetails(Program p1, Program p2, Address p1DiffAddress) {
		ProgramDiffDetails diffDetails = new ProgramDiffDetails(p1, p2);
		return diffDetails.getDiffDetails(p1DiffAddress);
	}

	/**
	 * Gets a string indicating the types of differences for the code units at the indicated
	 * address. The string contains information from each program where there are differences.
	 * It containing multiple lines separated by newline characters)
	 * @param p1 the original program
	 * @param p2 the program to diff against.
	 * @param p1DiffAddress the address that difference details are needed for.
	 * This address should be derived from program1.
	 * @param filter the program diff filter that indicates the diff details to show.
	 * @return a string indicating the differences.
	 */
	static public String getDiffDetails(Program p1, Program p2, Address p1DiffAddress,
			ProgramDiffFilter filter) {
		ProgramDiffDetails diffDetails = new ProgramDiffDetails(p1, p2);
		return diffDetails.getDiffDetails(p1DiffAddress, filter);
	}

	/**
	 * Gets a string indicating the types of differences for the code units at the indicated
	 * address. The string contains information from each program where there are differences.
	 * It containing multiple lines separated by newline characters)
	 * @param p1DiffAddress the address that difference details are needed for.
	 * This address should be derived from program1.
	 * @return a string indicating the differences.
	 */
	public String getDiffDetails(Address p1DiffAddress) {
		StyledDocument doc = new DefaultStyledDocument();
		getAllDetails(p1DiffAddress, doc, null);
		String text = null;
		try {
			text = doc.getText(0, doc.getLength());
		}
		catch (BadLocationException e) {
			Msg.error(this,
				"Error getting Diff details for address " + p1DiffAddress.toString() + ".", e);
		}
		return text;
	}

	/**
	 * Gets a string indicating the types of differences for the code units at the indicated
	 * address. The string contains information from each program where there are differences.
	 * It containing multiple lines separated by newline characters)
	 * @param p1DiffAddress the address that difference details are needed for.
	 * This address should be derived from program1.
	 * @param filter the program diff filter that indicates the diff details to show.
	 * @return a string indicating the differences.
	 */
	public String getDiffDetails(Address p1DiffAddress, ProgramDiffFilter filter) {
		StyledDocument doc = new DefaultStyledDocument();
		getDetails(p1DiffAddress, filter, doc, null);
		String text = null;
		try {
			text = doc.getText(0, doc.getLength());
		}
		catch (BadLocationException e) {
			Msg.error(this,
				"Error getting Diff details for address " + p1DiffAddress.toString() + ".", e);
		}
		return text;
	}

	/**
	 * Determine the detailed differences between the two programs at the
	 * indicated address. The differences are determined for the extent of the
	 * code units in the two programs at the indicated address.
	 * @param p1DiffAddress the address that difference details are needed for.
	 * This address should be derived from program1.
	 * @param doc the document where the details of differences between the two
	 * programs should be written.
	 * @param prefixString Line of text to display at beginning of the difference details information.
	 */
	public void getAllDetails(Address p1DiffAddress, StyledDocument doc, String prefixString) {
		resetDetails(p1DiffAddress, doc);
		if (prefixString != null) {
			addText(prefixString + "\n");
		}
		if (noMem) {
			addText(doc, "Program" + ((cu1 == null) ? "1" : "2") + " ");
			Program p = ((cu1 == null) ? p1 : p2);
			addColorProgram(doc, p.getDomainFile().toString());
			addText(" has ");
			addDangerColorText("no memory");
			addText(" at address ");
			addColorAddress(currentP1Address);
			addText(".\n\n");
			return;
		}
		noDifferences = true;
		addHeader();
		addProgramContextDetails(); // can throw ConcurrentModificationException.
		addByteDetails();
		addCodeUnitDetails();
		addFunctionDetails();
		addSymbolDetails();
		addEquateDetails();
		addRefDetails();
		addPlateCommentDetails();
		addPreCommentDetails();
		addEOLCommentDetails();
		addRepeatableCommentDetails();
		addPostCommentDetails();
		addBookmarkDetails();
		addUserDefinedDetails();
//		if (!noMem) {
		noDifferences =
			!hasProgramContextDiffs && !hasByteDiffs && !hasCodeUnitDiffs && !hasFunctionDiffs &&
				!hasSymbolDiffs && !hasEquateDiffs && !hasRefDiffs && !hasPlateCommentDiffs &&
				!hasPreCommentDiffs && !hasEolCommentDiffs && !hasRepeatableCommentDiffs &&
				!hasPostCommentDiffs && !hasBookmarkDiffs && !hasTagDiffs && !hasUserDefinedDiffs;
//		}
		addFooter();
		return;
	}

	/**
	 * Determine the detailed differences between the two programs at the
	 * indicated address. The differences are determined for the extent of the
	 * code units in the two programs at the indicated address.
	 * @param p1DiffAddress the address that difference details are needed for.
	 * This address should be derived from program1.
	 * @param filter the program diff filter that indicates the diff details to show.
	 * @param doc the document where the details of differences between the two
	 * programs should be written.
	 * @param prefixString Line of text to display at beginning of the difference details information.
	 */
	public void getDetails(Address p1DiffAddress, ProgramDiffFilter filter, StyledDocument doc,
			String prefixString) {
		resetDetails(p1DiffAddress, doc);
		if (prefixString != null) {
			addText(prefixString + "\n");
		}
		if (noMem) {
			addText(doc, "Program" + ((cu1 == null) ? "1" : "2") + " ");
			Program p = ((cu1 == null) ? p1 : p2);
			addColorProgram(doc, p.getDomainFile().toString());
			addText(" has ");
			addDangerColorText("no memory");
			addText(" at address ");
			addColorAddress(currentP1Address);
			addText(".\n\n");
			return;
		}
		noDifferences = true;
		addHeader();
		if (filter.getFilter(ProgramDiffFilter.PROGRAM_CONTEXT_DIFFS)) {
			addProgramContextDetails(); // can throw ConcurrentModificationException.
		}
		if (filter.getFilter(ProgramDiffFilter.BYTE_DIFFS)) {
			addByteDetails();
		}
		if (filter.getFilter(ProgramDiffFilter.CODE_UNIT_DIFFS)) {
			addCodeUnitDetails();
		}
		if (filter.getFilter(ProgramDiffFilter.FUNCTION_DIFFS)) {
			// Note: Function diff details will also include the function tag details.
			addFunctionDetails();
		}
		if (filter.getFilter(ProgramDiffFilter.SYMBOL_DIFFS)) {
			addSymbolDetails();
		}
		if (filter.getFilter(ProgramDiffFilter.EQUATE_DIFFS)) {
			addEquateDetails();
		}
		if (filter.getFilter(ProgramDiffFilter.REFERENCE_DIFFS)) {
			addRefDetails();
		}
		if (filter.getFilter(ProgramDiffFilter.PLATE_COMMENT_DIFFS)) {
			addPlateCommentDetails();
		}
		if (filter.getFilter(ProgramDiffFilter.PRE_COMMENT_DIFFS)) {
			addPreCommentDetails();
		}
		if (filter.getFilter(ProgramDiffFilter.EOL_COMMENT_DIFFS)) {
			addEOLCommentDetails();
		}
		if (filter.getFilter(ProgramDiffFilter.REPEATABLE_COMMENT_DIFFS)) {
			addRepeatableCommentDetails();
		}
		if (filter.getFilter(ProgramDiffFilter.POST_COMMENT_DIFFS)) {
			addPostCommentDetails();
		}
		if (filter.getFilter(ProgramDiffFilter.BOOKMARK_DIFFS)) {
			addBookmarkDetails();
		}
		if (filter.getFilter(ProgramDiffFilter.USER_DEFINED_DIFFS)) {
			addUserDefinedDetails();
		}
//		if (!noMem) {
		noDifferences =
			!hasProgramContextDiffs && !hasByteDiffs && !hasCodeUnitDiffs && !hasFunctionDiffs &&
				!hasSymbolDiffs && !hasEquateDiffs && !hasRefDiffs && !hasPlateCommentDiffs &&
				!hasPreCommentDiffs && !hasEolCommentDiffs && !hasRepeatableCommentDiffs &&
				!hasPostCommentDiffs && !hasBookmarkDiffs && !hasTagDiffs && !hasUserDefinedDiffs;
//		}
		addFooter();
		return;
	}

	private void addHeader() {
		if (minP1Address.equals(maxP1Address)) {
			bold(true);
			underline(true);
			addText("Difference details for address");
			underline(false);
			addText(": ");
			addColorAddress(minP1Address);
			bold(false);
			addText(newLine);
		}
		else {
			bold(true);
			underline(true);
			addText("Difference details for address range");
			underline(false);
			addText(": ");
			addText("[ ");
			addColorAddress(minP1Address);
			addText(" - ");
			addColorAddress(maxP1Address);
			addText(" ]");
			bold(false);
			addText(newLine);
		}
	}

	private void addFooter() {
		if (noDifferences) {
			addText(indent1 + "No " + (noMem ? "other " : "") + "differences." + newLine);
		}
	}

	private void initDetails() {

		l1 = p1.getListing();
		l2 = p2.getListing();

		maxRegisterName = "Register".length(); // default name length.
		for (Register element : p1.getProgramContext().getRegisters()) {
			maxRegisterName = Math.max(maxRegisterName, element.getName().length());
		}
	}

	private void resetDetails(Address p1DiffAddress, StyledDocument doc) {
		currentP1Address = p1DiffAddress;
		currentP2Address = SimpleDiffUtility.getCompatibleAddress(p1, p1DiffAddress, p2);
		this.detailsDoc = doc;
		this.noMem = false;
		try {
			doc.remove(0, doc.getLength());
		}
		catch (BadLocationException e) {
			Msg.error(this,
				"Error resetting Diff details for address " + p1DiffAddress.toString() + ".", e);
		}

		hasProgramContextDiffs = false;
		hasByteDiffs = false;
		hasCodeUnitDiffs = false;
		hasFunctionDiffs = false;
		hasSymbolDiffs = false;
		hasEquateDiffs = false;
		hasRefDiffs = false;
		hasPlateCommentDiffs = false;
		hasPreCommentDiffs = false;
		hasEolCommentDiffs = false;
		hasRepeatableCommentDiffs = false;
		hasPostCommentDiffs = false;
		hasBookmarkDiffs = false;
		hasTagDiffs = false;
		hasUserDefinedDiffs = false;

		cu1At = l1.getCodeUnitAt(currentP1Address);
		cu2At = (currentP2Address != null) ? l2.getCodeUnitAt(currentP2Address) : null;
		cu1 = l1.getCodeUnitContaining(currentP1Address);
		cu2 = (currentP2Address != null) ? l2.getCodeUnitContaining(currentP2Address) : null;
		if ((cu1 == null) || (cu2 == null)) {
			noMem = true;
//			return;
		}
		Address cu1Min = (cu1 != null) ? cu1.getMinAddress() : null;
		Address cu1Max = (cu1 != null) ? cu1.getMaxAddress() : null;
		Address cu2Min = (cu2 != null) ? cu2.getMinAddress() : null;
		Address cu2Max = (cu2 != null) ? cu2.getMaxAddress() : null;
		Address cu2MinAsP1Addr = SimpleDiffUtility.getCompatibleAddress(p2, cu2Min, p1);
		Address cu2MaxAsP1Addr = SimpleDiffUtility.getCompatibleAddress(p2, cu2Max, p1);

		// The min address for the second program's code unit might not be in the first program.
		minP1Address = ((cu2MinAsP1Addr == null) ||
			(((cu1Min != null) && cu1Min.compareTo(cu2MinAsP1Addr) <= 0)) ? cu1Min
					: cu2MinAsP1Addr);

		// The max address for the second program's code unit might not be in the first program.
		maxP1Address = ((cu2MaxAsP1Addr == null) ||
			((cu1Max != null) && cu1Max.compareTo(cu2MaxAsP1Addr) >= 0)) ? cu1Max : cu2MaxAsP1Addr;

		checkP1AddressSet = new AddressSet(minP1Address, maxP1Address);
	}

	/**
	 * Gets the address set where detailed differences will be determined for details at the
	 * indicated address. An address set is returned since the indicated address may be in different
	 * sized code units in each of the two programs.
	 * @param p1Address the current address where details are desired.
	 * This address may be from program1 or program2.
	 * @return the program1 address set for code units containing that address within the programs being diffed.
	 */
	public AddressSetView getDetailsAddressSet(final Address p1Address) {
		Address p2Address = SimpleDiffUtility.getCompatibleAddress(p1, p1Address, p2);
		CodeUnit codeunit1 = (p1Address != null) ? l1.getCodeUnitContaining(p1Address) : null;
		CodeUnit codeunit2 = (p2Address != null) ? l2.getCodeUnitContaining(p2Address) : null;
		if ((codeunit1 == null) || (codeunit2 == null)) {
			noMem = true;
			return new AddressSet();
		}
		Address cu1Min = codeunit1.getMinAddress();
		Address cu1Max = codeunit1.getMaxAddress();
		Address cu2Min = codeunit2.getMinAddress();
		Address cu2Max = codeunit2.getMaxAddress();
		Address cu2MinAsP1Addr = SimpleDiffUtility.getCompatibleAddress(p2, cu2Min, p1);
		Address cu2MaxAsP1Addr = SimpleDiffUtility.getCompatibleAddress(p2, cu2Max, p1);

		// The min address for the second program's code unit might not be in the first program.
		Address minimum =
			((cu2MinAsP1Addr == null) || (cu1Min.compareTo(cu2MinAsP1Addr) <= 0)) ? cu1Min
					: cu2MinAsP1Addr;

		// The max address for the second program's code unit might not be in the first program.
		Address maximum =
			((cu2MaxAsP1Addr == null) || (cu1Max.compareTo(cu2MaxAsP1Addr) >= 0)) ? cu1Max
					: cu2MaxAsP1Addr;

		return new AddressSet(minimum, maximum);
	}

	private void addByteDetails() {
		int addrLen = Math.max(7, minP1Address.toString().length());
		Memory mem1 = p1.getMemory();
		Memory mem2 = p2.getMemory();
		try {
			for (Address tmpAddr = minP1Address; tmpAddr.compareTo(maxP1Address) <= 0; tmpAddr =
				tmpAddr.add(1)) {
				addByteInfo(tmpAddr, addrLen, mem1, mem2);
			}
		}
		catch (AddressOutOfBoundsException e) {
			//This can occur at the end of a block.
		}
	}

	private void addByteHeader(int addrLength, Memory mem1, Memory mem2) {
		addDiffHeader("Byte");
		addByteInfo(null, addrLength, mem1, mem2);
	}

	/**
	 * Adds a string to the details indicating the address with byte differences and the byte values.
	 * @param p1Address the address to get the bytes for.
	 * This address should be derived from program1.
	 * @param addrLength the length of the address field.
	 * @param mem1 the first program's memory for obtaining the bytes
	 * @param mem2 the second program's memory.
	 */
	private void addByteInfo(Address p1Address, int addrLength, Memory mem1, Memory mem2) {
		String separatorSpaces = getSpaces(2);
		if (p1Address == null) {
			String spacesAfterAddr = getSpaces(addrLength - "Address".length());
			// Underline the header.
			addText(indent1);
			underline("Address");
			addText(spacesAfterAddr);
			addText(separatorSpaces);
			underline("Program1");
			addText(separatorSpaces);
			underline("Program2");
			addText(newLine);
		}
		else {
			Address p2Address = SimpleDiffUtility.getCompatibleAddress(p1, p1Address, p2);
			String addr = p1Address.toString();
			boolean hasB1 = true;
			boolean hasB2 = true;
			byte b1;
			byte b2;
			String b1Str;
			String b2Str;
			try {
				b1 = mem1.getByte(p1Address);
				b1Str = "0x" + getHexByte(b1);
			}
			catch (MemoryAccessException e) {
				b1Str = "Undefined";
				hasB1 = false;
			}
			if (p2Address != null) {
				try {
					b2 = mem2.getByte(p2Address);
					b2Str = "0x" + getHexByte(b2);
				}
				catch (MemoryAccessException e) {
					b2Str = "Undefined";
					hasB2 = false;
				}
			}
			else {
				b2Str = "Undefined";
				hasB2 = false;
			}
			if (b1Str.equals(b2Str)) {
				return; // No differences
			}
			if (!hasByteDiffs) {
				addByteHeader(addrLength, mem1, mem2);
				hasByteDiffs = true;
			}
			String spacesAfterAddr = getSpaces(addrLength - addr.length());
			addText(indent1);
			addColorAddress(p1Address);
			addText(spacesAfterAddr);
			addText(separatorSpaces);
			if (hasB1) {
				addText("  ");
			}
			addColorText(b1Str);
			if (hasB1) {
				addText("   ");
			}
			addText(separatorSpaces);
			if (hasB2) {
				addText("  ");
			}
			addColorText(b2Str);
			addText(newLine);
		}
	}

	private String getHexByte(byte b) {
		String bStr = Integer.toHexString(b);
		if (b >= (byte) 0x00 && b <= (byte) 0x0F) {
			return "0" + bStr;
		}
		if (bStr.length() > 2) {
			bStr = bStr.substring(bStr.length() - 2);
		}
		return bStr;
	}

	private void addSymbolDetails() {
		try {
			for (Address tmpAddr = minP1Address; tmpAddr.compareTo(maxP1Address) <= 0; tmpAddr =
				tmpAddr.add(1)) {
				addLabelInfo(tmpAddr);
			}
		}
		catch (AddressOutOfBoundsException e) {
			//This can occur at the end of a block.
		}
	}

	private void addLabelInfo(Address p1Address) {
		Address p2Address = SimpleDiffUtility.getCompatibleAddress(p1, p1Address, p2);

		Symbol[] s1 = p1.getSymbolTable().getSymbols(p1Address);
		Symbol[] s2 =
			(p2Address != null) ? p2.getSymbolTable().getSymbols(p2Address) : new Symbol[0];
		// Need to get lists of symbols without default labels.
		s1 = stripDefaultLabels(s1);
		s2 = stripDefaultLabels(s2);
		if ((s1.length == 0) && (s2.length == 0)) {
			return;
		}

		Comparator<Symbol> c = SymbolUtilities.getSymbolNameComparator();
		Arrays.sort(s1, c);
		Arrays.sort(s2, c);

		boolean s1IsEntry = ((s1.length > 0) && s1[0].isExternalEntryPoint());
		boolean s2IsEntry = ((s2.length > 0) && s2[0].isExternalEntryPoint());
		boolean entryPtsDiffer = (s1IsEntry != s2IsEntry);
		if (entryPtsDiffer) {
			if (!hasSymbolDiffs) {
				addDiffHeader("Label");
				hasSymbolDiffs = true;
			}
		}

		boolean sameSyms = sameSymbols(s1, s2);
		int maxLen = "Name".length();
		int maxTypeLen = "Type".length();
		int maxSourceLen = "Source".length();
		if (!sameSyms) {
			if (!hasSymbolDiffs) {
				addDiffHeader("Label");
				hasSymbolDiffs = true;
			}
			for (Symbol element : s1) {
				int len = element.getName().length();
				if (len > maxLen) {
					maxLen = len;
				}
				int typelen = element.getSymbolType().toString().length();
				if (typelen > maxTypeLen) {
					maxTypeLen = typelen;
				}
				int sourceLen = element.getSource().toString().length();
				if (sourceLen > maxSourceLen) {
					maxSourceLen = sourceLen;
				}
			}
			for (Symbol element : s2) {
				int len = element.getName().length();
				if (len > maxLen) {
					maxLen = len;
				}
				int typelen = element.getSymbolType().toString().length();
				if (typelen > maxTypeLen) {
					maxTypeLen = typelen;
				}
				int sourceLen = element.getSource().toString().length();
				if (sourceLen > maxSourceLen) {
					maxSourceLen = sourceLen;
				}
			}
			addSymbolInfo(1, p1Address, s1IsEntry, s1, maxLen, maxTypeLen, maxSourceLen);
			addSymbolInfo(2, p2Address, s2IsEntry, s2, maxLen, maxTypeLen, maxSourceLen);
		}
		else if (entryPtsDiffer) {
			addSymbolInfo(1, p1Address, s1IsEntry, null, 0, 0, 0);
			addSymbolInfo(2, p2Address, s2IsEntry, null, 0, 0, 0);
		}
	}

	private Symbol[] stripDefaultLabels(Symbol[] originalSymbols) {
		ArrayList<Symbol> list = new ArrayList<>();
		for (Symbol symbol : originalSymbols) {
			SymbolType symbolType = symbol.getSymbolType();
			if (symbolType.equals(SymbolType.FUNCTION) || (symbolType.equals(SymbolType.LABEL) &&
				!symbol.getSource().equals(SourceType.DEFAULT))) {
				list.add(symbol);
			}
		}
		return list.toArray(new Symbol[list.size()]);
	}

	/**
	 * @param addr
	 */
	private void addEntryPtLine(Address addr) {
		addText(indent2);
		addColorAddress(addr);
		addText(" is an ");
		addColorText("External Entry Point");
		addText("." + newLine);
	}

	private void addSymbolInfo(int pgmNum, Address pgmAddress, boolean isEntryPt, Symbol[] symbols,
			int maxLen, int maxTypeLen, int maxSourceLen) {
		addProgramText(pgmNum, pgmAddress);
		if (isEntryPt) {
			addEntryPtLine(pgmAddress);
		}
		if (symbols == null) {
			return; // null indicates symbols were the same.
		}
		if (symbols.length == 0) {
			addText(indent2 + "No symbols." + newLine);
			return;
		}
		addDisplayLabel(null, maxLen, maxTypeLen, maxSourceLen); // Header
		for (Symbol symbol : symbols) {
			addDisplayLabel(symbol, maxLen, maxTypeLen, maxSourceLen);
		}
	}

	/**
	 * Determines whether the two arrays of symbols are equal.
	 * @param s1 first array of symbols
	 * @param s2 second array of symbols
	 * @return true if the arrays of symbols are equal.
	 */
	private boolean sameSymbols(Symbol[] s1, Symbol[] s2) {
		if (s1.length != s2.length) {
			return false;
		}
		for (int i = 0; i < s1.length; i++) {
			if (!ProgramDiff.equivalentSymbols(p1, p2, s1[i], s2[i])) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Gets a string indicating the label name and its attributes.
	 * @param symbol the symbol to get the name and attributes for.
	 * @param nameLength the length of the name field.
	 * @param typeLength the length of the type field.
	 * @param sourceLength the length of the source field.
	 * @return the string with the label name and attributes.
	 */
	private void addDisplayLabel(Symbol symbol, int nameLength, int typeLength, int sourceLength) {
		String name = "";
		String type = "";
		String primary = getSpaces(7);
		String source = "";
		String namespace = "";
		String yes = getSpaces(2) + "yes" + getSpaces(2);
		String separatorSpaces = getSpaces(2);

		addText(indent2);
		if (symbol == null) {
			// Underline the header.
			underline("Name");
			addText(getSpaces(nameLength - "Name".length()));
			addText(separatorSpaces);
			underline("Type");
			addText(getSpaces(typeLength - "Type".length()));
			addText(separatorSpaces);
			underline("Primary");
			addText(separatorSpaces);
			underline("Source");
			addText(getSpaces(sourceLength - "Source".length()));
			addText(separatorSpaces);
			underline("Namespace");
		}
		else {
			name = symbol.getName();
			SymbolType symType = symbol.getSymbolType();
			type = symType.toString();
			source = symbol.getSource().toString();
			if (symbol.isPrimary()) {
				primary = yes;
			}
			Namespace parentNS = symbol.getParentNamespace();
			namespace = ((parentNS instanceof GlobalNamespace) ? parentNS.getName()
					: parentNS.getName(true));

			addColorText(name);
			addText(getSpaces(nameLength - name.length()));
			addText(separatorSpaces);
			addColorText(type);
			addText(getSpaces(typeLength - type.length()));
			addText(separatorSpaces);
			addColorText(primary);
			addText(separatorSpaces);
			addColorText(source);
			addText(getSpaces(sourceLength - source.length()));
			addText(separatorSpaces);
			addColorText(namespace);
			if (symbol.isPinned()) {
				addText(separatorSpaces);
				addColorText("(pinned)");
			}
		}
		addText(newLine);
	}

	private void addCodeUnitDetails() {
		if (cu1 instanceof Data && cu2 instanceof Data) {
			if (!isSameData((Data) cu1, (Data) cu2)) {
				addSubDataInfo((Data) cu1, (Data) cu2);
			}
		}
		else if (cu1 instanceof Instruction && cu2 instanceof Instruction) {
			if (!isSameInstruction((Instruction) cu1, (Instruction) cu2)) {
				addSimpleCodeUnitInfo();
			}
		}
		else {
			addSimpleCodeUnitInfo();
		}
	}

	private void addSubDataInfo(Data d1, Data d2) {
		String indent = indent2;
		StringBuffer buf1 = new StringBuffer();
		StringBuffer buf2 = new StringBuffer();
		compareDataCUs(d1, d2, buf1, buf2, indent);
		addDiffHeader("Code Unit");
		addProgramText(1);
		addText(buf1.toString());
		if (cu1At != null) {
			CodeUnit cu = l1.getCodeUnitAfter(cu1At.getMaxAddress());
			if (cu != null) {
				Address addr = cu.getMinAddress();
				addText(getCodeUnitInfo(l1, addr, indent));
			}
		}
		addProgramText(2);
		addText(buf2.toString());
		if (cu2At != null) {
			CodeUnit cu = l2.getCodeUnitAfter(cu2At.getMaxAddress());
			if (cu != null) {
				Address addr = cu.getMinAddress();
				addText(getCodeUnitInfo(l2, addr, indent));
			}
		}
		hasCodeUnitDiffs = true;
	}

	private void compareDataTypeComponents(DataTypeComponent dtc1, DataTypeComponent dtc2,
			StringBuffer buf1, StringBuffer buf2, String indent) {

		getComponentInfo(dtc1, buf1, indent);
		getComponentInfo(dtc2, buf2, indent);
		compareSubDataTypes(dtc1.getDataType(), dtc2.getDataType(), buf1, buf2, indent);
	}

	private void compareSubDataTypes(DataType dt1, DataType dt2, StringBuffer buf1,
			StringBuffer buf2, String indent) {
		String newIndent = indent + indent1;
		DataType actualDt1 = dt1;
		DataType actualDt2 = dt2;
		if ((actualDt1 != actualDt2) &&
			((actualDt1 instanceof Structure && actualDt2 instanceof Structure) ||
				(actualDt1 instanceof Union && actualDt2 instanceof Union))) {
			compareCompositeComponents((Composite) actualDt1, (Composite) actualDt2, buf1, buf2,
				newIndent);
		}
	}

	private void compareCompositeComponents(Composite dt1, Composite dt2, StringBuffer buf1,
			StringBuffer buf2, String newIndent) {
		DataTypeComponent[] compDt1 = dt1.getComponents();
		DataTypeComponent[] compDt2 = dt2.getComponents();
		int min = (compDt1.length <= compDt2.length) ? compDt1.length : compDt2.length;
		int i = 0;
		for (; i < min; i++) {
			compareDataTypeComponents(compDt1[i], compDt2[i], buf1, buf2, newIndent);
		}
		for (int index1 = i; index1 < compDt1.length; index1++) {
			getComponentInfo(compDt1[index1], buf1, newIndent);
		}
		for (int index2 = i; index2 < compDt2.length; index2++) {
			getComponentInfo(compDt2[index2], buf2, newIndent);
		}
	}

	private void compareDataCUs(Data d1, Data d2, StringBuffer buf1, StringBuffer buf2,
			String indent) {
		String newIndent = indent + indent1;
		DataType actualDt1 = d1.getDataType();
		DataType actualDt2 = d2.getDataType();
		String name1 = getCategoryName(actualDt1);
		String name2 = getCategoryName(actualDt2);
		getCUString(indent, buf1, cu1);
		getCUString(indent, buf2, cu2);
		if ((actualDt1 != actualDt2) && (name1.equals(name2)) &&
			((actualDt1 instanceof Structure && actualDt2 instanceof Structure) ||
				(actualDt1 instanceof Union && actualDt2 instanceof Union))) {
			compareCompositeComponents((Composite) actualDt1, (Composite) actualDt2, buf1, buf2,
				newIndent);
		}
	}

	private DataType getComponentInfo(DataTypeComponent dtc, StringBuffer buf, String indent) {
		int offset = dtc.getOffset();
		int ordinal = dtc.getOrdinal();
		String comment = dtc.getComment();
		String fieldName = dtc.getFieldName();
		DataType actualDt = dtc.getDataType();
		if (fieldName == null) {
			fieldName = dtc.getDefaultFieldName();
		}
		// TODO: how should we display bitfields?
		buf.append(indent + "Offset=" + DiffUtility.toSignedHexString(offset) + " " + "Ordinal=" +
			ordinal + " " + fieldName + " " + actualDt.getMnemonic(actualDt.getDefaultSettings()) +
			"  " + getCategoryName(actualDt) + " " + "DataTypeSize=" +
			(actualDt.isZeroLength() ? 0 : actualDt.getLength()) + " " + "ComponentSize=" +
			dtc.getLength() + " " + ((comment != null) ? comment : "") +
			" " + newLine);
		return actualDt;
	}

	private String getCategoryName(DataType dt) {
		return dt.getPathName();
	}

	private void addSimpleCodeUnitInfo() {
		String newIndent = indent2 + indent1;
		String cui1 = getCodeUnitInfo(l1, currentP1Address, newIndent);
		String cui2 = getCodeUnitInfo(l2, currentP2Address, newIndent);
		if (!cui1.equals(cui2)) {
			addDiffHeader("Code Unit");
			addProgramText(1);
			addText(cui1);
			addProgramText(2);
			addText(cui2);
			hasCodeUnitDiffs = true;
		}
	}

	private String getCodeUnitInfo(Listing listing, Address addr, String indent) {
		String newIndent = indent + indent1;
		CodeUnit cu = (addr != null) ? listing.getCodeUnitContaining(addr) : null;
		if (cu == null) {
			return indent + "No instruction or data." + newLine;
		}
		StringBuffer buf = new StringBuffer();
		Address maxAddress = maxP1Address;
		if (listing == l2) {
			maxAddress = SimpleDiffUtility.getCompatibleAddress(p1, maxP1Address, p2);
		}
		int maxVisibleLines = 100;
		int linesSoFar = 0;
		while ((cu != null) && (maxAddress != null) &&
			(cu.getMinAddress().compareTo(maxAddress) <= 0) && (linesSoFar < maxVisibleLines)) {
			Address min = getCUString(indent, buf, cu);
			if (cu instanceof Data) {
				Data data = (Data) cu;
				DataType dt = data.getDataType();
				if (dt instanceof Composite) {
					DataTypeComponent[] components = ((Composite) dt).getComponents();
					for (DataTypeComponent dtc : components) {
						int offset = dtc.getOffset();
						String comment = dtc.getComment();
						String fieldName = dtc.getFieldName();
						if (fieldName == null) {
							fieldName = "field" + offset;
						}
						buf.append(newIndent + min.add(offset) + " " + dtc.getFieldName() + " " +
							dtc.getDataType().getName() + " " + "length=" +
							dtc.getLength() + " " +
							((comment != null) ? comment : "") + " " + newLine);
					}
				}
			}
			cu = listing.getCodeUnitAfter(cu.getMaxAddress());
			linesSoFar++;
		}
		if (linesSoFar >= maxVisibleLines) {
			buf.append(newIndent + "... Too many code unit lines for display, so truncating at " +
				maxVisibleLines + " lines." + newLine);
		}
		return buf.toString();
	}

	private Address getCUString(String indent, StringBuffer buf, CodeUnit cu) {
		Address min = cu.getMinAddress();
		Address max = cu.getMaxAddress();
		String addrRangeStr = min + ((min.equals(max)) ? "" : " - " + max);
		String cuRep;
		if (cu instanceof Data) {
			cuRep = ((Data) cu).getDataType().getPathName();
		}
		else if (cu instanceof Instruction) {
			Instruction inst = (Instruction) cu;
			boolean removedFallThrough =
				inst.isFallThroughOverridden() && (inst.getFallThrough() == null);
			boolean hasFlowOverride = inst.getFlowOverride() != FlowOverride.NONE;
			cuRep = cu.toString();
			if (removedFallThrough) {
				cuRep += newLine + indent + getSpaces(addrRangeStr.length()) + "    " +
					"Removed FallThrough";
			}
			else if (inst.isFallThroughOverridden()) {
				// Show the fallthrough override.
				Address fallThroughAddress = inst.getFallThrough();
				Reference[] refs = inst.getReferencesFrom();
				for (Reference ref : refs) {
					if (ref.getReferenceType().isFallthrough()) {
						Address toAddress = ref.getToAddress();
						boolean isOverride = SystemUtilities.isEqual(fallThroughAddress, toAddress);
						String prefix =
							isOverride ? "FallThrough Override: " : "FallThrough Reference: ";
						cuRep += newLine + indent + getSpaces(addrRangeStr.length()) + "    " +
							prefix + DiffUtility.getUserToAddressString(inst.getProgram(), ref);
					}
				}
			}
			if (hasFlowOverride) {
				cuRep += newLine + indent + getSpaces(addrRangeStr.length()) + "    " +
					"Flow Override: " + inst.getFlowOverride();
			}
			cuRep += newLine + indent + getSpaces(addrRangeStr.length()) + "    " +
				"Instruction Prototype hash = " +
				Integer.toHexString(inst.getPrototype().hashCode());
		}
		else {
			cuRep = cu.toString();
		}
		buf.append(indent + addrRangeStr + "    " + cuRep + newLine);
		return min;
	}

	private void addRefDetails() {
		ReferenceManager rm1 = p1.getReferenceManager();
		ReferenceManager rm2 = p2.getReferenceManager();
		Address addr1 = minP1Address;
		Address addr2 = SimpleDiffUtility.getCompatibleAddress(p1, addr1, p2);
		while (addr1.compareTo(maxP1Address) <= 0) {
			Reference[] refs1 = rm1.getReferencesFrom(addr1);
			Reference[] refs2 = (addr2 != null) ? rm2.getReferencesFrom(addr2) : new Reference[0];
			// Only compare the non-fallthrough refs.
			Reference[] diffRefs1 = ProgramDiff.getDiffRefs(refs1);
			Reference[] diffRefs2 = ProgramDiff.getDiffRefs(refs2);
			Arrays.sort(diffRefs1);
			Arrays.sort(diffRefs2);
			if (!ProgramDiff.equivalentReferenceArrays(p1, p2, diffRefs1, diffRefs2)) {
				getRefsText(addr1, diffRefs1, diffRefs2);
			}
			try {
				addr1 = addr1.addNoWrap(1);
			}
			catch (AddressOverflowException e) {
				// bail at end of space
				break;
			}
			addr2 = SimpleDiffUtility.getCompatibleAddress(p1, addr1, p2);
		}
	}

	private void getRefsText(Address p1Address, Reference[] refs1, Reference[] refs2) {
		Address p2Address = SimpleDiffUtility.getCompatibleAddress(p1, p1Address, p2);
		if (!hasRefDiffs) {
			addDiffHeader("Reference");

		}
		addProgramText(1, p1Address);
		addText(getProgramRefDetails(p1, refs1, p2));
		addProgramText(2, p2Address);
		addText(getProgramRefDetails(p2, refs2, p1));
		hasRefDiffs = true;
	}

	private String getRefInfo(Program pgm, Reference ref) {
		String typeStr = "Type: " + ref.getReferenceType();
		String fromStr = "  From: " + ref.getFromAddress();
		String operandStr =
			((ref.isMnemonicReference()) ? "  Mnemonic" : ("  Operand: " + ref.getOperandIndex()));
		String toStr = "  To: " + DiffUtility.getUserToAddressString(pgm, ref);
		String sourceStr = "  " + ref.getSource().toString();
		String primaryStr = ((ref.isPrimary()) ? "  Primary" : "");
		String symbolStr = "";
		long symbolID = ref.getSymbolID();
		if (symbolID != -1) {
			Symbol sym = pgm.getSymbolTable().getSymbol(symbolID);
			if (sym != null) {
				symbolStr = "  Symbol: " + sym.getName(true);
			}
		}
		return typeStr + fromStr + operandStr + toStr + sourceStr + primaryStr + symbolStr;
	}

	private String getProgramRefDetails(Program pgm, Reference[] refs, Program otherProgram) {
		StringBuffer buf = new StringBuffer();
		for (Reference ref : refs) {
			Reference otherRef = DiffUtility.getReference(pgm, ref, otherProgram);
			if ((otherRef != null) &&
				ProgramDiff.equivalentReferences(pgm, otherProgram, ref, otherRef)) {
				continue;
			}
			if (ref.isExternalReference()) {
				buf.append(indent2 + "External Reference " + getRefInfo(pgm, ref) + newLine);
			}
			else if (ref.isStackReference()) {
				buf.append(indent2 + "Stack Reference " + getRefInfo(pgm, ref) + newLine);
			}
			else {
				buf.append(indent2 + "Reference " + getRefInfo(pgm, ref) + newLine);
			}
		}
		if (buf.length() == 0) {
			return indent2 + "No unmatched references." + newLine;
		}
		return buf.toString();
	}

	private void addEquateDetails() {
		EquateTable et1 = p1.getEquateTable();
		EquateTable et2 = p2.getEquateTable();
		AddressSet checkP2AddressSet = DiffUtility.getCompatibleAddressSet(checkP1AddressSet, p2);
		AddressIterator iter1 = et1.getEquateAddresses(checkP1AddressSet);
		AddressIterator iter2 = et2.getEquateAddresses(checkP2AddressSet);
		// The MultiAddressIterator needs all iterators to be from the same program to work properly.
		// So convert the program2 iterator to a program1 iterator and pass that as the second iterator.
		AddressIteratorConverter convertedIter2 = new AddressIteratorConverter(p2, iter2, p1);
		MultiAddressIterator iter =
			new MultiAddressIterator(new AddressIterator[] { iter1, convertedIter2 }, true);
		while (iter.hasNext()) {
			Address p1Address = iter.next();
			addEquateInfo(et1, et2, p1Address);
		}
	}

	private void addEquateInfo(EquateTable et1, EquateTable et2, Address p1Address) {
		boolean hasAddrDiffs = false;
		for (int opIndex = 0; opIndex < Program.MAX_OPERANDS; opIndex++) {
			hasAddrDiffs = addEquateInfo(et1, et2, p1Address, opIndex, hasAddrDiffs);
		}
	}

	private boolean addEquateInfo(EquateTable et1, EquateTable et2, Address p1Address, int opIndex,
			boolean hasAddrDiffs) {
		Address p2Address = SimpleDiffUtility.getCompatibleAddress(p1, p1Address, p2);
		boolean hasAddr1 = hasAddrDiffs;
		boolean hasAddr2 = hasAddrDiffs;
		List<Equate> list1 = et1.getEquates(p1Address, opIndex);
		List<Equate> list2 = et2.getEquates(p2Address, opIndex);
		Equate[] eq1 = list1.toArray(new Equate[list1.size()]);
		Equate[] eq2 = list2.toArray(new Equate[list2.size()]);
		if (!sameEquates(eq1, eq2)) {
			if (!hasEquateDiffs) {
				addDiffHeader("Equate");
				hasEquateDiffs = true;
			}
			if (!hasAddr1) {
				addProgramText(1, p1Address);
				hasAddrDiffs = true;
			}

			int nameLen = "Equate".length();
			int valueLen = "Value".length();
			for (Equate element : eq1) {
				int len = element.getName().length();
				if (len > nameLen) {
					nameLen = len;
				}
				int vlen = Long.toHexString(element.getValue()).length();
				if (vlen > valueLen) {
					valueLen = vlen;
				}
			}
			for (Equate element : eq2) {
				int len = element.getName().length();
				if (len > nameLen) {
					nameLen = len;
				}
				int vlen = Long.toHexString(element.getValue()).length();
				if (vlen > valueLen) {
					valueLen = vlen;
				}
			}

			addOperandText(opIndex);
			addEquates(eq1, nameLen, valueLen);
			if (!hasAddr2) {
				addProgramText(2, p2Address);
				hasAddrDiffs = true;
			}
			addEquates(eq2, nameLen, valueLen);
		}
		return hasAddrDiffs;
	}

	/**
	 * @param opIndex
	 */
	private void addOperandText(int opIndex) {
		addText(indent2);
		addText("Operand: ");
		addColorText(Integer.toString(opIndex));
		addText(newLine);
	}

	private void addEquates(Equate[] eq, int nameLen, int valueLen) {
		int num = eq.length;
		if (num == 0) {
			addText(indent3 + "No equates." + newLine);
		}
		else {
			addDisplayEquate(null, nameLen, valueLen);
			for (int i = 0; i < num; i++) {
				addDisplayEquate(eq[i], nameLen, valueLen);
			}
		}
	}

	private void addDisplayEquate(Equate equate, int nameLength, int valueLength) {

		String separatorSpaces = getSpaces(2);

		addText(indent3);
		if (equate == null) {
			// Underline the header.
			underline("Equate");
			addText(getSpaces(nameLength - "Equate".length()));
			addText(separatorSpaces);
			underline("Value");
			addText(getSpaces(valueLength - "Value".length()));
		}
		else {
			String name = equate.getName();
			long eqValue = equate.getValue();
			String value = Long.toString(eqValue) + (" or 0x" + Long.toHexString(eqValue));

			addColorText(name);
			addText(getSpaces(nameLength - name.length()));
			addText(separatorSpaces);
			addText(getSpaces(valueLength - value.length()));
			addColorText(value);
		}
		addText(newLine);
	}

	private boolean sameEquates(Equate[] e1, Equate[] e2) {
		if (e1.length != e2.length) {
			return false;
		}
		for (int i = 0; i < e1.length; i++) {
			if (!e1[i].equals(e2[i])) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Gets the Diff Details for the program context registers.
	 * @throws ConcurrentModificationException if analysis is modifying the program context.
	 */
	private void addProgramContextDetails() throws ConcurrentModificationException {

		if (!ProgramMemoryComparator.sameProgramContextRegisterNames(p1, p2)) {
			addDiffHeader("Program Context");
			addText(
				indent1 + "Program Context Registers don't match between the programs." + newLine);
			return;
		}

		// Check all the register's values and output any differences.
		ProgramContext pc1 = p1.getProgramContext();
		ProgramContext pc2 = p2.getProgramContext();
		for (Register reg1 : pc1.getRegisters()) {
			addRegisterDiffDetails(pc1, pc2, reg1);
		}
	}

	/**
	 * Adds the Diff Details for the indicated register to the details document.
	 * @param pc1 first program's register context
	 * @param pc2 second program's register context
	 * @param reg1 the register
	 * @throws ConcurrentModificationException if analysis is modifying the program context.
	 */
	private void addRegisterDiffDetails(ProgramContext pc1, ProgramContext pc2, Register reg1)
			throws ConcurrentModificationException {
		String name = reg1.getName();
		Register reg2 = pc2.getRegister(name);

		AddressRangeIterator p1AddressRangeIter = checkP1AddressSet.getAddressRanges();
		while (p1AddressRangeIter.hasNext()) {
			AddressRange p1Range = p1AddressRangeIter.next();
			Address min1 = p1Range.getMinAddress();
			Address max1 = p1Range.getMaxAddress();
			Address min2 = SimpleDiffUtility.getCompatibleAddress(p1, min1, p2);
			Address max2 = SimpleDiffUtility.getCompatibleAddress(p1, max1, p2);

			AddressRangeIterator it1 = pc1.getRegisterValueAddressRanges(reg1, min1, max1); // Can throw ConcurrentModificationException
			AddressRangeIterator it2 = pc2.getRegisterValueAddressRanges(reg2, min2, max2); // Can throw ConcurrentModificationException

			// CombinedAddressRangeIterator only works for iterators from the same program.
			// So convert the program2 iterator to a program1 iterator and pass it to the constructor.
			AddressRangeIteratorConverter convertedIt2 = new AddressRangeIteratorConverter(it2, p1);
			AddressRangeIterator p1CombinedIterator =
				new CombinedAddressRangeIterator(it1, convertedIt2);

			while (p1CombinedIterator.hasNext()) {
				AddressRange addrRange1 = p1CombinedIterator.next();
				Address rangeMin1 = addrRange1.getMinAddress();
				Address rangeMax1 = addrRange1.getMaxAddress();
				Address rangeMin2 = SimpleDiffUtility.getCompatibleAddress(p1, rangeMin1, p2);
				BigInteger value1 = pc1.getValue(reg1, rangeMin1, false);
				BigInteger value2 = pc2.getValue(reg2, rangeMin2, false);
				boolean sameValue = (value1 == null) ? (value2 == null) : value1.equals(value2);
				if (!sameValue) {
					if (!hasProgramContextDiffs) {
						addDiffHeader("Program Context");
						addDisplayRegValues(null, rangeMin1, rangeMax1, value1, value2);
						hasProgramContextDiffs = true;
					}
					addDisplayRegValues(reg1, rangeMin1, rangeMax1, value1, value2);
				}
			}
		}
	}

	private void addDisplayRegValues(Register reg, Address p1MinRegAddr, Address p1MaxRegAddr,
			BigInteger value1, BigInteger value2) {
		String minStr = p1MinRegAddr.toString();
		String maxStr = p1MaxRegAddr.toString();
		String separatorSpaces = getSpaces(2);

		AddressSpace p1DefaultSpace = p1.getAddressFactory().getDefaultAddressSpace();
		int maxAddrLength = p1DefaultSpace.getMaxAddress().toString().length();
		if (maxAddrLength < 10) {
			maxAddrLength = 10;
		}
		int maxValueLength = Long.toHexString(-1L).length() + 2;
		if (maxValueLength < 14) {
			maxValueLength = 14;
		}

		addText(indent2);
		if (reg == null) {
			// Underline the header.
			underline("Register");
			underline(getSpaces(maxRegisterName - "Register".length()));
			addText(separatorSpaces);
			underline("MinAddress");
			underline(getSpaces(maxAddrLength - "MinAddress".length()));
			addText(separatorSpaces);
			underline("MaxAddress");
			underline(getSpaces(maxAddrLength - "MaxAddress".length()));
			addText(separatorSpaces);
			underline("Program1 Value");
			underline(getSpaces(maxValueLength - "Program1 Value".length()));
			addText(separatorSpaces);
			underline("Program2 Value");
			underline(getSpaces(maxValueLength - "Program2 Value".length()));
		}
		else {
			String regName = reg.getName();
			addColorText(regName);
			addText(getSpaces(maxRegisterName - regName.length()));
			addText(separatorSpaces);
			addColorText(minStr);
			addText(getSpaces(maxAddrLength - minStr.length()));
			addText(separatorSpaces);
			addColorText(maxStr);
			addText(getSpaces(maxAddrLength - maxStr.length()));
			addText(separatorSpaces);
			String value1Str = (value1 != null) ? "0x" + value1.toString(16) : "Undefined";
			addText(getSpaces(maxValueLength - value1Str.length()));
			addColorText(value1Str);
			addText(separatorSpaces);
			String value2Str = (value2 != null) ? "0x" + value2.toString(16) : "Undefined";
			addText(getSpaces(maxValueLength - value2Str.length()));
			addColorText(value2Str);
		}
		addText(newLine);
	}

	private void addEOLCommentDetails() {
		hasEolCommentDiffs = addSpecificCommentDetails(CodeUnit.EOL_COMMENT, "EOL-Comment");
	}

	private void addPreCommentDetails() {
		hasPreCommentDiffs = addSpecificCommentDetails(CodeUnit.PRE_COMMENT, "Pre-Comment");
	}

	private void addPostCommentDetails() {
		hasPostCommentDiffs = addSpecificCommentDetails(CodeUnit.POST_COMMENT, "Post-Comment");
	}

	private void addPlateCommentDetails() {
		hasPlateCommentDiffs = addSpecificCommentDetails(CodeUnit.PLATE_COMMENT, "Plate-Comment");
	}

	/**
	 * Displays tag differences if they exist between the two functions.
	 *
	 * @param doc1 text to show for program 1
	 * @param doc2 text to show for program 2
	 */
	private void addTagDetails(StyledDocument doc1, StyledDocument doc2) {

		Function func1 = l1.getFunctionAt(currentP1Address);
		Function func2 = (currentP2Address != null) ? l2.getFunctionAt(currentP2Address) : null;

		if (func1 == null || func2 == null) {
			Msg.error(this, "couldn't find functions for addresses: " + currentP1Address + "::" +
				currentP2Address);
		}

		Set<FunctionTag> func1Tags = func1.getTags();
		Set<FunctionTag> func2Tags = func2.getTags();

		// Sort the tags before we print out the details - this will make viewing
		// the differences much easier.
		func1Tags = new TreeSet<>(func1Tags);
		func2Tags = new TreeSet<>(func2Tags);

		if (!ProgramDiff.equivalentTagSets(func1Tags, func2Tags)) {

			addText(doc1, indent2 + "Tags: ");
			addColorText(doc1, getTagInfo(func1Tags));
			addText(doc1, newLine);

			addText(doc2, indent2 + "Tags: ");
			addColorText(doc2, getTagInfo(func2Tags));
			addText(doc2, newLine);

			hasTagDiffs = true;
		}

		hasTagDiffs = false;
	}

	private void addRepeatableCommentDetails() {
		hasRepeatableCommentDiffs =
			addSpecificCommentDetails(CodeUnit.REPEATABLE_COMMENT, "Repeatable-Comment");
	}

	/**
	 * Constructs a comma-delimited string from the names of all function
	 * tags passed-in. If a comment is present in the tag object, it will be shown
	 * in parenthesis.
	 *
	 * @param tags
	 * @return
	 */
	private String getTagInfo(Collection<FunctionTag> tags) {
		if (tags == null || tags.size() == 0) {
			return "";
		}

		StringBuilder strBuilder = new StringBuilder();
		for (FunctionTag tag : tags) {
			strBuilder.append(", ");
			strBuilder.append(tag.getName());
			if (tag.getComment() != null && !tag.getComment().isEmpty()) {
				strBuilder.append("(" + tag.getComment() + ")");
			}
		}

		String retString = strBuilder.toString();

		// Replace any leading ',' character before returning.
		if (retString.startsWith(",")) {
			retString = retString.replaceFirst(",", "");
		}

		return retString;
	}

	private boolean addSpecificCommentDetails(int commentType, String commentName) {
		boolean hasCommentDiff = false;
		try {
			for (Address p1Address = minP1Address; p1Address.compareTo(
				maxP1Address) <= 0; p1Address = p1Address.add(1L)) {
				Address p2Address = SimpleDiffUtility.getCompatibleAddress(p1, p1Address, p2);
				String noComment = "No " + commentName + ".";
				String cmt1 = l1.getComment(commentType, p1Address);
				String cmt2 = (p2Address != null) ? l2.getComment(commentType, p2Address) : null;
				if (!SystemUtilities.isEqual(cmt1, cmt2)) {
					if (!hasCommentDiff) {
						addDiffHeader(commentName);
						hasCommentDiff = true;
					}

					addProgramText(1, p1Address);
					if (cmt1 != null) {
						addColorComment(cmt1);
					}
					else {
						addText(noComment);
					}
					addText(newLine);

					addProgramText(2, p2Address);
					if (cmt2 != null) {
						addColorComment(cmt2);
					}
					else {
						addText(noComment);
					}
					addText(newLine);
				}
			}
		}
		catch (AddressOutOfBoundsException e) {
			//This can occur at the end of a block.
		}
		return hasCommentDiff;
	}

	private void addFunctionDetails() {
		Function func1 = l1.getFunctionAt(currentP1Address);
		Function func2 = (currentP2Address != null) ? l2.getFunctionAt(currentP2Address) : null;

		if ((func1 == null) && (func2 == null)) {
			return;
		}
		if (ProgramDiff.equivalentFunctions(func1, func2)) {
			return;
		}
		addDiffHeader("Function");
		addFunctionInfo(func1, func2);
		hasFunctionDiffs = true;
	}

	private void addFunctionInfo(Function function1, Function function2) {
		StyledDocument doc1 = new DefaultStyledDocument();
		StyledDocument doc2 = new DefaultStyledDocument();
		if (function1 == null || function2 == null) {
			addAllFunctionInfo(doc1, doc2, function1, function2);
		}
		else {
			addSignature(doc1, doc2, function1, function2);
			addNamespace(doc1, doc2, function1, function2);
			addBody(doc1, doc2, function1, function2);
			addThunk(doc1, doc2, function1, function2);
			addInline(doc1, doc2, function1, function2);
			addCallingConvention(doc1, doc2, function1, function2);
			addNoReturn(doc1, doc2, function1, function2);
			addReturn(doc1, doc2, function1, function2);
			addStackPurge(doc1, doc2, function1, function2);
			addStackFrame(doc1, doc2, function1.getStackFrame(), function2.getStackFrame());
			addCustomVariableStorage(doc1, doc2, function1, function2);
			addParameters(doc1, doc2, function1, function2);
			addLocals(doc1, doc2, function1, function2);
			addTagDetails(doc1, doc2);
		}

		addProgramText(1);
		addStyledDocument(doc1);
		addProgramText(2);
		addStyledDocument(doc2);
	}

	@SuppressWarnings("unused")
	private boolean sameDocs(StyledDocument doc1, StyledDocument doc2) {
		int len1 = doc1.getLength();
		int len2 = doc2.getLength();
		if (len1 != len2) {
			return false;
		}
		try {
			String text1 = doc1.getText(0, len1);
			String text2 = doc2.getText(0, len2);
			return text1.equals(text2);
		}
		catch (BadLocationException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			return false;
		}
	}

	private void addStyledDocument(StyledDocument doc1) {
		Element root = doc1.getDefaultRootElement();
		copyLeafs(root);
	}

	private void copyLeafs(Element parent) {
		int elementCount = parent.getElementCount();
		for (int elementIndex = 0; elementIndex < elementCount; elementIndex++) {
			Element child = parent.getElement(elementIndex);
			if (child.isLeaf()) {
				copyLeaf(child);
			}
			else {
				copyLeafs(child);
			}
		}
	}

	private void copyLeaf(Element leaf) {
		AttributeSet attrSet = leaf.getAttributes();
		Document leafDoc = leaf.getDocument();
		int start = leaf.getStartOffset();
		int end = leaf.getEndOffset();
		try {
			String text = leafDoc.getText(start, end - start);
			detailsDoc.insertString(detailsDoc.getLength(), text, attrSet);
		}
		catch (BadLocationException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	private void addAllFunctionInfo(StyledDocument doc1, StyledDocument doc2, Function function1,
			Function function2) {
		addAllFunctionInfo(doc1, function1);
		addAllFunctionInfo(doc2, function2);
	}

	private void addAllFunctionInfo(StyledDocument doc, Function function) {
		if (function == null) {
			addText(doc, indent2 + "No function defined here." + newLine);
			return;
		}
		addSignature(doc, function);
		addNamespace(doc, function);
		addBody(doc, function);
		addThunk(doc, function);
		addInline(doc, function);
		addCallingConvention(doc, function);
		addNoReturn(doc, function);
		addReturn(doc, function);
		addStackPurge(doc, function);
		addStackFrame(doc, function);
		addCustomVariableStorage(doc, function);
		addParameters(doc, function);
		addLocals(doc, function);
	}

	private void addSignature(StyledDocument doc, Function function) {
		addFunctionInfo(doc, "Signature: ", function.getPrototypeString(false, false));
	}

	private void addSignature(StyledDocument doc1, StyledDocument doc2, Function function1,
			Function function2) {
		String sigStr1 = function1.getPrototypeString(false, false);
		String sigStr2 = function2.getPrototypeString(false, false);
		if (!sigStr1.equals(sigStr2)) {
			addFunctionInfo(doc1, "Signature: ", sigStr1);
			addFunctionInfo(doc2, "Signature: ", sigStr2);
		}
	}

	private void addNamespace(StyledDocument doc, Function function) {
		Namespace parentNS = function.getParentNamespace();
		String namespace =
			((parentNS instanceof GlobalNamespace) ? parentNS.getName() : parentNS.getName(true));
		addFunctionInfo(doc, "Namespace: ", namespace);
	}

	private void addNamespace(StyledDocument doc1, StyledDocument doc2, Function function1,
			Function function2) {
		Namespace parentNS1 = function1.getParentNamespace();
		Namespace parentNS2 = function2.getParentNamespace();
		String namespace1 = ((parentNS1 instanceof GlobalNamespace) ? parentNS1.getName()
				: parentNS1.getName(true));
		String namespace2 = ((parentNS2 instanceof GlobalNamespace) ? parentNS2.getName()
				: parentNS2.getName(true));
		if (!namespace1.equals(namespace2)) {
			addFunctionInfo(doc1, "Namespace: ", namespace1);
			addFunctionInfo(doc2, "Namespace: ", namespace2);
		}
	}

	private void addBody(StyledDocument doc, Function function) {
		addFunctionInfo(doc, "Body: ", function.getBody().toString());
	}

	private void addBody(StyledDocument doc1, StyledDocument doc2, Function function1,
			Function function2) {
		AddressSetView body1 = function1.getBody();
		AddressSetView body2 = function2.getBody();
		AddressSet body2AsP1 = DiffUtility.getCompatibleAddressSet(body2, p1);
		if (!body1.equals(body2AsP1)) {
			addFunctionInfo(doc1, "Body: ", body1.toString());
			addFunctionInfo(doc2, "Body: ", body2.toString());
		}
	}

	private void addStackPurge(StyledDocument doc, Function function) {
		addFunctionInfo(doc, "Stack Purge Size: ", Integer.toString(function.getStackPurgeSize()));
	}

	private void addStackPurge(StyledDocument doc1, StyledDocument doc2, Function function1,
			Function function2) {
		int purge1 = function1.getStackPurgeSize();
		int purge2 = function2.getStackPurgeSize();
		if (purge1 != purge2) {
			addFunctionInfo(doc1, "Stack Purge Size: ", Integer.toString(purge1));
			addFunctionInfo(doc2, "Stack Purge Size: ", Integer.toString(purge2));
		}
	}

	private void addCallingConvention(StyledDocument doc, Function function) {
		addFunctionInfo(doc, "Calling Convention: ", function.getCallingConventionName());
	}

	private void addCallingConvention(StyledDocument doc1, StyledDocument doc2, Function function1,
			Function function2) {
		String name1 = function1.getCallingConventionName();
		String name2 = function2.getCallingConventionName();
		if (!name1.equals(name2)) {
			addFunctionInfo(doc1, "Calling Convention: ", name1);
			addFunctionInfo(doc2, "Calling Convention: ", name2);
		}
	}

	private void addThunk(StyledDocument doc, Function function) {
		Function thunkedFunction = function.getThunkedFunction(false);
		addFunctionInfo(doc, "Thunk? : ",
			((thunkedFunction != null) ? ("yes   " + getThunkedFunctionString(thunkedFunction))
					: "no"));
		if (thunkedFunction != null) {
			addFunctionInfo(doc, "  Name : ", function.getName());
			addFunctionInfo(doc, "  Source : ",
				function.getSymbol().getSource().getDisplayString());
			addFunctionInfo(doc, "  External : ",
				(thunkedFunction.isExternal()
						? ("yes   " + thunkedFunction.getExternalLocation().toString())
						: "no"));
		}
	}

	private void addThunk(StyledDocument doc1, StyledDocument doc2, Function function1,
			Function function2) {
		if (!ProgramDiff.isEquivalentThunk(function1, function2)) {
			addThunk(doc1, function1);
			addThunk(doc2, function2);
		}
	}

	private String getThunkedFunctionString(Function thunkedFunction) {
		return "Thunked Function: " + thunkedFunction.getName() + " @ " +
			thunkedFunction.getEntryPoint().toString(true);
	}

	private void addInline(StyledDocument doc, Function function) {
		addFunctionInfo(doc, "Inline? : ", (function.isInline() ? "yes" : "no"));
	}

	private void addInline(StyledDocument doc1, StyledDocument doc2, Function function1,
			Function function2) {
		boolean isInline1 = function1.isInline();
		boolean isInline2 = function2.isInline();
		if (isInline1 != isInline2) {
			addFunctionInfo(doc1, "Inline? : ", (isInline1 ? "yes" : "no"));
			addFunctionInfo(doc2, "Inline? : ", (isInline2 ? "yes" : "no"));
		}
	}

	private void addNoReturn(StyledDocument doc, Function function) {
		addFunctionInfo(doc, "No Return? : ", Boolean.toString(function.hasNoReturn()));
	}

	private void addNoReturn(StyledDocument doc1, StyledDocument doc2, Function function1,
			Function function2) {
		boolean hasNoReturn1 = function1.hasNoReturn();
		boolean hasNoReturn2 = function2.hasNoReturn();
		if (hasNoReturn1 != hasNoReturn2) {
			addFunctionInfo(doc1, "No Return? : ", Boolean.toString(hasNoReturn1));
			addFunctionInfo(doc2, "No Return? : ", Boolean.toString(hasNoReturn2));
		}
	}

	private void addCustomVariableStorage(StyledDocument doc, Function function) {
		addFunctionInfo(doc, "Custom Variable Storage? : ",
			(function.hasCustomVariableStorage() ? "yes" : "no"));
	}

	private void addCustomVariableStorage(StyledDocument doc1, StyledDocument doc2,
			Function function1, Function function2) {
		boolean hasCustomStorage1 = function1.hasCustomVariableStorage();
		boolean hasCustomStorage2 = function2.hasCustomVariableStorage();
		if (hasCustomStorage1 != hasCustomStorage2) {
			addFunctionInfo(doc1, "Custom Variable Storage? : ",
				(hasCustomStorage1 ? "yes" : "no"));
			addFunctionInfo(doc2, "Custom Variable Storage? : ",
				(hasCustomStorage2 ? "yes" : "no"));
		}
	}

	private void addStackFrame(StyledDocument doc, Function function) {
		StackFrame frame = function.getStackFrame();
		addFunctionInfo(doc, "Stack Frame: ", "");
		addFrameSize(doc, frame);
		addStackGrowth(doc, frame);
		addReturnOffset(doc, frame);
		addParameterOffset(doc, frame);
		addParameterSize(doc, frame);
	}

	private void addStackFrame(StyledDocument doc1, StyledDocument doc2, StackFrame frame1,
			StackFrame frame2) {
		if (!sameStackFrame(frame1, frame2)) {
			addFunctionInfo(doc1, "Stack Frame: ", "");
			addFunctionInfo(doc2, "Stack Frame: ", "");

			addFrameSize(doc1, doc2, frame1, frame2);
			addStackGrowth(doc1, doc2, frame1, frame2);
			addReturnOffset(doc1, doc2, frame1, frame2);
			addParameterOffset(doc1, doc2, frame1, frame2);
			addParameterSize(doc1, doc2, frame1, frame2);

		}
	}

	private boolean sameStackFrame(StackFrame frame1, StackFrame frame2) {
		return frame1.equals(frame2);
	}

	private void addFrameSize(StyledDocument doc, StackFrame frame) {
		addFrameInfo(doc, "Frame Size: ", Integer.toString(frame.getFrameSize()));
	}

	private void addFrameSize(StyledDocument doc1, StyledDocument doc2, StackFrame frame1,
			StackFrame frame2) {
		int size1 = frame1.getFrameSize();
		int size2 = frame2.getFrameSize();
		if (size1 != size2) {
			addFrameInfo(doc1, "Frame Size: ", Integer.toString(size1));
			addFrameInfo(doc2, "Frame Size: ", Integer.toString(size2));
		}
	}

	private void addStackGrowth(StyledDocument doc, StackFrame frame) {
		addFrameInfo(doc, "Grows negative? ", Boolean.toString(frame.growsNegative()));
	}

	private void addStackGrowth(StyledDocument doc1, StyledDocument doc2, StackFrame frame1,
			StackFrame frame2) {
		boolean growth1 = frame1.growsNegative();
		boolean growth2 = frame2.growsNegative();
		if (growth1 != growth2) {
			addFrameInfo(doc1, "Grows negative? ", Boolean.toString(growth1));
			addFrameInfo(doc2, "Grows negative? ", Boolean.toString(growth2));
		}
	}

	private void addReturnOffset(StyledDocument doc, StackFrame frame) {
		addFrameInfo(doc, "Return Address Offset: ",
			DiffUtility.toSignedHexString(frame.getReturnAddressOffset()));
	}

	private void addReturnOffset(StyledDocument doc1, StyledDocument doc2, StackFrame frame1,
			StackFrame frame2) {
		int offset1 = frame1.getReturnAddressOffset();
		int offset2 = frame2.getReturnAddressOffset();
		if (offset1 != offset2) {
			addFrameInfo(doc1, "Return Address Offset: ", DiffUtility.toSignedHexString(offset1));
			addFrameInfo(doc2, "Return Address Offset: ", DiffUtility.toSignedHexString(offset2));
		}
	}

	private void addParameterOffset(StyledDocument doc, StackFrame frame) {
		addFrameInfo(doc, "Parameter Offset: ",
			DiffUtility.toSignedHexString(frame.getParameterOffset()));
	}

	private void addParameterOffset(StyledDocument doc1, StyledDocument doc2, StackFrame frame1,
			StackFrame frame2) {
		int offset1 = frame1.getParameterOffset();
		int offset2 = frame2.getParameterOffset();
		if (offset1 != offset2) {
			addFrameInfo(doc1, "Parameter Offset: ", DiffUtility.toSignedHexString(offset1));
			addFrameInfo(doc2, "Parameter Offset: ", DiffUtility.toSignedHexString(offset2));
		}
	}

	private void addParameterSize(StyledDocument doc, StackFrame frame) {
		addFrameInfo(doc, "Size of Parameter Portion: ", "" + frame.getParameterSize());
	}

	private void addParameterSize(StyledDocument doc1, StyledDocument doc2, StackFrame frame1,
			StackFrame frame2) {
		int size1 = frame1.getParameterSize();
		int size2 = frame2.getParameterSize();
		if (size1 != size2) {
			addFrameInfo(doc1, "Size of Parameter Portion: ", "" + size1);
			addFrameInfo(doc2, "Size of Parameter Portion: ", "" + size2);
		}
	}

	private class VariableLayout {
		int dtLen;
		int offsetLen;
		int firstUseLen;
		int nameLen;
		int sizeLen;
		int sourceLen;
	}

	private VariableLayout getVariableLayout(Variable[] vars) {
		VariableLayout vl = new VariableLayout();
		vl.dtLen = "DataType".length();
		vl.offsetLen = "Storage".length();
		vl.firstUseLen = "FirstUse".length();
		vl.nameLen = "Name".length();
		vl.sizeLen = "Size".length();
		vl.sourceLen = "Source".length();
		for (Variable var : vars) {
			vl.dtLen = Math.max(vl.dtLen, var.getDataType().getPathName().length());
			vl.offsetLen = Math.max(vl.offsetLen, var.getVariableStorage().toString().length());
			vl.firstUseLen = Math.max(vl.firstUseLen,
				DiffUtility.toSignedHexString(var.getFirstUseOffset()).length());
			vl.nameLen = Math.max(vl.nameLen, var.getName().length());
			vl.sizeLen = Math.max(vl.sizeLen, Integer.toString(var.getLength()).length());
			vl.sourceLen = Math.max(vl.sourceLen, var.getSource().toString().length());
		}
		return vl;
	}

	private void addParameters(StyledDocument doc, Function function) {
		Variable[] vars = function.getParameters();
		addFrameInfo(doc, "Parameters: ", "");
		VariableLayout varLayout = getVariableLayout(vars);
		printParameters(doc, vars, varLayout, vars.length);
	}

	private void addParameters(StyledDocument doc1, StyledDocument doc2, Function function1,
			Function function2) {

		boolean checkParamStorage =
			function1.hasCustomVariableStorage() || function2.hasCustomVariableStorage();

		Variable[] vars1 = function1.getParameters();
		Variable[] vars2 = function2.getParameters();
		if (ProgramDiff.equivalentVariableArrays(vars1, vars2, checkParamStorage)) {
			return;
		}
		addFrameInfo(doc1, "Parameters: ", "");
		addFrameInfo(doc2, "Parameters: ", "");

		MultiComparableArrayIterator<Variable> iter =
			new MultiComparableArrayIterator<>(new Variable[][] { vars1, vars2 });

		ArrayList<Variable> varList1 = new ArrayList<>(); // variables to print to the details for program 1.
		ArrayList<Variable> varList2 = new ArrayList<>(); // variables to print to the details for program 2.
		while (iter.hasNext()) {
			Variable[] vars = iter.next();
			Variable var1 = vars[0];
			Variable var2 = vars[1];
			if (var1 != null && var2 != null &&
				ProgramDiff.equivalentVariables(var1, var2, checkParamStorage)) {
				continue;
			}
			if (var1 != null) {
				varList1.add(var1);
			}
			if (var2 != null) {
				varList2.add(var2);
			}
		}
		ArrayList<Variable> allVarsList = new ArrayList<>(varList1);
		allVarsList.addAll(varList2);

		Variable[] printVars1 = varList1.toArray(new Variable[varList1.size()]);
		Variable[] printVars2 = varList2.toArray(new Variable[varList2.size()]);
		Variable[] combinedVars = allVarsList.toArray(new Variable[allVarsList.size()]);

		VariableLayout varLayout = getVariableLayout(combinedVars);
		printParameters(doc1, printVars1, varLayout, vars1.length);
		printParameters(doc2, printVars2, varLayout, vars2.length);
	}

	private void printParameters(StyledDocument doc, Variable[] printVars, VariableLayout varLayout,
			int actualVarCount) {
		if (printVars.length == 0) {
			addText(doc, indent4 + "No " + ((actualVarCount == 0) ? "" : "unmatched ") +
				"parameters." + newLine);
		}
		else { // Add the table header
			addVariable(doc, null, varLayout, indent4);
			for (Variable printVar : printVars) {
				addVariable(doc, printVar, varLayout, indent4);
			}
		}
	}

	private void addReturn(StyledDocument doc1, StyledDocument doc2, Function function1,
			Function function2) {
		Parameter returnVar1 = function1.getReturn();
		Parameter returnVar2 = function2.getReturn();
		boolean checkParamStorage =
			function1.hasCustomVariableStorage() || function2.hasCustomVariableStorage();
		if (ProgramDiff.equivalentVariables(returnVar1, returnVar2, checkParamStorage)) {
			return;
		}

		VariableLayout varLayout1 = getVariableLayout(new Variable[] { returnVar1 });
		addFunctionInfo(doc1, "Return Value : ", "");
		addVariable(doc1, null, varLayout1, indent3); // Add the column header
		addVariable(doc1, returnVar1, varLayout1, indent3);

		VariableLayout varLayout2 = getVariableLayout(new Variable[] { returnVar2 });
		addFunctionInfo(doc2, "Return Value : ", "");
		addVariable(doc2, null, varLayout2, indent3); // Add the column header
		addVariable(doc2, returnVar2, varLayout2, indent3);
	}

	private void addReturn(StyledDocument doc, Function function) {
		Variable returnVar = function.getReturn();
		VariableLayout varLayout = getVariableLayout(new Variable[] { returnVar });
		addFunctionInfo(doc, "Return Value : ", "");
		addVariable(doc, null, varLayout, indent3); // Add the column header
		addVariable(doc, returnVar, varLayout, indent3);
	}

	private void addLocals(StyledDocument doc, Function function) {
		Variable[] vars = function.getLocalVariables();
		addFrameInfo(doc, "Local Variables: ", "");
		VariableLayout varLayout = getVariableLayout(vars);
		printLocals(doc, vars, varLayout, vars.length);
	}

	private void addLocals(StyledDocument doc1, StyledDocument doc2, Function function1,
			Function function2) {
		Variable[] vars1 = function1.getLocalVariables();
		Variable[] vars2 = function2.getLocalVariables();
		if (ProgramDiff.equivalentVariableArrays(vars1, vars2, false)) {
			return;
		}
		addFrameInfo(doc1, "Local Variables: ", "");
		addFrameInfo(doc2, "Local Variables: ", "");

		MultiComparableArrayIterator<Variable> iter =
			new MultiComparableArrayIterator<>(new Variable[][] { vars1, vars2 });

		ArrayList<Variable> varList1 = new ArrayList<>(); // variables to print to the details for program 1.
		ArrayList<Variable> varList2 = new ArrayList<>(); // variables to print to the details for program 2.
		while (iter.hasNext()) {
			Variable[] vars = iter.next();
			Variable var1 = vars[0];
			Variable var2 = vars[1];
			if (var1 != null && var2 != null && ProgramDiff.equivalentVariables(var1, var2, true)) {
				continue;
			}
			if (var1 != null) {
				varList1.add(var1);
			}
			if (var2 != null) {
				varList2.add(var2);
			}
		}
		ArrayList<Variable> allVarsList = new ArrayList<>(varList1);
		allVarsList.addAll(varList2);

		Variable[] printVars1 = varList1.toArray(new Variable[varList1.size()]);
		Variable[] printVars2 = varList2.toArray(new Variable[varList2.size()]);
		Variable[] combinedVars = allVarsList.toArray(new Variable[allVarsList.size()]);

		VariableLayout varLayout = getVariableLayout(combinedVars);
		printLocals(doc1, printVars1, varLayout, vars1.length);
		printLocals(doc2, printVars2, varLayout, vars2.length);
	}

	private void printLocals(StyledDocument doc, Variable[] printVars, VariableLayout varLayout,
			int actualVarCount) {
		if (printVars.length == 0) {
			addText(doc, indent4 + "No " + ((actualVarCount == 0) ? "" : "unmatched ") +
				"local variables." + newLine);
		}
		else {
			addVariable(doc, null, varLayout, indent4); // Add the table header
			for (Variable printVar : printVars) {
				addVariable(doc, printVar, varLayout, indent4);
			}
		}
	}

	private void addVariable(final StyledDocument doc, final Variable var,
			final VariableLayout layout, String indent) {
		int offsetLen = layout.offsetLen;
		int firstUseLen = layout.firstUseLen;
		int dtLen = layout.dtLen;
		int nameLen = layout.nameLen;
		int sizeLen = layout.sizeLen;
		int sourceLen = layout.sourceLen;
		String separatorSpaces = getSpaces(2);
		addText(doc, indent);
		if (var == null) {
			underline(doc, "DataType");
			addText(doc, getSpaces(dtLen - "DataType".length()));
			addText(doc, separatorSpaces);
			underline(doc, "Storage");
			addText(doc, getSpaces(offsetLen - "Storage".length()));
			addText(doc, separatorSpaces);
			underline(doc, "FirstUse");
			addText(doc, getSpaces(firstUseLen - "FirstUse".length()));
			addText(doc, separatorSpaces);
			underline(doc, "Name");
			addText(doc, getSpaces(nameLen - "Name".length()));
			addText(doc, separatorSpaces);
			underline(doc, "Size");
			addText(doc, getSpaces(sizeLen - "Size".length()));
			addText(doc, separatorSpaces);
			underline(doc, "Source");
			addText(doc, getSpaces(sourceLen - "Source".length()));
			addText(doc, separatorSpaces);
			underline(doc, "Comment");
		}
		else {
			String dt = var.getDataType().getPathName();
			String offset = var.getVariableStorage().toString();
			String firstUse = DiffUtility.toSignedHexString(var.getFirstUseOffset());
			String name = var.getName();
			String size = "" + var.getLength();
			String source = var.getSource().toString();
			String comment = var.getComment();

			addColorText(doc, dt);
			addText(doc, getSpaces(dtLen - dt.length()));
			addText(doc, separatorSpaces);
			addText(doc, getSpaces(offsetLen - offset.length())); // Right justify the offset
			addColorText(doc, offset);
			addText(doc, separatorSpaces);
			addText(doc, getSpaces(firstUseLen - firstUse.length())); // Right justify the firstUse
			addColorText(doc, firstUse);
			addText(doc, separatorSpaces);
			addColorText(doc, name);
			addText(doc, getSpaces(nameLen - name.length()));
			addText(doc, separatorSpaces);
			addText(doc, getSpaces(sizeLen - size.length())); // Right justify the size
			addColorText(doc, size);
			addText(doc, separatorSpaces);
			addColorText(doc, source);
			addText(doc, getSpaces(sourceLen - source.length()));
			addText(doc, separatorSpaces);
			addColorText(doc, comment);
		}
		addText(doc, newLine);
	}

	private void addFunctionInfo(StyledDocument doc, String name, String value) {
		addText(doc, indent2 + name);
		addColorText(doc, value);
		addText(doc, newLine);
	}

	private void addFrameInfo(StyledDocument doc, String name, String value) {
		addText(doc, indent3 + name);
		addColorText(doc, value);
		addText(doc, newLine);
	}

	private void addUserDefinedDetails() {
		String upi1 = getUserPropertyInfo(cu1At);
		String upi2 = getUserPropertyInfo(cu2At);
		if (!SystemUtilities.isEqual(upi1, upi2)) {
			addDiffHeader("User Defined Property");
			addProgramText(1, currentP1Address);
			addText(upi1);
			addProgramText(2, currentP2Address);
			addText(upi2);
			hasUserDefinedDiffs = true;
		}
	}

	private String getUserPropertyInfo(CodeUnit cu) {
		StringBuffer buf = new StringBuffer();
		if (cu != null) {
			Iterator<String> propNames = cu.propertyNames();
			ArrayList<String> names = new ArrayList<>();
			while (propNames.hasNext()) {
				names.add(propNames.next());
			}
			String[] names1 = names.toArray(new String[names.size()]);
			Arrays.sort(names1);

			String stringProp = null;
			int intProp = -1;
			Object objProp = null;
			boolean voidProp = false;
			for (String propertyName : names1) {
				if (cu.hasProperty(propertyName)) {
					// Handle case where the class for a Saveable property is missing (unsupported).
					if (cu.getProgram().getListing().getPropertyMap(
						propertyName) instanceof UnsupportedMapDB) {
						buf.append(
							indent2 + propertyName + " is an unsupported property." + newLine);
						continue;
					}
					// Int property
					try {
						intProp = cu.getIntProperty(propertyName);
						buf.append(indent2 + propertyName + " = " + intProp + newLine);
						continue;
					}
					catch (NoValueException e) {
						// Do nothing.
					}
					catch (TypeMismatchException e) {
						// "Int" wasn't the correct property type, so ignore here and
						// handle any unrecognized property below after checking all types.
					}
					// String property
					try {
						stringProp = cu.getStringProperty(propertyName);
					}
					catch (TypeMismatchException e) {
						// "String" wasn't the correct property type, so ignore here and
						// handle any unrecognized property below after checking all types.
					}
					if (stringProp != null) {
						buf.append(indent2 + propertyName + " = " + stringProp + newLine);
						continue;
					}
					// Object property
					try {
						objProp = cu.getObjectProperty(propertyName);
					}
					catch (TypeMismatchException e) {
						// "Object" wasn't the correct property type, so ignore here and
						// handle any unrecognized property below after checking all types.
					}
					if (objProp != null) {
						buf.append(indent2 + propertyName + ": " + objProp.toString() + newLine);
						continue;
					}
					// Void property
					try {
						voidProp = cu.getVoidProperty(propertyName);
					}
					catch (TypeMismatchException e) {
						// "Void" wasn't the correct property type, so ignore here and
						// handle any unrecognized property below after checking all types.
					}
					if (voidProp) {
						buf.append(indent2 + propertyName + " is a VoidProperty." + newLine);
						continue;
					}

					// Unrecognized property
					buf.append(
						indent2 + "Unknown property type for " + propertyName + "." + newLine);
				}
			}
		}
		if (buf.length() == 0) {
			return indent2 + "No user properties." + newLine;
		}
		return buf.toString();
	}

	private void addBookmarkDetails() {
		BookmarkManager bmm1 = p1.getBookmarkManager();
		BookmarkManager bmm2 = p2.getBookmarkManager();
		try {
			for (Address p1Address = minP1Address; p1Address.compareTo(
				maxP1Address) <= 0; p1Address = p1Address.add(1)) {
				Address p2Address = SimpleDiffUtility.getCompatibleAddress(p1, p1Address, p2);
				Bookmark[] marks1 = bmm1.getBookmarks(p1Address);
				Arrays.sort(marks1, BOOKMARK_COMPARATOR);
				Bookmark[] marks2 =
					(p2Address != null) ? bmm2.getBookmarks(p2Address) : new Bookmark[0];
				Arrays.sort(marks2, BOOKMARK_COMPARATOR);
				if (!sameBookmarks(marks1, marks2)) {
					if (!hasBookmarkDiffs) {
						addDiffHeader("Bookmark");
						hasBookmarkDiffs = true;
					}
					addProgramText(1, p1Address);
					addBookmarks(marks1);
					addProgramText(2, p2Address);
					addBookmarks(marks2);
				}
			}
		}
		catch (AddressOutOfBoundsException e) {
			//This can occur at the end of a block.
		}
	}

	/**
	 * Determines whether or not two arrays of bookmarks are equal.
	 * @param marks1 first array of bookmarks
	 * @param marks2 second array of bookmarks
	 * @return true if the two bookmark arrays are equal.
	 */
	private boolean sameBookmarks(Bookmark[] marks1, Bookmark[] marks2) {
		if (marks1.length != marks2.length) {
			return false;
		}
		for (int i = 0; i < marks1.length; i++) {
			Address marks1Addr = marks1[i].getAddress();
			Address marks2Addr = marks2[i].getAddress();
			Address marks2AddressAsP1 = SimpleDiffUtility.getCompatibleAddress(p2, marks2Addr, p1);
			if (!marks1Addr.equals(marks2AddressAsP1) ||
				!marks1[i].getTypeString().equals(marks2[i].getTypeString()) ||
				!marks1[i].getCategory().equals(marks2[i].getCategory()) ||
				!marks1[i].getComment().equals(marks2[i].getComment())) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Adds multiple bookmarks to the details.
	 * @param marks the bookmarks to add.
	 */
	private void addBookmarks(Bookmark[] marks) {
		if (marks.length > 0) {
			int typeLen = "Type".length();
			int catLen = "Category".length();
			for (Bookmark mark : marks) {
				typeLen = Math.max(typeLen, mark.getType().getTypeString().length());
				catLen = Math.max(catLen, mark.getCategory().length());
			}
			addDisplayBookmark(null, typeLen, catLen);
			for (Bookmark mark : marks) {
				addDisplayBookmark(mark, typeLen, catLen);
			}
		}
		else {
			addText(indent2 + "No bookmarks." + newLine);
		}
	}

	private void addDisplayBookmark(Bookmark mark, int typeLength, int catLength) {
		String separatorSpaces = getSpaces(2);
		addText(indent2);
		if (mark == null) {
			underline("Type");
			addText(getSpaces(typeLength - "Type".length()));
			addText(separatorSpaces);
			underline("Category");
			addText(getSpaces(catLength - "Category".length()));
			addText(separatorSpaces);
			underline("Comment");
		}
		else {
			String type = mark.getType().getTypeString();
			String category = mark.getCategory();
			String comment = mark.getComment();
			addColorText(type);
			addText(getSpaces(typeLength - type.length()));
			addText(separatorSpaces);
			addColorText(category);
			addText(getSpaces(catLength - category.length()));
			addText(separatorSpaces);
			addColorText(comment);
		}
		addText(newLine);
	}

	private boolean isSameInstruction(Instruction i1, Instruction i2) {
		boolean samePrototypes = i1.getPrototype().equals(i2.getPrototype());
		boolean sameInstructionLength = i1.getLength() == i2.getLength();
		boolean sameFallthrough = ProgramDiff.isSameFallthrough(p1, i1, p2, i2);
		boolean sameFlowOverride = i1.getFlowOverride() == i2.getFlowOverride();
		return samePrototypes && sameInstructionLength && sameFallthrough && sameFlowOverride;
	}

	/** Returns whether the two defined data objects are the same.
	 * @param d1 the first defined data object
	 * @param d2 the second defined data object
	 * @return true if the defeined data objects are the same.
	 */
	private boolean isSameData(Data d1, Data d2) {
		if (d1.getLength() != d2.getLength()) {
			return false;
		}
		ghidra.program.model.data.DataType dt1 = d1.getDataType();
		ghidra.program.model.data.DataType dt2 = d2.getDataType();
		if (!dt1.isEquivalent(dt2)) {
			return false;
		}
		// Detect that data type name or path differs?
		if (!dt1.getPathName().equals(dt2.getPathName())) {
			return false;
		}

		return true;
	}

	/**
	 * Creates a formatted difference string for an individual line difference
	 * between program1 and program2.
	 */
	@SuppressWarnings("unused")
	private void addDiffString(String name, int nameOffset, String p1Diff, int p1Offset,
			String p2Diff, int p2Offset, boolean underline) {
		int nameLen = name.length();
		int p1Len = p1Diff.length();
		int nameEnd = nameOffset + nameLen;
		int p1End = p1Offset + p1Len;
		int spacesBeforeName = nameOffset;
		int spacesBeforeP1 = p1Offset - nameEnd;
		int spacesBeforeP2 = p2Offset - p1End;

		addText(getSpaces(spacesBeforeName));
		if (underline) {
			underline(name);
		}
		else {
			addColorText(name);
		}
		addText(getSpaces(spacesBeforeP1));
		if (underline) {
			underline(p1Diff);
		}
		else {
			addColorText(p1Diff);
		}
		addText(getSpaces(spacesBeforeP2));
		if (underline) {
			underline(p2Diff);
		}
		else {
			addColorText(p2Diff);
		}
		addText(newLine);
	}

	private String getSpaces(int numSpaces) {
		if (numSpaces <= 0) {
			return "";
		}
		StringBuffer buf = new StringBuffer(numSpaces);
		for (int i = 0; i < numSpaces; i++) {
			buf.append(" ");
		}
		return buf.toString();
	}

	private void addDiffHeader(String text) {
		addText(newLine);
		underline(text + " Diffs");
		addText(" : " + newLine);
	}

	private void addProgramText(int programNumber) {
		addProgramText(detailsDoc, programNumber);
	}

	private void addProgramText(StyledDocument doc, int programNumber) {
		Program p = (programNumber == 2) ? p2 : p1;
		addText(doc, newLine + indent1);
		addText(doc, "Program" + programNumber + " ");
		addColorProgram(doc, p.getDomainFile().toString());
		addText(doc, " :" + newLine);
	}

	private void addProgramText(int programNumber, Address addr) {
		addProgramText(detailsDoc, programNumber, addr);
	}

	private void addProgramText(StyledDocument doc, int programNumber, Address addr) {
		Program p = (programNumber == 2) ? p2 : p1;
		addText(doc, newLine + indent1);
		addText(doc, "Program" + programNumber + " ");
		addColorProgram(doc, p.getDomainFile().toString());
		addText(doc, " at ");
		addColorAddress(doc, addr);
		addText(doc, " :" + newLine);
	}

	private void underline(boolean show) {
		if (show) {
			textAttrSet.addAttribute(StyleConstants.Underline, Boolean.TRUE);
		}
		else {
			textAttrSet.removeAttribute(StyleConstants.Underline);
		}
	}

	private void bold(boolean show) {
		if (show) {
			textAttrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		}
		else {
			textAttrSet.removeAttribute(StyleConstants.Bold);
		}
	}

	private void color(Color color) {
		if (color != null) {
			textAttrSet.addAttribute(StyleConstants.Foreground, color);
		}
		else {
			textAttrSet.removeAttribute(StyleConstants.Foreground);
		}

	}

	private void underline(String text) {
		underline(detailsDoc, text);
	}

	private void underline(StyledDocument doc, String text) {
		underline(true);
		try {
			doc.insertString(doc.getLength(), text, textAttrSet);
		}
		catch (BadLocationException e) {
			Msg.error(this, "Error underlining text in the Diff details.", e);
		}
		underline(false);
	}

	private void addColorComment(String text) {
		addColorComment(detailsDoc, text);
	}

	private void addColorComment(StyledDocument doc, String text) {
		color(COMMENT_COLOR);
		try {
			doc.insertString(doc.getLength(), text, textAttrSet);
		}
		catch (BadLocationException e) {
			Msg.error(this, "Error coloring text in Diff details.", e);
		}
		color(null);
	}

	private void addColorAddress(Address addr) {
		addColorAddress(detailsDoc, addr);
	}

	private void addColorAddress(StyledDocument doc, Address addr) {
		String text = (addr != null) ? addr.toString() : "no matching address";
		color(ADDRESS_COLOR);
		try {
			doc.insertString(doc.getLength(), text, textAttrSet);
		}
		catch (BadLocationException e) {
			Msg.error(this, "Error coloring address text in Diff details.", e);
		}
		color(null);
	}

	private void addColorText(String text) {
		addColorText(detailsDoc, text);
	}

	private void addColorText(StyledDocument doc, String text) {
		color(EMPHASIZE_COLOR);
		try {
			doc.insertString(doc.getLength(), text, textAttrSet);
		}
		catch (BadLocationException e) {
			Msg.error(this, "Error coloring text in Diff details.", e);
		}
		color(null);
	}

	private void addColorProgram(StyledDocument doc, String text) {
		color(PURPLE);
		try {
			doc.insertString(doc.getLength(), text, textAttrSet);
		}
		catch (BadLocationException e) {
			Msg.error(this, "Error coloring text in Diff details.", e);
		}
		color(null);
	}

	private void addText(String text) {
		addText(detailsDoc, text);
	}

	private void addText(StyledDocument doc, String text) {
		try {
			doc.insertString(doc.getLength(), text, textAttrSet);
		}
		catch (BadLocationException e) {
			Msg.error(this, "Error adding text to Diff details.", e);
		}
	}

	private void addDangerColorText(String text) {
		addColorText(RED, detailsDoc, text);
	}

	private void addColorText(Color color, StyledDocument doc, String text) {
		color(color);
		try {
			doc.insertString(doc.getLength(), text, textAttrSet);
		}
		catch (BadLocationException e) {
			Msg.error(this, "Error adding color text to Diff details.", e);
		}
		color(null);
	}
}
