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
package ghidra.app.util;

import java.util.*;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.fieldpanel.support.RowColLocation;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.StringUtilities;

/**
 * Utility class with methods to get comment information that can be displayed in the
 * end of line comment field. A DisplayableEol is associated with a code unit.
 * The DisplayableEol gets information for the EOL comment field, which can show the
 * End of Line comment for the code unit, the Repeatable comment for the code unit,
 * any repeatable comments for the code units that this code unit has references to, and
 * possibly a comment indicating the data at a code unit that is referenced by this code unit.
 */
public class DisplayableEol {

	private static final String POINTER_ARROW = "-> ";

	public static final int MY_EOLS = 0;
	public static final int MY_REPEATABLES = 1;
	public static final int REF_REPEATABLES = 2;
	public static final int MY_AUTOMATIC = 3;
	private CodeUnit codeUnit;
	private Object[][] displayCommentArrays = { null, null, null, null };
	private boolean alwaysShowRepeatable = false;
	private boolean alwaysShowRefRepeats = false;
	private boolean alwaysShowAutomatic = false;
	private boolean showAutomaticFunctions;
	private boolean operandsFollowPointerRefs = false;
	private int maxDisplayLines;
	private int totalCommentsFound;

	private boolean useAbbreviatedAutomatic;

	public DisplayableEol(CodeUnit cu, boolean alwaysShowRepeatable, boolean alwaysShowRefRepeats,
			boolean alwaysShowAutomatic, boolean operandsFollowPointerRefs, int maxDisplayLines,
			boolean useAbbreviatedAutomatic, boolean showAutomaticFunctions) {
		this.codeUnit = cu;
		this.alwaysShowRepeatable = alwaysShowRepeatable;
		this.alwaysShowRefRepeats = alwaysShowRefRepeats;
		this.alwaysShowAutomatic = alwaysShowAutomatic;
		this.operandsFollowPointerRefs = operandsFollowPointerRefs;
		this.maxDisplayLines = maxDisplayLines;
		this.useAbbreviatedAutomatic = useAbbreviatedAutomatic;
		this.showAutomaticFunctions = showAutomaticFunctions;

		initComments();
	}

	private void initComments() {
		displayCommentArrays[MY_EOLS] = codeUnit.getCommentAsArray(CodeUnit.EOL_COMMENT);
		totalCommentsFound += displayCommentArrays[MY_EOLS].length;

		displayCommentArrays[MY_REPEATABLES] =
			codeUnit.getCommentAsArray(CodeUnit.REPEATABLE_COMMENT);
		totalCommentsFound += displayCommentArrays[MY_REPEATABLES].length;

		displayCommentArrays[REF_REPEATABLES] = new RefRepeatComment[0];
		displayCommentArrays[MY_AUTOMATIC] = new String[0];
		if (totalCommentsFound > maxDisplayLines) {
			// no more room to display the comments below; don't process them
			return;
		}

		// cap the number of references we get (we don't want to process 500000....)
		Reference[] refs = getReferencesFrom(codeUnit, 100);
		Arrays.sort(refs);

		Program program = codeUnit.getProgram();
		displayCommentArrays[REF_REPEATABLES] =
			getRepeatableComments(program.getListing(), refs, true);
		totalCommentsFound += displayCommentArrays[REF_REPEATABLES].length;

		displayCommentArrays[MY_AUTOMATIC] = getReferencePreviews(program, refs);
		totalCommentsFound += displayCommentArrays[MY_AUTOMATIC].length;
	}

	private Reference[] getReferencesFrom(CodeUnit cu, int maxReferences) {
		ArrayList<Reference> list = new ArrayList<>();

		Program program = cu.getProgram();
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressSet set = new AddressSet(cu.getMinAddress(), cu.getMaxAddress());
		AddressIterator iter = referenceManager.getReferenceSourceIterator(set, true);
		while (iter.hasNext() && list.size() < maxReferences) {
			Address fromAddress = iter.next();
			Reference[] refs = referenceManager.getReferencesFrom(fromAddress);
			for (Reference element : refs) {
				list.add(element);
			}
		}
		return list.toArray(new Reference[list.size()]);
	}

	/**
	 * Return whether the associated code unit has an end of line comment
	 * @return whether the associated code unit has an end of line comment
	 */
	public boolean hasEOL() {
		return (displayCommentArrays[MY_EOLS] != null) &&
			(((String[]) displayCommentArrays[MY_EOLS]).length > 0);
	}

	/**
	 * Return whether the associated code unit has a repeatable comment
	 * @return whether the associated code unit has a repeatable comment
	 */
	public boolean hasRepeatable() {
		return (displayCommentArrays[MY_REPEATABLES] != null) &&
			(((String[]) displayCommentArrays[MY_REPEATABLES]).length > 0);
	}

	/**
	 * Return whether any memory reference from this code unit has a repeatable
	 * comment at the reference's to address
	 * @return whether any memory reference from this code unit has a repeatable
	 * comment at the reference's to address
	 */
	public boolean hasReferencedRepeatable() {
		return (displayCommentArrays[REF_REPEATABLES] != null) &&
			(displayCommentArrays[REF_REPEATABLES].length > 0);
	}

	/**
	 * Return whether this code unit has an automatic comment.  For example, a memory reference
	 * from this code unit has a function defined at the reference's to address, or if the to
	 * address is a pointer.
	 * @return whether this code unit has an automatic comment
	 */
	public boolean hasAutomatic() {
		return (displayCommentArrays[MY_AUTOMATIC] != null) &&
			(displayCommentArrays[MY_AUTOMATIC].length > 0);
	}

	private String[] getReferencePreviews(Program program, Reference[] refs) {

		if (refs.length == 0) {
			return getPreviewForNoReferences();
		}

		Set<String> set = new HashSet<>();
		for (Reference reference : refs) {

			if (reachedMaximumResults(set.size())) {
				break;
			}

			if (!isValidReference(program, reference)) {
				continue;
			}

			addReferencePreview(set, program, reference);
		}

		String[] array = new String[set.size()];
		set.toArray(array);
		return array;
	}

	private String[] getPreviewForNoReferences() {
		String undefinedPointerText = getUndefinedPointer(codeUnit);
		if (undefinedPointerText != null) {
			return new String[] { undefinedPointerText };
		}
		return new String[0];
	}

	private boolean isValidReference(Program program, Reference reference) {

		if (!reference.isMemoryReference()) {
			return false;
		}

		Address toAddr = reference.getToAddress();
		return isGoodAddress(program, toAddr);
	}

	private boolean reachedMaximumResults(int newCount) {
		return (totalCommentsFound + newCount) >= maxDisplayLines;
	}

	private void addReferencePreview(Set<String> results, Program program, Reference reference) {

		Address toAddr = reference.getToAddress();
		if (handleDirectFlow(results, reference, program, toAddr)) {
			return;
		}

		Data data = getData(program, toAddr);
		if (data == null) {
			return; // nothing there!
		}

		if (handleIndirectDataReference(results, reference, program, toAddr, data)) {
			return;
		}

		handleDirectDataReference(results, toAddr, data);
	}

	private Data getData(Program program, Address toAddr) {

		Data data = program.getListing().getDataAt(toAddr);
		if (data == null) {
			// could be slower
			data = program.getListing().getDataContaining(toAddr);
		}
		return data;
	}

	private void handleDirectDataReference(Set<String> set, Address dataAccessAddress, Data data) {

		Object value = data.getValue();
		if (value instanceof Scalar) {
			Scalar scalar = (Scalar) value;
			if (scalar.getSignedValue() == 0) {
				return;
			}
		}

		String dataRepresentation = getDataValueRepresentation(dataAccessAddress, data);
		if (!StringUtils.isBlank(dataRepresentation)) {
			set.add("= " + dataRepresentation);
		}
	}

	private String getDataValueRepresentation(Address dataAccessAddress, Data data) {
		if (!useAbbreviatedAutomatic) {
			return data.getDefaultValueRepresentation();
		}

		if (isOffcut(dataAccessAddress, data)) {
			return getOffcutDataString(dataAccessAddress, data);
		}

		return data.getDefaultValueRepresentation();
	}

	private boolean isOffcut(Address address, CodeUnit cu) {
		if (cu == null) {
			return false;
		}
		return !cu.getMinAddress().equals(address);
	}

	private String getOffcutDataString(Address offcutAddress, Data data) {
		Address dataAddress = data.getMinAddress();
		int diff = (int) offcutAddress.subtract(dataAddress);

		DataType dt = data.getBaseDataType();
		return getOffcutForStringData(data, dataAddress, diff, dt);
	}

	private String getOffcutForStringData(Data data, Address dataAddress, int diff, DataType dt) {
		if (StringDataInstance.isString(data)) {
			StringDataInstance string = StringDataInstance.getStringDataInstance(data);
			string = string.getByteOffcut(diff);
			return string.getStringRepresentation();
		}
		if (!data.hasStringValue()) {
			return null;
		}

		int len = data.getLength();

		if (diff >= len) {
			// not sure if this can happen--just use the default
			return data.getDefaultValueRepresentation();
		}

		DumbMemBufferImpl mb = new DumbMemBufferImpl(data.getMemory(), dataAddress.add(diff));
		String s = dt.getRepresentation(mb, data, len - diff);

		return s;
	}

	private boolean handleIndirectDataReference(Set<String> set, Reference reference,
			Program program, Address toAddress, Data data) {

		RefType type = reference.getReferenceType();
		if (!type.isIndirect()) {
			return false;
		}

		if (handlePointer(set, program, reference, data)) {
			return true;
		}

		handlePotentialPointer(set, program, toAddress, data);
		return true;
	}

	private boolean handlePointer(Set<String> set, Program program, Reference reference,
			Data data) {

		if (!data.isPointer()) {
			return false;
		}

		SymbolTable symbolTable = program.getSymbolTable();
		ReferenceManager referenceManager = program.getReferenceManager();
		Reference pointerReference =
			referenceManager.getPrimaryReferenceFrom(reference.getToAddress(), 0);
		if (pointerReference != null) {
			Address addr = pointerReference.getToAddress();
			Symbol sym = symbolTable.getPrimarySymbol(addr);
			if (operandsFollowPointerRefs && reference.getOperandIndex() != CodeUnit.MNEMONIC) {
				if (!sym.isDynamic()) {
					return true; // already displayed by operand
				}
			}
			set.add(POINTER_ARROW + sym.getName());
			return true;
		}

		Address address = (Address) data.getValue();
		if (address != null && address.getOffset() != 0) {
			set.add(POINTER_ARROW + address);
		}

		return true;
	}

	private void handlePotentialPointer(Set<String> list, Program program, Address toAddress,
			Data data) {

		if (data.isDefined()) {
			return;
		}

		// if no data is defined at the address, see if it is a pointer
		SymbolTable symbolTable = program.getSymbolTable();
		PseudoDisassembler dis = new PseudoDisassembler(program);
		Address pointerAddress = dis.getIndirectAddr(toAddress);
		if (!isGoodAddress(program, pointerAddress)) {
			return;
		}

		Symbol symbol = symbolTable.getPrimarySymbol(pointerAddress);
		if (symbol != null) {
			list.add(POINTER_ARROW + symbol.getName());
		}
		else {
			list.add(POINTER_ARROW + pointerAddress);
		}
	}

	private boolean handleDirectFlow(Set<String> set, Reference reference, Program program,
			Address toAddr) {

		if (!showAutomaticFunctions) {
			return false;
		}

		RefType type = reference.getReferenceType();
		if (!type.isFlow()) {
			return false;
		}

		if (type.isIndirect()) {
			return false;
		}

		if (type.isCall()) {
			boolean showName = reference.isMnemonicReference();
			String signature = getFunctionSignature(program, toAddr, showName);
			if (signature != null) {
				set.add(signature);
			}
		}

		return true;
	}

	private String getUndefinedPointer(CodeUnit cu) {
		if (!(cu instanceof Data)) {
			return null;
		}

		Data data = (Data) cu;
		DataType dataType = data.getDataType();
		if (!(dataType instanceof Undefined || dataType instanceof DefaultDataType)) {
			return null;
		}

		Program program = cu.getProgram();
		if (programIsEntireMemorySpace(program)) {
			// this prevents the case where a program represents the entire address space
			// in which everything looks like a pointer
			return null;
		}

		int align = program.getLanguage().getInstructionAlignment();
		Address codeUnitAddress = cu.getAddress();
		long codeUnitOffset = codeUnitAddress.getOffset();
		if ((codeUnitOffset % align) != 0) {
			// not aligned
			return null;
		}

		int pointerSize = program.getDefaultPointerSize();
		long addrLong = 0;
		Memory memory = program.getMemory();
		try {
			switch (pointerSize) {
				case 4:
					int addrInt = memory.getInt(codeUnitAddress);
					addrLong = (addrInt & 0xffffffffL);
					addrLong *= codeUnitAddress.getAddressSpace().getAddressableUnitSize();
					break;
				case 8:
					addrLong = memory.getLong(codeUnitAddress);
					break;
			}
		}
		catch (MemoryAccessException e) {
			// handled below
		}

		if (addrLong != 0) {
			try {
				Address potentialAddr = codeUnitAddress.getNewAddress(addrLong);
				if (memory.contains(potentialAddr)) {
					return "?  ->  " + potentialAddr.toString();
				}
			}
			catch (AddressOutOfBoundsException e) {
				// ignore
			}
		}
		return null;
	}

	private boolean programIsEntireMemorySpace(Program program) {
		Address minAddress = program.getMinAddress();
		Address maxAddress = program.getMaxAddress();
		AddressSpace addressSpace = maxAddress.getAddressSpace();
		Address spaceMaxAddress = addressSpace.getMaxAddress();
		long minOffset = minAddress.getOffset();
		if (minOffset == 0 && maxAddress.equals(spaceMaxAddress)) {
			return true;
		}
		return false;
	}

	private String getFunctionSignature(Program program, Address funcAddr,
			boolean displayFuncName) {
		Function function = program.getFunctionManager().getFunctionAt(funcAddr);
		if (function == null) {
			return null;
		}
		return function.getPrototypeString(false, false);
	}

	/**
	 * Check if this address could really be a good address in the program.
	 * Never accept 0 as a valid address.
	 *
	 * @param program program to check if address is valid within.
	 * @param addr    address in program to be checked
	 * @return true if this is a valid address
	 */
	private boolean isGoodAddress(Program program, Address addr) {
		if (addr == null) {
			return false;
		}
		if (!program.getMemory().contains(addr)) {
			return false;
		}

		long offset = addr.getOffset();
		if (offset == 0x0 || offset == 0xffffffff || offset == 0xffff || offset == 0xff) {
			return false;
		}

		return true;
	}

	/**
	 * Gets an array of objects that indicate the repeatable comments at the "to addresses" of the
	 * references.
	 * @param listing the program listing
	 * @param memRefs the references whose repeatable comments we are interested in.
	 * @param showAll true indicates to show all referenced repeatable comments and not just the
	 * primary reference's repeatable comment.
	 * @return an array of objects, where each object is a RefRepeatComment containing an
	 * address and a String array of the repeatable comments for a reference.
	 */
	private RefRepeatComment[] getRepeatableComments(Listing listing, Reference[] memRefs,
			boolean showAll) {
		Set<RefRepeatComment> set = new HashSet<>();

		for (int i = 0; i < memRefs.length && totalCommentsFound < maxDisplayLines; ++i) {
			if (!showAll && !memRefs[i].isPrimary()) {
				continue;
			}

			Address address = memRefs[i].getToAddress();
			String[] comment = getComment(listing, address);
			if (comment != null && comment.length > 0) {
				set.add(new RefRepeatComment(address, comment));
				totalCommentsFound++;
			}
		}

		return set.toArray(new RefRepeatComment[set.size()]);
	}

	private String[] getComment(Listing listing, Address address) {

		// prefer listing comments first since there may not be a code unit at this address
		String repeatableComment = listing.getComment(CodeUnit.REPEATABLE_COMMENT, address);
		if (repeatableComment != null) {
			return StringUtilities.toLines(repeatableComment);
		}

		CodeUnit cu = listing.getCodeUnitAt(address);
		if (cu == null) {
			return null;
		}

		Function func = listing.getFunctionAt(address);
		if (func != null) {
			return func.getRepeatableCommentAsArray();
		}

		return cu.getCommentAsArray(CodeUnit.REPEATABLE_COMMENT);
	}

	/**
	 * Return all the comments
	 * @return the comments
	 */
	public String[] getComments() {
		ArrayList<String> list = new ArrayList<>();
		boolean hasEol = hasEOL();
		boolean hasRepeatable = hasRepeatable();
		boolean hasRefRepeats = hasReferencedRepeatable();

		list.addAll(Arrays.asList((String[]) displayCommentArrays[MY_EOLS]));
		if (alwaysShowRepeatable || !hasEol) {
			list.addAll(Arrays.asList((String[]) displayCommentArrays[MY_REPEATABLES]));
		}

		if (alwaysShowRefRepeats || !(hasEol || hasRepeatable)) {
			RefRepeatComment[] refRepeatComments =
				(RefRepeatComment[]) displayCommentArrays[REF_REPEATABLES];
			for (RefRepeatComment refRepeatComment : refRepeatComments) {
				// Address addr = refRepeatComments[j].getAddress();
				list.addAll(Arrays.asList(refRepeatComment.getCommentLines()));
			}
		}

		if (alwaysShowAutomatic || !(hasEol || hasRepeatable || hasRefRepeats)) {
			list.addAll(Arrays.asList((String[]) displayCommentArrays[MY_AUTOMATIC]));
		}

		return list.toArray(new String[list.size()]);
	}

	/**
	 * Gets the end of line comment as an array.
	 *
	 * @return the EOL comment
	 */
	public String[] getEOLComments() {
		return (String[]) displayCommentArrays[MY_EOLS];
	}

	/**
	 * Gets the repeatable comment as an array.
	 * @return the repeatable comment.
	 */
	public String[] getRepeatableComments() {
		return (String[]) displayCommentArrays[MY_REPEATABLES];
	}

	/**
	 * Gets the number of repeatable comments at the "to reference"s
	 * @return the number of reference repeatable comments
	 */
	public int getReferencedRepeatableCommentsCount() {
		return displayCommentArrays[REF_REPEATABLES].length;
	}

	public String[] getReferencedRepeatableComments() {
		ArrayList<String> stringList = new ArrayList<>();
		int refRepeatCount = getReferencedRepeatableCommentsCount();
		for (int i = 0; i < refRepeatCount; i++) {
			RefRepeatComment refRepeatComment = getReferencedRepeatableComments(i);
			String[] refRepeatComments = refRepeatComment.getCommentLines();
			stringList.addAll(Arrays.asList(refRepeatComments));
		}
		return stringList.toArray(new String[stringList.size()]);
	}

	/**
	 * Gets a referenced repeatable comment as a RefRepeatComment object.
	 * @param index indicator of which referenced repeatable comment is desired.
	 * The value is 0 thru one less than the number of referenced repeatable comments.
	 * @return the RefRepeatComment containing the referenced address and its referenced repeatable comment
	 */
	public RefRepeatComment getReferencedRepeatableComments(int index) {
		return (RefRepeatComment) displayCommentArrays[REF_REPEATABLES][index];
	}

	/**
	 * Gets a referenced repeatable comment as a RefRepeatComment object.
	 * @param refAddress the reference address whose repeatable comment is desired.
	 * Note: there must be a reference from the address for this displayableEol to the refAddress.
	 * @return the comment lines for the referenced address's repeatable comment or null.
	 */
	public String[] getReferencedRepeatableComments(Address refAddress) {
		Object[] refRepeatArray = displayCommentArrays[REF_REPEATABLES];
		for (Object element : refRepeatArray) {
			RefRepeatComment refRepeatComment = (RefRepeatComment) element;
			if (refRepeatComment.getAddress().equals(refAddress)) {
				return refRepeatComment.getCommentLines();
			}
		}
		return null;
	}

	/**
	 * Gets the automatic comment as an array.
	 * @return the automatic comment
	 */
	public String[] getAutomaticComment() {
		return (String[]) displayCommentArrays[MY_AUTOMATIC];
	}

	@Override
	public String toString() {

		StringBuilder buffy = new StringBuilder();
		String[] eols = (String[]) displayCommentArrays[MY_EOLS];
		if (eols.length != 0) {
			buffy.append("EOLs: ").append(Arrays.toString(eols));
		}

		String[] myRepeatables = (String[]) displayCommentArrays[MY_REPEATABLES];
		if (myRepeatables.length != 0) {
			buffy.append("My Repeatables: ").append(Arrays.toString(myRepeatables));
		}

		Object[] refRepeatables = displayCommentArrays[REF_REPEATABLES];
		if (refRepeatables.length != 0) {
			buffy.append("Ref Repeatables: ").append(Arrays.toString(refRepeatables));
		}

		String[] myAutomatic = (String[]) displayCommentArrays[MY_AUTOMATIC];
		if (myAutomatic.length != 0) {
			buffy.append("My Automatic: ").append(Arrays.toString(myAutomatic));
		}

		return buffy.toString();
	}

	public int getCommentLineCount(int subType) {
		switch (subType) {
			case MY_EOLS:
				return ((String[]) displayCommentArrays[MY_EOLS]).length;
			case MY_REPEATABLES:
				return ((String[]) displayCommentArrays[MY_REPEATABLES]).length;
			case REF_REPEATABLES:
				int count = 0;
				Object[] refRepeatArray = displayCommentArrays[REF_REPEATABLES];
				for (Object element : refRepeatArray) {
					count += ((RefRepeatComment) element).getCommentLines().length;
				}
				return count;
			case MY_AUTOMATIC:
				return ((String[]) displayCommentArrays[MY_AUTOMATIC]).length;
			default:
				throw new IllegalArgumentException(
					subType + " is not a valid Eol Comment subType indicator.");
		}

	}

	public int getRefRepeatableCommentLineCount(Address refAddress) {
		Object[] refRepeatArray = displayCommentArrays[REF_REPEATABLES];
		for (Object element : refRepeatArray) {
			RefRepeatComment refRepeatComment = (RefRepeatComment) element;
			if (refRepeatComment.getAddress().equals(refAddress)) {
				return refRepeatComment.getCommentLines().length;
			}
		}
		return 0;
	}

	private int getEolRow(ProgramLocation loc) {
		int numBefore = 0;
		boolean hasEol = hasEOL();
		boolean hasRepeatable = hasRepeatable();
		boolean hasRefRepeats = hasReferencedRepeatable();

		if (loc instanceof EolCommentFieldLocation) {
			EolCommentFieldLocation commentLoc = (EolCommentFieldLocation) loc;
			return numBefore + commentLoc.getCurrentCommentRow();
		}
		numBefore += getCommentLineCount(DisplayableEol.MY_EOLS);

		if (loc instanceof RepeatableCommentFieldLocation) {
			RepeatableCommentFieldLocation commentLoc = (RepeatableCommentFieldLocation) loc;
			return numBefore + commentLoc.getCurrentCommentRow();
		}

		if (alwaysShowRepeatable || !hasEol) {
			numBefore += getCommentLineCount(DisplayableEol.MY_REPEATABLES);
		}

		if (loc instanceof RefRepeatCommentFieldLocation) {
			RefRepeatCommentFieldLocation commentLoc = (RefRepeatCommentFieldLocation) loc;
			Address desiredAddress = commentLoc.getReferencedRepeatableAddress();
			int startRowInRefRepeats = getCommentStartRow(desiredAddress);
			int rowInComment =
				(hasRefRepeatComment(desiredAddress)) ? commentLoc.getCurrentCommentRow() : 0;
			return numBefore + startRowInRefRepeats + rowInComment;
		}

		if (alwaysShowRefRepeats || !(hasEol || hasRepeatable)) {
			numBefore += getCommentLineCount(DisplayableEol.REF_REPEATABLES);
		}

		if (loc instanceof AutomaticCommentFieldLocation) {
			AutomaticCommentFieldLocation commentLoc = (AutomaticCommentFieldLocation) loc;
			return numBefore + commentLoc.getCurrentCommentRow();
		}

		if (alwaysShowAutomatic || !(hasEol || hasRepeatable || hasRefRepeats)) {
			numBefore += getCommentLineCount(DisplayableEol.MY_AUTOMATIC);
		}

		return numBefore;
	}

	private boolean hasRefRepeatComment(Address desiredAddress) {
		RefRepeatComment[] refRepeatComments =
			(RefRepeatComment[]) displayCommentArrays[REF_REPEATABLES];
		for (RefRepeatComment comment : refRepeatComments) {
			Address checkAddress = comment.getAddress();
			if (desiredAddress.equals(checkAddress)) {
				return true;
			}
		}
		return false;
	}

	public RowColLocation getRowCol(CommentFieldLocation cloc) {
		int strOffset = cloc.getCharOffset();
		if (cloc instanceof RefRepeatCommentFieldLocation) {
			RefRepeatCommentFieldLocation commentLoc = (RefRepeatCommentFieldLocation) cloc;
			Address desiredAddress = commentLoc.getReferencedRepeatableAddress();
			if (!hasRefRepeatComment(desiredAddress)) {
				strOffset = 0;
			}
		}
		int eolRow = getEolRow(cloc);
		return new RowColLocation(eolRow, strOffset);
	}

	public ProgramLocation getLocation(int eolRow, int eolColumn) {
		boolean hasEol = hasEOL();
		boolean hasRepeatable = hasRepeatable();
		boolean hasRefRepeats = hasReferencedRepeatable();
		int numEol = getCommentLineCount(MY_EOLS);
		int numRepeatable = getCommentLineCount(MY_REPEATABLES);
		int numRefRepeats = getCommentLineCount(REF_REPEATABLES);
		int numAutomatic = getCommentLineCount(MY_AUTOMATIC);

		int[] cpath = null;
		if (codeUnit instanceof Data) {
			cpath = ((Data) codeUnit).getComponentPath();
		}

		int beforeEol = 0;
		int beforeRepeatable = beforeEol + numEol;
		int beforeRefRepeats = beforeRepeatable;
		if (alwaysShowRepeatable || !hasEol) {
			beforeRefRepeats += numRepeatable;
		}

		int beforeAutomatic = beforeRefRepeats;
		if (alwaysShowRefRepeats || !(hasEol || hasRepeatable)) {
			beforeAutomatic += numRefRepeats;
		}

		int numTotal = beforeAutomatic;
		if (alwaysShowAutomatic || !(hasEol || hasRepeatable || hasRefRepeats)) {
			numTotal += numAutomatic;
		}

		if (eolRow < 0) {
			return null;
		}

		Program program = codeUnit.getProgram();
		if (eolRow < beforeRepeatable) {
			return new EolCommentFieldLocation(program, codeUnit.getMinAddress(), cpath,
				getComments(), eolRow, eolColumn, eolRow);
		}

		if (eolRow < beforeRefRepeats) {
			return new RepeatableCommentFieldLocation(program, codeUnit.getMinAddress(), cpath,
				getComments(), eolRow, eolColumn, eolRow - beforeRepeatable);
		}

		if (eolRow < beforeAutomatic) {
			int rowInAllRefRepeats = eolRow - beforeRefRepeats;
			return new RefRepeatCommentFieldLocation(program, codeUnit.getMinAddress(), cpath,
				getComments(), eolRow, eolColumn, getRefRepeatRow(rowInAllRefRepeats),
				getRefRepeatAddress(rowInAllRefRepeats));
		}

		if (eolRow < numTotal) {
			return new AutomaticCommentFieldLocation(program, codeUnit.getMinAddress(), cpath,
				getComments(), eolRow, eolColumn, eolRow - beforeAutomatic);
		}

		return null;
	}

	private Address getRefRepeatAddress(int rowInAllRefRepeats) {
		RefRepeatComment[] refRepeatComments =
			(RefRepeatComment[]) displayCommentArrays[REF_REPEATABLES];
		int currentStartRow = 0;
		for (RefRepeatComment comment : refRepeatComments) {
			int numRows = comment.getCommentLineCount();
			if (rowInAllRefRepeats < (currentStartRow + numRows)) {
				return comment.getAddress();
			}
			currentStartRow += numRows;
		}
		return null;
	}

	private int getRefRepeatRow(int rowInAllRefRepeats) {
		RefRepeatComment[] refRepeatComments =
			(RefRepeatComment[]) displayCommentArrays[REF_REPEATABLES];
		int currentStartRow = 0;
		for (RefRepeatComment comment : refRepeatComments) {
			int numRows = comment.getCommentLineCount();
			if (rowInAllRefRepeats < (currentStartRow + numRows)) {
				return rowInAllRefRepeats - currentStartRow;
			}
			currentStartRow += numRows;
		}
		return -1;
	}

	private int getCommentStartRow(Address refAddress) {
		RefRepeatComment[] refRepeatComments =
			(RefRepeatComment[]) displayCommentArrays[REF_REPEATABLES];
		int currentStartRow = 0;
		for (RefRepeatComment comment : refRepeatComments) {
			Address checkAddress = comment.getAddress();
			if (refAddress.compareTo(checkAddress) <= 0) {
				return currentStartRow;
			}
			currentStartRow += comment.getCommentLineCount();
		}
		return currentStartRow;
	}

	public boolean isRefRepeatRow(int eolRow) {
		boolean hasEol = hasEOL();
		boolean hasRepeatable = hasRepeatable();
		int numEol = getCommentLineCount(MY_EOLS);
		int numRepeatable = getCommentLineCount(MY_REPEATABLES);
		int numRefRepeats = getCommentLineCount(REF_REPEATABLES);

		int beforeEol = 0;
		int beforeRepeatable = beforeEol + numEol;
		int beforeRefRepeats = beforeRepeatable;
		if (alwaysShowRepeatable || !hasEol) {
			beforeRefRepeats += numRepeatable;
		}
		int beforeAutomatic = beforeRefRepeats;
		if (alwaysShowRefRepeats || !(hasEol || hasRepeatable)) {
			beforeAutomatic += numRefRepeats;
		}

		return ((eolRow >= beforeRefRepeats) && (eolRow < beforeAutomatic));
	}

}
