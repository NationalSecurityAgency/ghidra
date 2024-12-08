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
import ghidra.app.util.viewer.field.EolEnablement;
import ghidra.app.util.viewer.field.EolExtraCommentsOption;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.StringUtilities;
import util.CollectionUtils;

/**
 * Utility class with methods to get comment information that can be displayed in the end of line
 * comment field. Each instance of this class is associated with a code unit.  This class uses the
 * provided options to decide how to load and filter existing comments.
 *
 * <p>Comment types that can be shown include the End of Line comment for the code unit, the
 * Repeatable comment for the code unit, any repeatable comments for the code units that this code
 * unit has references to, and possibly a comment indicating the data at a code unit that is
 * referenced by this code unit.
 */
public class EolComments {

	private static final String POINTER_ARROW = "-> ";

	private CodeUnit codeUnit;

	private List<String> eols = new ArrayList<>();
	private List<String> repeatables = new ArrayList<>();
	private List<RefRepeatComment> refRepeatables = new ArrayList<>();
	private List<String> autos = new ArrayList<>();
	private List<Reference> references = new ArrayList<>();

	// used to signal the operand is already displaying a pointer reference, so there is no need for
	// this class to create a comment to do the same
	private boolean operandsShowReferences = false;

	private int maxDisplayComments;
	private EolExtraCommentsOption extraCommentsOption;

	public EolComments(CodeUnit cu, boolean operandsShowReferences, int maxDisplayComments,
			EolExtraCommentsOption extraCommentsOption) {
		this.codeUnit = cu;
		this.operandsShowReferences = operandsShowReferences;
		this.maxDisplayComments = maxDisplayComments;
		this.extraCommentsOption = extraCommentsOption;
		loadComments();
	}

	private void loadComments() {
		loadEols();
		loadRepeatables();
		loadRefRepeatables();
		loadAutos();
	}

	/**
	 * Returns the current number of comments in this class.  The value of this method will change
	 * as this class is loading comments.  After loading, this value will be fixed.
	 * @return the size
	 */
	private int size() {
		int refRepeatablesSize = 0;
		for (RefRepeatComment item : refRepeatables) {
			refRepeatablesSize += item.getCommentLineCount();
		}
		return eols.size() + repeatables.size() + refRepeatablesSize + autos.size();
	}

	/**
	 * Returns the number of comments that can be added before reaching the maximum number of
	 * comments
	 * @return the number of comments
	 */
	private int getAvailableSpace() {
		return maxDisplayComments - size();
	}

	private void loadEols() {
		Collection<String> comments =
			Arrays.asList(codeUnit.getCommentAsArray(CodeUnit.EOL_COMMENT));
		addStrings(comments, eols);
	}

	private void loadRepeatables() {
		boolean hasOtherComments = !eols.isEmpty();
		if (!extraCommentsOption.isShowingRepeatables(hasOtherComments)) {
			return;
		}

		Collection<String> comments =
			Arrays.asList(codeUnit.getCommentAsArray(CodeUnit.REPEATABLE_COMMENT));
		addStrings(comments, repeatables);
	}

	private void loadRefRepeatables() {
		boolean hasOtherComments = !(eols.isEmpty() && repeatables.isEmpty());
		if (!extraCommentsOption.isShowingRefRepeatables(hasOtherComments)) {
			return;
		}

		Collection<RefRepeatComment> refRepeatableComments = getRepeatableComments(true);
		addRefRepeatables(refRepeatableComments, refRepeatables);
	}

	private void loadAutos() {
		boolean hasOtherComments =
			!(eols.isEmpty() && repeatables.isEmpty() && refRepeatables.isEmpty());
		if (!extraCommentsOption.isShowingAutoComments(hasOtherComments)) {
			return;
		}

		Collection<String> comments = getReferencePreviews();
		addStrings(comments, autos);
	}

	private void addRefRepeatables(Collection<RefRepeatComment> from,
			Collection<RefRepeatComment> to) {

		int space = getAvailableSpace();
		int total = 0;
		for (RefRepeatComment item : from) {
			to.add(item);
			total += item.getCommentLineCount();
			if (total == space) {
				return;
			}
		}
	}

	private void addStrings(Collection<String> from, Collection<String> to) {
		int space = getAvailableSpace();
		for (String item : from) {
			to.add(item);
			if (to.size() == space) {
				return;
			}
		}
	}

	private void loadReferences() {
		if (!references.isEmpty()) {
			return; // already loaded
		}

		// arbitrary limit to prevent excessive consumption of resources
		int space = getAvailableSpace();
		int max = Math.min(100, space);
		Program program = codeUnit.getProgram();
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressSet addresses = new AddressSet(codeUnit.getMinAddress(), codeUnit.getMaxAddress());
		AddressIterator it = referenceManager.getReferenceSourceIterator(addresses, true);
		while (it.hasNext() && references.size() < max) {
			Address fromAddress = it.next();
			Reference[] refs = referenceManager.getReferencesFrom(fromAddress);
			for (Reference r : refs) {
				references.add(r);
			}
		}
		Collections.sort(references);
	}

	public boolean isShowingRepeatables() {
		return !repeatables.isEmpty();
	}

	public boolean isShowingRefRepeatables() {
		return !refRepeatables.isEmpty();
	}

	public boolean isShowingAutoComments() {
		return !autos.isEmpty();
	}

	private Collection<String> getReferencePreviews() {

		loadReferences();
		if (references.isEmpty()) {
			return getPreviewForNoReferences();
		}

		int space = getAvailableSpace();
		Program program = codeUnit.getProgram();
		Set<String> set = new LinkedHashSet<>();
		for (Reference reference : references) {

			if (set.size() >= space) {
				break;
			}

			if (!isValidReference(program, reference)) {
				continue;
			}

			createAutoCommentFromReference(set, program, reference);
		}

		return set;
	}

	private Collection<String> getPreviewForNoReferences() {
		Set<String> set = new HashSet<>();
		String translatedString = getTranslatedString();
		if (translatedString != null) {
			set.add(translatedString);
			return set;
		}
		String pointerText = getUndefinedPointer(codeUnit);
		if (pointerText != null) {
			set.add(pointerText);
			return set;
		}
		return set;
	}

	private String getTranslatedString() {
		if (codeUnit instanceof Data data && StringDataInstance.isString(data)) {
			StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);
			if (sdi.hasTranslatedValue()) {
				// show the translated value
				return sdi.getStringRepresentation(sdi.isShowTranslation());
			}
		}
		return null;
	}

	private boolean isValidReference(Program program, Reference reference) {
		if (!reference.isMemoryReference()) {
			return false;
		}
		Address toAddress = reference.getToAddress();
		return isValidAddress(program, toAddress);
	}

	private void createAutoCommentFromReference(Set<String> results, Program program,
			Reference reference) {

		Address toAddress = reference.getToAddress();
		if (createFunctionCallPreview(results, reference, program, toAddress)) {
			return;
		}

		Data data = getData(program, toAddress);
		if (data == null) {
			return; // nothing there
		}

		if (createIndirectDataReferencePreview(results, reference, program, toAddress, data)) {
			return;
		}

		handleDirectDataReferencePreview(results, toAddress, data);
	}

	private Data getData(Program program, Address toAddr) {
		Data data = program.getListing().getDataAt(toAddr);
		if (data == null) {
			data = program.getListing().getDataContaining(toAddr);
		}
		return data;
	}

	private void handleDirectDataReferencePreview(Set<String> set, Address address, Data data) {

		Object value = data.getValue();
		if (value instanceof Scalar) {
			Scalar scalar = (Scalar) value;
			if (scalar.getSignedValue() == 0) {
				return;
			}
		}

		String dataRepresentation = getDataValueRepresentation(address, data);
		if (!StringUtils.isBlank(dataRepresentation)) {
			set.add("= " + dataRepresentation);
		}
	}

	private String getDataValueRepresentation(Address dataAccessAddress, Data data) {
		if (extraCommentsOption.useAbbreviatedComments()) {
			if (isOffcut(dataAccessAddress, data)) {
				return getOffcutString(dataAccessAddress, data);
			}
		}
		return data.getDefaultValueRepresentation();
	}

	private boolean isOffcut(Address address, CodeUnit cu) {
		if (cu == null) {
			return false;
		}
		return !cu.getMinAddress().equals(address);
	}

	private String getOffcutString(Address offcutAddress, Data data) {
		Address dataAddress = data.getMinAddress();
		int diff = (int) offcutAddress.subtract(dataAddress);
		DataType dt = data.getBaseDataType();
		return getOffcutString(data, dataAddress, diff, dt);
	}

	private String getOffcutString(Data data, Address dataAddress, int diff, DataType dt) {
		if (StringDataInstance.isString(data)) {
			StringDataInstance string = StringDataInstance.getStringDataInstance(data);
			string = string.getByteOffcut(diff);
			return string.getStringRepresentation();
		}
		if (!data.hasStringValue()) {
			return null;
		}

		int length = data.getLength();
		if (diff >= length) {
			// not sure if this can happen--just use the default
			return data.getDefaultValueRepresentation();
		}

		DumbMemBufferImpl mb = new DumbMemBufferImpl(data.getMemory(), dataAddress.add(diff));
		return dt.getRepresentation(mb, data, length - diff);
	}

	private boolean createIndirectDataReferencePreview(Set<String> set, Reference reference,
			Program program, Address toAddress, Data data) {

		RefType type = reference.getReferenceType();
		if (!type.isIndirect()) {
			return false;
		}

		if (createDefinedDataPointerPreview(set, program, reference, data)) {
			return true;
		}

		createUndefinedPointerPreview(set, program, toAddress, data);
		return true;
	}

	private boolean createDefinedDataPointerPreview(Set<String> set, Program program,
			Reference reference, Data data) {

		if (!data.isPointer()) {
			return false;
		}

		SymbolTable symbolTable = program.getSymbolTable();
		ReferenceManager referenceManager = program.getReferenceManager();
		Reference pointerReference =
			referenceManager.getPrimaryReferenceFrom(reference.getToAddress(), 0);
		if (pointerReference != null) {
			Symbol symbol = symbolTable.getPrimarySymbol(pointerReference.getToAddress());
			if (operandIsShowingSymbolReference(symbol, reference)) {
				return true; // already displayed by operand
			}
			set.add(POINTER_ARROW + symbol.getName());
			return true;
		}

		Address address = (Address) data.getValue();
		if (address != null && address.getOffset() != 0) {
			set.add(POINTER_ARROW + address);
		}

		return true;
	}

	private boolean operandIsShowingSymbolReference(Symbol symbol, Reference reference) {
		if (operandsShowReferences && reference.getOperandIndex() != CodeUnit.MNEMONIC) {
			if (!symbol.isDynamic()) {
				return true;
			}
		}
		return false;
	}

	private void createUndefinedPointerPreview(Set<String> list, Program program, Address toAddress,
			Data data) {

		if (data.isDefined()) {
			return;
		}

		// if no data is defined at the address, see if it is a pointer
		SymbolTable symbolTable = program.getSymbolTable();
		PseudoDisassembler dis = new PseudoDisassembler(program);
		Address pointerAddress = dis.getIndirectAddr(toAddress);
		if (!isValidAddress(program, pointerAddress)) {
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

	private boolean createFunctionCallPreview(Set<String> set, Reference reference, Program program,
			Address toAddress) {

		if (extraCommentsOption.getAutoFunction() == EolEnablement.NEVER) {
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
			String signature = getFunctionSignature(program, toAddress);
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
		if (isEntireMemorySpace(program)) {
			// everything looks like a pointer when a program represents the entire address space
			return null;
		}

		int align = program.getLanguage().getInstructionAlignment();
		Address codeUnitAddress = cu.getAddress();
		long codeUnitOffset = codeUnitAddress.getOffset();
		if ((codeUnitOffset % align) != 0) {
			return null; // not aligned
		}

		return createPointerString(program, codeUnitAddress);
	}

	private String createPointerString(Program program, Address codeUnitAddress) {
		int pointerSize = program.getDefaultPointerSize();
		long offset = 0;
		Memory memory = program.getMemory();
		try {
			switch (pointerSize) {
				case 4:
					int addrInt = memory.getInt(codeUnitAddress);
					offset = (addrInt & 0xffffffffL);
					offset *= codeUnitAddress.getAddressSpace().getAddressableUnitSize();
					break;
				case 8:
					offset = memory.getLong(codeUnitAddress);
					break;
				default:
					return null;
			}

			if (offset != 0) {
				Address potentialAddr = codeUnitAddress.getNewAddress(offset);
				if (memory.contains(potentialAddr)) {
					return "?  ->  " + potentialAddr.toString();
				}
			}
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			// handled below
		}

		return null;
	}

	private boolean isEntireMemorySpace(Program program) {
		Address min = program.getMinAddress();
		Address max = program.getMaxAddress();
		AddressSpace space = max.getAddressSpace();
		return min.getOffset() == 0 && max.equals(space.getMaxAddress());
	}

	private String getFunctionSignature(Program program, Address a) {

		// Note: Users have complained the 'undefined' return type clutters the display.  Update
		// signature to omit return type if it is undefined.
		Function f = program.getFunctionManager().getFunctionAt(a);
		if (f != null) {
			return f.getPrototypeString(false, false);
		}
		return null;
	}

	/**
	 * Check if this address could be a valid address in the program. 0 id not a valid address.
	 *
	 * @param program program to check if address is valid within
	 * @param address address in program to be checked
	 * @return true if this is a valid address
	 */
	private boolean isValidAddress(Program program, Address address) {
		if (address == null) {
			return false;
		}
		if (!program.getMemory().contains(address)) {
			return false;
		}

		long offset = address.getOffset();
		if (offset == 0x0 || offset == 0xffffffff || offset == 0xffff || offset == 0xff) {
			return false;
		}

		return true;
	}

	private Collection<RefRepeatComment> getRepeatableComments(boolean showAll) {

		loadReferences();
		int space = getAvailableSpace();
		Set<RefRepeatComment> set = new LinkedHashSet<>();
		for (int i = 0; i < references.size() && set.size() < space; ++i) {
			Reference reference = references.get(i);
			if (!showAll && !reference.isPrimary()) {
				continue;
			}

			Address address = reference.getToAddress();
			String[] comment = getComment(address);
			if (!CollectionUtils.isBlank(comment)) {
				set.add(new RefRepeatComment(address, comment));
			}
		}

		return set;
	}

	private String[] getComment(Address address) {

		Program program = codeUnit.getProgram();
		Listing listing = program.getListing();

		// prefer listing comments first since there may not be a code unit at this address
		String repeatable = listing.getComment(CodeUnit.REPEATABLE_COMMENT, address);
		if (repeatable != null) {
			return StringUtilities.toLines(repeatable);
		}

		CodeUnit cu = listing.getCodeUnitAt(address);
		if (cu == null) {
			return null;
		}

		Function f = listing.getFunctionAt(address);
		if (f != null) {
			return f.getRepeatableCommentAsArray();
		}

		return cu.getCommentAsArray(CodeUnit.REPEATABLE_COMMENT);
	}

	/**
	 * Return all comments loaded by this class
	 * @return the comments
	 */
	public List<String> getComments() {
		List<String> list = new ArrayList<>();
		list.addAll(eols);
		list.addAll(repeatables);
		for (RefRepeatComment comment : refRepeatables) {
			list.addAll(Arrays.asList(comment.getCommentLines()));
		}
		list.addAll(autos);
		return list;
	}

	private String[] getCommentsArray() {
		List<String> comments = getComments();
		return comments.toArray(new String[comments.size()]);
	}

	/**
	 * Gets the End of Line comments
	 * @return the comments
	 */
	public List<String> getEOLComments() {
		return Collections.unmodifiableList(eols);
	}

	/**
	 * Gets the repeatable comments
	 * @return the comments
	 */
	public List<String> getRepeatableComments() {
		return Collections.unmodifiableList(repeatables);
	}

	/**
	 * Gets the repeatable comments at the "to reference"s
	 * @return the comments
	 */
	public List<RefRepeatComment> getReferencedRepeatableComments() {
		return Collections.unmodifiableList(refRepeatables);
	}

	/**
	 * Gets the automatic comments
	 * @return the comments
	 */
	public List<String> getAutomaticComment() {
		return Collections.unmodifiableList(autos);
	}

	@Override
	public String toString() {

		StringBuilder buffy = new StringBuilder();
		if (eols.isEmpty()) {
			buffy.append("EOLs: ").append(eols);
		}

		if (!repeatables.isEmpty()) {
			buffy.append("My Repeatables: ").append(repeatables);
		}

		if (!refRepeatables.isEmpty()) {
			buffy.append("Ref Repeatables: ").append(refRepeatables);
		}

		if (!autos.isEmpty()) {
			buffy.append("My Automatic: ").append(autos);
		}

		return buffy.toString();
	}

	private int getEolRow(ProgramLocation loc) {
		int numBefore = 0;
		if (loc instanceof EolCommentFieldLocation) {
			EolCommentFieldLocation commentLoc = (EolCommentFieldLocation) loc;
			return numBefore + commentLoc.getCurrentCommentRow();
		}

		numBefore += eols.size();

		if (loc instanceof RepeatableCommentFieldLocation) {
			RepeatableCommentFieldLocation commentLoc = (RepeatableCommentFieldLocation) loc;
			return numBefore + commentLoc.getCurrentCommentRow();
		}

		numBefore += repeatables.size();

		if (loc instanceof RefRepeatCommentFieldLocation) {
			RefRepeatCommentFieldLocation commentLoc = (RefRepeatCommentFieldLocation) loc;
			Address desiredAddress = commentLoc.getReferencedRepeatableAddress();
			int startRowInRefRepeats = getCommentStartRow(desiredAddress);
			int rowInComment =
				(hasRefRepeatComment(desiredAddress)) ? commentLoc.getCurrentCommentRow() : 0;
			return numBefore + startRowInRefRepeats + rowInComment;
		}

		numBefore += refRepeatables.size();

		if (loc instanceof AutomaticCommentFieldLocation) {
			AutomaticCommentFieldLocation commentLoc = (AutomaticCommentFieldLocation) loc;
			return numBefore + commentLoc.getCurrentCommentRow();
		}

		numBefore += autos.size();

		return numBefore;
	}

	private boolean hasRefRepeatComment(Address desiredAddress) {
		for (RefRepeatComment comment : refRepeatables) {
			Address checkAddress = comment.getAddress();
			if (desiredAddress.equals(checkAddress)) {
				return true;
			}
		}
		return false;
	}

	public RowColLocation getRowCol(CommentFieldLocation cloc) {
		int offset = cloc.getCharOffset();
		if (cloc instanceof RefRepeatCommentFieldLocation) {
			RefRepeatCommentFieldLocation commentLoc = (RefRepeatCommentFieldLocation) cloc;
			Address desiredAddress = commentLoc.getReferencedRepeatableAddress();
			if (!hasRefRepeatComment(desiredAddress)) {
				offset = 0;
			}
		}
		int eolRow = getEolRow(cloc);
		return new RowColLocation(eolRow, offset);
	}

	public ProgramLocation getLocation(int eolRow, int eolColumn) {

		if (eolRow < 0) {
			return null;
		}

		int numEol = eols.size();
		int numRepeatable = repeatables.size();
		int numRefRepeats = refRepeatables.size();
		int numAutomatic = autos.size();

		int beforeRepeatable = numEol;
		int beforeRefRepeats = beforeRepeatable;
		if (!repeatables.isEmpty()) {
			beforeRefRepeats += numRepeatable;
		}

		int beforeAutomatic = beforeRefRepeats;
		if (!refRepeatables.isEmpty()) {
			beforeAutomatic += numRefRepeats;
		}

		int numTotal = beforeAutomatic;
		if (!autos.isEmpty()) {
			numTotal += numAutomatic;
		}

		Program program = codeUnit.getProgram();
		Address minAddress = codeUnit.getMinAddress();
		int[] cpath = null;
		if (codeUnit instanceof Data) {
			cpath = ((Data) codeUnit).getComponentPath();
		}
		if (eolRow < beforeRepeatable) {
			return new EolCommentFieldLocation(program, minAddress, cpath, getCommentsArray(),
				eolRow, eolColumn, eolRow);
		}

		if (eolRow < beforeRefRepeats) {
			return new RepeatableCommentFieldLocation(program, minAddress, cpath,
				getCommentsArray(), eolRow, eolColumn, eolRow - beforeRepeatable);
		}

		if (eolRow < beforeAutomatic) {
			int rowInAllRefRepeats = eolRow - beforeRefRepeats;
			return new RefRepeatCommentFieldLocation(program, minAddress, cpath, getCommentsArray(),
				eolRow, eolColumn, getRefRepeatRow(rowInAllRefRepeats),
				getRefRepeatAddress(rowInAllRefRepeats));
		}

		if (eolRow < numTotal) {
			return new AutomaticCommentFieldLocation(program, minAddress, cpath, getCommentsArray(),
				eolRow, eolColumn, eolRow - beforeAutomatic);
		}

		return null;
	}

	private Address getRefRepeatAddress(int row) {
		int currentRow = 0;
		for (RefRepeatComment comment : refRepeatables) {
			int lineCount = comment.getCommentLineCount();
			if (row < (currentRow + lineCount)) {
				return comment.getAddress();
			}
			currentRow += lineCount;
		}
		return null;
	}

	private int getRefRepeatRow(int row) {
		int currentRow = 0;
		for (RefRepeatComment comment : refRepeatables) {
			int numRows = comment.getCommentLineCount();
			if (row < (currentRow + numRows)) {
				return row - currentRow;
			}
			currentRow += numRows;
		}
		return -1;
	}

	private int getCommentStartRow(Address address) {
		int currentRow = 0;
		for (RefRepeatComment comment : refRepeatables) {
			Address commentAddress = comment.getAddress();
			if (address.compareTo(commentAddress) <= 0) {
				return currentRow;
			}
			currentRow += comment.getCommentLineCount();
		}
		return currentRow;
	}
}
