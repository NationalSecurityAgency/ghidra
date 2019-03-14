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
package ghidra.app.plugin.core.string;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramTask;
import ghidra.program.util.string.FoundString;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class MakeStringsTask extends ProgramTask {
	private static final String LOCALIZATION_SEPARATOR = "@";

	private final static int MAX_LABEL_LENGTH = 60;

	private List<FoundString> foundStrings;
	private boolean autoLabel;
	private boolean addAlignmentBytes;
	private boolean allowTruncate;
	private int offset;
	private boolean hasErrors = false;
	private int alignment;

	private boolean makeArray;
	private List<StringEvent> events = new ArrayList<>();

	public MakeStringsTask(Program program, List<FoundString> foundStrings, int offset,
			int alignment, boolean autoLabel, boolean addAlignmentBytes, boolean allowTruncate,
			boolean makeArray) {
		super(program, "Making Strings", true, true, true);
		this.foundStrings = foundStrings;
		this.offset = offset;
		this.alignment = alignment;
		this.autoLabel = autoLabel;
		this.addAlignmentBytes = addAlignmentBytes;
		this.allowTruncate = allowTruncate;
		this.makeArray = makeArray;

	}

	public MakeStringsTask(Program program, FoundString foundString, int offset, int alignment,
			boolean autoLabel, boolean addAlignmentBytes, boolean allowTruncate,
			boolean makeArray) {
		super(program, "Making Strings", true, true, true);

		List<FoundString> tempFoundStrings = new ArrayList<>();
		tempFoundStrings.add(foundString);
		this.foundStrings = tempFoundStrings;

		this.offset = offset;
		this.alignment = alignment;
		this.autoLabel = autoLabel;
		this.addAlignmentBytes = addAlignmentBytes;
		this.allowTruncate = allowTruncate;
		this.makeArray = makeArray;
	}

	@Override
	public void doRun(TaskMonitor monitor) {
		monitor.initialize(foundStrings.size());

		for (FoundString foundString : foundStrings) {
			if (monitor.isCancelled()) {
				break;
			}
			makeString(foundString);
			monitor.incrementProgress(1);
		}

	}

	private void makeString(FoundString foundString) {
		StringDataInstance stringInstance = foundString.getDataInstance(program.getMemory());
		if (offset != 0) {
			stringInstance = stringInstance.getCharOffcut(offset);
		}
		if (stringInstance.getStringLength() == 0) {
			return;
		}

		Address address = stringInstance.getAddress();
		int length = stringInstance.getDataLength();
		int paddingLength = getPaddingLength(address, length);

		Address conflictingAddress =
			DataUtilities.findFirstConflictingAddress(program, address, length, true);
		if (conflictingAddress != null) {
			if (!allowTruncate) {
				hasErrors = true;
				return;
			}
			length = (int) conflictingAddress.subtract(address);
			paddingLength = 0;
		}

		if (paddingLength > 0) {
			conflictingAddress = DataUtilities.findFirstConflictingAddress(program,
				address.add(length), paddingLength, true);
			if (conflictingAddress != null) {
				paddingLength = 0;
			}
		}

		DataType stringInstanceDataType = stringInstance.getStringDataTypeGuess();

		// non-pascal strings can absorb the extra zero bytes directly, pascal strings must create a separate alignment data
		if (!isPascal(stringInstanceDataType)) {
			length += paddingLength;
			paddingLength = 0;
		}

		DataType dataTypeToCreate = stringInstanceDataType;
		if (makeArray && stringInstanceDataType instanceof AbstractStringDataType) {
			DataType elementDT =
				((AbstractStringDataType) stringInstanceDataType).getReplacementBaseType();
			int elementCount = length / elementDT.getLength();
			dataTypeToCreate = new ArrayDataType(elementDT, elementCount, elementDT.getLength());
		}

		Data stringData = null;
		try {
			// TODO: Clearing all conflicts might be overly aggressive
			stringData = DataUtilities.createData(program, address, dataTypeToCreate, length, false,
				DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			events.add(new StringAddedEvent(dataTypeToCreate, address, stringData.getLength()));
		}
		catch (Exception e) {
			hasErrors = true;
		}

		if (paddingLength != 0) {
			try {
				program.getListing().createData(address.add(length), new AlignmentDataType(),
					paddingLength);
			}
			catch (Exception e) {
				// don't care that padding failed
			}
		}

		if (autoLabel && stringData != null) {
			String labelString = dataTypeToCreate.getDefaultLabelPrefix(stringData, stringData,
				stringData.getLength(), DataTypeDisplayOptions.DEFAULT);
			createLabel(address, labelString);
		}

	}

	private boolean isPascal(DataType stringDataType) {
		return stringDataType instanceof PascalString255DataType ||
			stringDataType instanceof PascalStringDataType ||
			stringDataType instanceof PascalUnicodeDataType;
	}

	/**
	 * Creates an analysis (not user defined) type of label with the specified name at the
	 * program's address.
	 * @param addr the address
	 * @param label the name for the label
	 */
	private void createLabel(Address addr, String label) {
		if (label.length() > MAX_LABEL_LENGTH) {
			label = label.substring(0, MAX_LABEL_LENGTH) + LOCALIZATION_SEPARATOR + addr;
		}

		try {
			doCreateLabel(addr, label);
			return;
		}
		catch (DuplicateNameException exc) {
			if (labelAlreadyExists(addr, label)) {
				// ignore label if it already exists
				return;
			}
		}
		catch (InvalidInputException exc) {
			// handled below
		}

		createLocalizedLabel(addr, label);
	}

	private void createLocalizedLabel(Address addr, String label) {
		String validLabel = SymbolUtilities.replaceInvalidChars(label, false);
		String localizedLabel = validLabel + LOCALIZATION_SEPARATOR + addr.toString();
		try {
			doCreateLabel(addr, localizedLabel);
		}
		catch (DuplicateNameException e) {
			// this implies there is already a 'localized' symbol at this address, with the
			// same name as the string we created--ignore
		}
		catch (InvalidInputException e) {
			// shouldn't happen
			Msg.debug(this, "Unexpected exception creating symbol", e);
		}
	}

	private void doCreateLabel(Address addr, String label)
			throws DuplicateNameException, InvalidInputException {
		Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
		if (sym == null) {
			program.getSymbolTable().createLabel(addr, label, SourceType.ANALYSIS);
		}
		else if (sym.getSource() == SourceType.DEFAULT) {
			sym.setName(label, SourceType.ANALYSIS);
		}
		else {
			// do nothing if symbol matches new label otherwise make new label primary
			// but keep the other one around
			if (!sym.toString().equals(label)) {
				Symbol newSym =
					program.getSymbolTable().createLabel(addr, label, SourceType.ANALYSIS);
				newSym.setPrimary();
			}
		}
	}

	private boolean labelAlreadyExists(Address addr, String name) {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol[] symbols = symbolTable.getSymbols(addr);
		for (Symbol symbol : symbols) {
			if (symbol.getName().equals(name)) {
				return true;
			}
		}
		return false;
	}

	private int getPaddingLength(Address address, int length) {
		if (!addAlignmentBytes || length % alignment == 0) {
			return 0;
		}

		int padLength = alignment - (length % alignment);

		try {
			byte[] bytes = new byte[padLength];
			int num = program.getMemory().getBytes(address.add(length), bytes, 0, padLength);
			if (num != padLength) {
				return 0;
			}
			for (int i = 0; i < padLength; i++) {
				if (bytes[i] != 0) {
					return 0;
				}
			}
			return padLength;
		}
		catch (MemoryAccessException e1) {
			return 0;
		}
	}

	public boolean hasErrors() {
		return hasErrors;
	}

	public List<StringEvent> getStringEvents() {
		return events;
	}
}
