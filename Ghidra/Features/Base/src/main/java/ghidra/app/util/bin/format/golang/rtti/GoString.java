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
package ghidra.app.util.bin.format.golang.rtti;

import java.io.IOException;
import java.util.function.Predicate;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.next.DWARFDataInstanceHelper;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;

/**
 * A structure that represents a golang string instance.
 */
@StructureMapping(structureName = "string")
public class GoString implements StructureMarkup<GoString> {
	public static final int MAX_SANE_STR_LEN = 1024 * 1024; // 1mb

	/**
	 * Creates a artificial gostring instance that was not read from a memory location.
	 * <p>
	 * @param goBinary {@link GoRttiMapper}
	 * @param stringData location of char array
	 * @param len length of char array
	 * @return new GoString instance
	 */
	public static GoString createInlineString(GoRttiMapper goBinary, Address stringData, long len) {
		GoString result = new GoString();
		result.context = goBinary.createArtificialStructureContext(GoString.class);
		result.str = stringData.getOffset();
		result.len = len;
		return result;
	}

	@ContextField
	private StructureContext<GoString> context;

	@FieldMapping
	@MarkupReference("getStringAddr")
	@EOLComment("getStringValue")
	private long str;

	@FieldMapping
	private long len;

	/**
	 * Returns the address of the char data, referenced via the str field's markup annotation
	 * @return address of the char data
	 */
	public Address getStringAddr() {
		return context.getDataTypeMapper().getDataAddress(str);
	}

	/**
	 * Returns an AddressRange that encompasses the string char data.
	 * 
	 * @return AddressRange that encompasses the string char data
	 */
	public AddressRange getStringDataRange() {
		if (len <= 0) {
			return null;
		}
		Address charStart = context.getDataTypeMapper().getDataAddress(str);
		Address charEnd = context.getDataTypeMapper().getDataAddress(str + len - 1);
		return new AddressRangeImpl(charStart, charEnd);
	}

	/**
	 * Returns the length of the string data
	 * 
	 * @return length of the string data
	 */
	public long getLength() {
		return len;
	}

	/**
	 * Returns the string value.
	 * 
	 * @return string value
	 * @throws IOException if error reading char data
	 */
	public String getStringValue() throws IOException {
		BinaryReader reader = context.getDataTypeMapper().getReader(str);
		return reader.readNextUtf8String((int) len);
	}

	private DataType getStringCharDataType() {
		// use char as the element data type because it renders better, even though
		// it causes a type-cast to uint8* in the decompiler
		return new ArrayDataType(CharDataType.dataType, (int) len, -1,
			context.getDataTypeMapper().getDTM());
	}

	/**
	 * Returns true if this string instance is valid and probably contains a go string.
	 * 
	 * @param charValidRange addresses that are valid locations for a string's char[] data 
	 * @param stringContentValidator a callback that will test a recovered string for validity
	 * @return boolean true if valid string, false if not valid string
	 * @throws IOException if error reading data
	 */
	public boolean isValid(AddressSetView charValidRange, Predicate<String> stringContentValidator)
			throws IOException {

		if (len <= 0 || len > MAX_SANE_STR_LEN) {
			return false;
		}

		Address structStartAddr = context.getStructureAddress();
		AddressRange charDataRange = getStringDataRange();
		if (charDataRange == null || !charValidRange.contains(charDataRange.getMinAddress(),
			charDataRange.getMaxAddress())) {
			return false;
		}

		DWARFDataInstanceHelper dihUtil =
			new DWARFDataInstanceHelper(context.getDataTypeMapper().getProgram());
		if (!dihUtil.isDataTypeCompatibleWithAddress(context.getStructureDataType(),
			structStartAddr)) {
			return false;
		}

		long maxValidLen =
			charValidRange.getMaxAddress().subtract(charDataRange.getMinAddress()) - 1;
		if (len > maxValidLen) {
			return false;
		}
		if (!isCompatibleCharDataType(charDataRange.getMinAddress())) {
			return false;
		}
		if (hasOffcutReferences(charDataRange)) {
			return false;
		}

		String stringValue = getStringValue();
		if (!stringContentValidator.test(stringValue)) {
			return false;
		}

		return true;
	}

	private boolean hasOffcutReferences(AddressRange charDataRange) {
		AddressIterator it = context.getDataTypeMapper()
				.getProgram()
				.getReferenceManager()
				.getReferenceDestinationIterator(new AddressSet(charDataRange), true);
		Address refAddr = it.hasNext() ? it.next() : null;
		if (refAddr != null && refAddr.equals(charDataRange.getMinAddress())) {
			refAddr = it.hasNext() ? it.next() : null;
		}
		return refAddr != null;
	}

	private boolean isCompatibleCharDataType(Address charDataAddr) {
		DataType stringCharDataType = getStringCharDataType();
		DWARFDataInstanceHelper dihUtil =
			new DWARFDataInstanceHelper(context.getDataTypeMapper().getProgram());
		return dihUtil.isDataTypeCompatibleWithAddress(stringCharDataType, charDataAddr);
	}

	/**
	 * Returns true if this string instance points to valid char[] data.
	 * 
	 * @param charValidRange addresses that are valid locations for a string's char[] data 
	 * @param stringContentValidator a callback that will test a recovered string for validity
	 * @return boolean true if valid string, false if not valid string
	 * @throws IOException if error reading data
	 */
	public boolean isValidInlineString(AddressSetView charValidRange,
			Predicate<String> stringContentValidator) throws IOException {
		if (len <= 0 || len > MAX_SANE_STR_LEN) {
			return false;
		}

		Address charStart = getStringAddr();

		try {
			Address charEnd = charStart.addNoWrap(len - 1);
			if (!charValidRange.contains(charStart) || !charValidRange.contains(charEnd)) {
				// TODO: maybe change check to ensure both ends of char array are in same contiguous block
				return false;
			}
		}
		catch (AddressOverflowException e) {
			return false;
		}

		long maxValidLen = charValidRange.getMaxAddress().subtract(charStart) - 1;
		if (len > maxValidLen) {
			return false;
		}
		if (!isCompatibleCharDataType(charStart)) {
			return false;
		}

		String stringValue = getStringValue();
		if (!stringContentValidator.test(stringValue)) {
			return false;
		}

		return true;
	}

	@Override
	public String getStructureLabel() throws IOException {
		return StringDataInstance.makeStringLabel("gostr_", getStringValue(),
			DataTypeDisplayOptions.DEFAULT);
	}

	@Override
	public StructureContext<GoString> getStructureContext() {
		return context;
	}

	@Override
	public void additionalMarkup(MarkupSession session) throws IOException {
		session.markupAddress(getStringAddr(), getStringCharDataType());
	}
}
