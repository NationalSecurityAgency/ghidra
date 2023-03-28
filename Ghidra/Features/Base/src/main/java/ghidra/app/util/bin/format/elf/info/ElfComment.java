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
package ghidra.app.util.bin.format.elf.info;

import java.util.ArrayList;
import java.util.List;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.StringUTF8DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

/**
 * An Elf section that contains null-terminated strings, typically added by the compiler to
 * the binary
 */
public class ElfComment implements ElfInfoItem {

	public static final String SECTION_NAME = ".comment";

	/**
	 * Reads an ElfComment from the standard ".comment" section in the specified Program.
	 * 
	 * @param program Program to read from
	 * @return new instance, or null if not found or data error
	 */
	public static ElfComment fromProgram(Program program) {
		ItemWithAddress<ElfComment> wrappedItem = ElfInfoItem.readItemFromSection(program,
			SECTION_NAME, ElfComment::read);
		return wrappedItem != null ? wrappedItem.item() : null;
	}

	/**
	 * Reads a ElfComment from the specified BinaryReader.
	 * 
	 * @param br BinaryReader to read from
	 * @param program unused, present to match the signature of {@link ElfInfoItem.ReaderFunc}
	 * @return new instance, or null if data error
	 */
	public static ElfComment read(BinaryReader br, Program program) {
		try {
			List<String> commentStrings = new ArrayList<>();
			List<Integer> commentStringLengths = new ArrayList<>();
			while (br.hasNext()) {
				long start = br.getPointerIndex();
				String str = br.readNextUtf8String();
				commentStrings.add(str);
				commentStringLengths.add((int) (br.getPointerIndex() - start));
			}
			return new ElfComment(commentStrings, commentStringLengths);
		}
		catch (IOException e) {
			// fall thru and return null
		}
		return null;
	}

	private final List<String> commentStrings;
	private final List<Integer> commentStringLengths; // retain original string lengths so we can correctly markup memory

	public ElfComment(List<String> commentStrings, List<Integer> commentStringLengths) {
		this.commentStrings = commentStrings;
		this.commentStringLengths = commentStringLengths;
	}

	public List<String> getCommentStrings() {
		return commentStrings;
	}

	@Override
	public void markupProgram(Program program, Address address) {
		try {
			Options progInfo = program.getOptions(Program.PROGRAM_INFO);
			SymbolTable symTable = program.getSymbolTable();

			for (int commentNum = 0; commentNum < commentStrings.size(); commentNum++) {
				String commentStr = commentStrings.get(commentNum);
				Integer strLen = commentStringLengths.get(commentNum);

				progInfo.setString("Elf Comment[%d]".formatted(commentNum), commentStr);
				symTable.createLabel(address, "ElfComment[%d]".formatted(commentNum),
					SourceType.IMPORTED);
				DataUtilities.createData(program, address, StringUTF8DataType.dataType, strLen,
					false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
				address = address.addWrap(strLen); // need to allow wrap so we don't error when hitting end-of-section
			}
		}
		catch (CodeUnitInsertionException | InvalidInputException e) {
			Msg.error(this, "Failed to markup ElfComment at %s: %s".formatted(address, this));
		}

	}

	@Override
	public String toString() {
		return String.format("ElfComment [commentStrings=%s]", commentStrings);
	}

}
