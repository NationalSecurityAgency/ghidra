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
package ghidra.app.util.bin.format.pdb2.pdbreader.symbol;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents the Inlined Function Callsite symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class InlinedFunctionCallsiteMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x114d;

	private long pointerToInliner;
	private long pointerToThisBlockEnd;
	private RecordNumber inlineeRecordNumber;
	private List<InstructionAnnotation> binaryAnnotationOpcodeList = new ArrayList<>();

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public InlinedFunctionCallsiteMsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		pointerToInliner = reader.parseUnsignedIntVal();
		pointerToThisBlockEnd = reader.parseUnsignedIntVal();
		// TODO: eventually change to parse() after we figure out what is going on with high bit
		// fixup.  Seems to point to incorrect data.
		inlineeRecordNumber = RecordNumber.parseNoWitness(pdb, reader, RecordCategory.ITEM, 32);
		while (reader.hasMore()) {
			InstructionAnnotation instruction = new InstructionAnnotation(reader);
			if (instruction.getInstructionCode() != InstructionAnnotation.Opcode.INVALID) {
				binaryAnnotationOpcodeList.add(instruction);
			}
		}
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the pointer to inliner.
	 * @return Pointer to inliner.
	 */
	public long getPointerToInliner() {
		return pointerToInliner;
	}

	/**
	 * Returns the pointer to this block end.
	 * @return Pointer to this block end.
	 */
	public long getPointerToThisBlockEnd() {
		return pointerToThisBlockEnd;
	}

	/**
	 * Returns inlinee record number.
	 * @return Inlinee record number.
	 */
	public RecordNumber getInlineeRecordNumber() {
		return inlineeRecordNumber;
	}

	/**
	 * Returns {@link List}&lt;{@link InstructionAnnotation}&gt;.
	 * @return Instruction annotations.
	 */
	public List<InstructionAnnotation> getBinaryAnnotationOpcodeList() {
		return binaryAnnotationOpcodeList;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		builder.append(String.format(": Parent: %08X,  End: %08X, Inlinee: %s\n", pointerToInliner,
			pointerToThisBlockEnd, pdb.getTypeRecord(inlineeRecordNumber)));
		int count = 0;
		for (InstructionAnnotation instruction : binaryAnnotationOpcodeList) {
			if (count++ == 4) {
				builder.append("\n");
				count = 0;
			}
			builder.append(instruction);
		}
	}

	@Override
	protected String getSymbolTypeName() {
		return "INLINESITE2";
	}

}
