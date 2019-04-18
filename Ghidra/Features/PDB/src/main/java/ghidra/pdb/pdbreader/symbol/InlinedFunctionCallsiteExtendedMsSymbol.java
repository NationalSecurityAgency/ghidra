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
package ghidra.pdb.pdbreader.symbol;

import java.util.ArrayList;
import java.util.List;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.AbstractPdb;
import ghidra.pdb.pdbreader.CategoryIndex;

/**
 * This class represents the Inlined Function Callsite Extended symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class InlinedFunctionCallsiteExtendedMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x115d;

	private long pointerToInliner;
	private long pointerToThisBlockEnd;
	private int inlineeIndex;
	private long invocationsCount;
	private List<InstructionAnnotation> binaryAnnotationOpcodeList = new ArrayList<>();

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public InlinedFunctionCallsiteExtendedMsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		pointerToInliner = reader.parseUnsignedIntVal();
		pointerToThisBlockEnd = reader.parseUnsignedIntVal();
		inlineeIndex = reader.parseInt();
		pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.ITEM, inlineeIndex));
		pdb.popDependencyStack();
		invocationsCount = reader.parseUnsignedIntVal();
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

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		builder.append(String.format(
			": Parent: %08X,  End: %08X, PGO Edge Count: %d, Inlinee: %s\n", pointerToInliner,
			pointerToThisBlockEnd, invocationsCount, pdb.getItemRecord(inlineeIndex)));
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
