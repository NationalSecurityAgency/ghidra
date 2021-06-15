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
 * This class represents the Annotation symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class AnnotationMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x1019;

	private long offset;
	private int segment;
	private List<String> annotationStringList = new ArrayList<>();

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field or unexpected data.
	 */
	public AnnotationMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		offset = reader.parseUnsignedIntVal();
		segment = pdb.parseSegment(reader);
		int count = reader.parseUnsignedShortVal();
		for (int i = 0; i < count; i++) {
			String string = reader.parseString(pdb, StringParseType.StringUtf8Nt);
			annotationStringList.add(string);
		}
		if (annotationStringList.size() != count) {
			throw new PdbException("We are not expecting this--needs investigation");
		}
		reader.align4();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: [%04X:%08X]\n", getSymbolTypeName(), segment, offset));
		int count = 0;
		for (String string : annotationStringList) {
			builder.append(String.format("%5d: %s\n", count++, string));
		}
	}

	@Override
	protected String getSymbolTypeName() {
		return "ANNOTATION";
	}

}
