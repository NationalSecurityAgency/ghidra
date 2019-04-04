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
package ghidra.pdb.pdbreader.type;

import java.util.List;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.AbstractPdb;
import ghidra.pdb.pdbreader.AbstractTypeIndex;

public abstract class AbstractOemDefinableStringMsType extends AbstractMsType {

	protected int msAssignedOEMIdentifier;
	protected int oemAssignedTypeIdentifier;
	protected List<AbstractTypeIndex> typeIndexList;
	protected byte[] remainingBytes;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractOemDefinableStringMsType(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		msAssignedOEMIdentifier = reader.parseUnsignedShortVal();
		oemAssignedTypeIdentifier = reader.parseUnsignedShortVal();
		typeIndexList = parseTypeIndexList(reader);
		//TODO: We do not know what "OEM-defined" data remains.  For now, just grabbing rest.
		remainingBytes = reader.parseBytesRemaining();
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		builder.append("OEM Definable String\n");
		builder.append(
			String.format("  MSFT-assigned OEM Identifier: %s\n", msAssignedOEMIdentifier));
		builder.append(String.format("  OEM-assigned Identifier: %s\n", oemAssignedTypeIdentifier));
		builder.append(String.format("  count: %d\n", typeIndexList.size()));
		for (int i = 0; i < typeIndexList.size(); i++) {
			builder.append(
				String.format("    typeIndex[%d]: 0x%08x\n", i, typeIndexList.get(i).get()));
		}
		builder.append(String.format("  additional data length: %d\n", remainingBytes.length));
	}

	/**
	 * Parses the Type Index List.
	 * @param reader {@link PdbByteReader} that is deserialized.
	 * @return Type indices.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract List<AbstractTypeIndex> parseTypeIndexList(PdbByteReader reader)
			throws PdbException;

}
