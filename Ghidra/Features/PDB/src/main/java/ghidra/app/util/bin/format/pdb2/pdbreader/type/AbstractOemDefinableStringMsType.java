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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents various flavors of OEM Definable String type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractOemDefinableStringMsType extends AbstractMsType {

	protected int msAssignedOEMIdentifier;
	protected int oemAssignedTypeIdentifier;
	protected List<RecordNumber> recordNumbers;
	protected byte[] remainingBytes;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @param intSize size of count and record number to parse.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractOemDefinableStringMsType(AbstractPdb pdb, PdbByteReader reader, int intSize)
			throws PdbException {
		super(pdb, reader);
		msAssignedOEMIdentifier = reader.parseUnsignedShortVal();
		oemAssignedTypeIdentifier = reader.parseUnsignedShortVal();
		recordNumbers = new ArrayList<>();
		int count = reader.parseVarSizedCount(intSize);
		for (int i = 0; i < count; i++) {
			RecordNumber aRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, intSize);
			recordNumbers.add(aRecordNumber);
		}
		//TODO: We do not know what "OEM-defined" data remains.  For now, just grabbing rest.
		remainingBytes = reader.parseBytesRemaining();
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		builder.append("OEM Definable String\n");
		builder.append(
			String.format("  MSFT-assigned OEM Identifier: %s\n", msAssignedOEMIdentifier));
		builder.append(String.format("  OEM-assigned Identifier: %s\n", oemAssignedTypeIdentifier));
		builder.append(String.format("  count: %d\n", recordNumbers.size()));
		for (int i = 0; i < recordNumbers.size(); i++) {
			builder.append(String.format("    recordNumber[%d]: 0x%08x\n", i,
				recordNumbers.get(i).getNumber()));
		}
		builder.append(String.format("  additional data length: %d\n", remainingBytes.length));
	}

}
