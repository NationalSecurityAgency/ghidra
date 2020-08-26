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

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents various flavors of Skip type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractSkipMsType extends AbstractMsType {

	protected RecordNumber nextValidRecordNumber;
	protected int recordLength;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @param recordNumberSize size of record number to parse.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractSkipMsType(AbstractPdb pdb, PdbByteReader reader, int recordNumberSize)
			throws PdbException {
		super(pdb, reader);
		nextValidRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		recordLength = reader.getLimit() - reader.getIndex();
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		builder.append(String.format("Skip Record, nextValidTypeIndex = 0x%x, Length = 0x%x",
			nextValidRecordNumber.getNumber(), recordLength));
	}

}
