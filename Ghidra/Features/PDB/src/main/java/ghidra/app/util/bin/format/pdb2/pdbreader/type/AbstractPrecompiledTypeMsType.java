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
 * This class represents various flavors of Precompiled type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractPrecompiledTypeMsType extends AbstractMsType {

	// TODO: not if this is a record number (type index) or something else; doc not CV_TYP.
	protected RecordNumber startRecordNumber;
	protected long count;
	protected long signature;
	protected String name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @param intSize size of count and record number to parse.
	 * @param strType {@link StringParseType} to use.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractPrecompiledTypeMsType(AbstractPdb pdb, PdbByteReader reader, int intSize,
			StringParseType strType) throws PdbException {
		super(pdb, reader);
		startRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, intSize);
		count = reader.parseVarSizedUInt(intSize);
		signature = reader.parseUnsignedIntVal();
		name = reader.parseString(pdb, strType);
	}

	// Note: MSFT output API not documented.
	@Override
	public void emit(StringBuilder builder, Bind bind) {
		builder.append(String.format("Precompiled: signature=0X%08X, name=%s, start=%s, count=%d",
			signature, name, pdb.getTypeRecord(startRecordNumber).toString(), count));
	}

}
