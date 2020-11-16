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
 * This class represents various flavors of Derived Class List type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractDerivedClassListMsType extends AbstractMsType {

	protected List<RecordNumber> recordNumbers;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @param intSize size of count and record number to parse.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractDerivedClassListMsType(AbstractPdb pdb, PdbByteReader reader, int intSize)
			throws PdbException {
		super(pdb, reader);
		recordNumbers = new ArrayList<>();
		int count = reader.parseVarSizedCount(intSize);
		for (int i = 0; i < count; i++) {
			RecordNumber aRecordNumber =
				RecordNumber.parse(pdb, reader, RecordCategory.TYPE, intSize);
			recordNumbers.add(aRecordNumber);
		}
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		DelimiterState ds = new DelimiterState("", ", ");
		for (RecordNumber aRecordNumber : recordNumbers) {
			AbstractMsType type = pdb.getTypeRecord(aRecordNumber);
			builder.append(ds.out(true, type.toString()));
		}
	}

}
