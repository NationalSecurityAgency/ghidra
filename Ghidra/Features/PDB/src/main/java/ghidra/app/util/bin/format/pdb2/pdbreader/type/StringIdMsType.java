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
import ghidra.util.Msg;

/**
 * This class represents the <B>MsType</B> flavor of String ID type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class StringIdMsType extends AbstractMsType {

	public static final int PDB_ID = 0x1605;

	private RecordNumber substringIdListRecordNumber;
	private String name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a string.
	 */
	public StringIdMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		substringIdListRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.ITEM, 32);
		name = reader.parseString(pdb, StringParseType.StringNt);
		reader.skipPadding();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the complete string, which would include portions concatenated from underlying
	 *  substrings.
	 * @return the complete string.
	 * @see #getStringPortion()
	 */
	public String getString() {
		StringBuilder builder = new StringBuilder();
		buildString(builder);
		return builder.toString();
	}

	/**
	 * Returns the string portion contained in this record.
	 * @return the string portion.
	 * @see #getString()
	 */
	public String getStringPortion() {
		return name;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		buildString(builder);
	}

	private void buildString(StringBuilder builder) {
		//TODO: could be wrong (including how substrings are concatenated and added), but it
		// appears to work correctly like this.
		if (substringIdListRecordNumber != RecordNumber.NO_TYPE) {
			AbstractMsType subStringList = pdb.getTypeRecord(substringIdListRecordNumber);
			if (!(subStringList instanceof SubstringListMsType)) {
				String message = "Expected SubstringListMsType, but found " +
					subStringList.getClass().getSimpleName();
				Msg.info(this, message);
				PdbLog.message(message);
				return;
			}
			builder.append(subStringList);

		}
		// The API shows this as an else on the 'if' and I found a symbol which would get
		//  truncated without this as a stand-alone statement.  MSFT appears to be wrong
		//  in their handling of the PDB here.
		// Example is from build1264_Z7/cn3.pdb in testPdbTPI800UsingAutoClose_1().
		builder.append(name);
	}
}
