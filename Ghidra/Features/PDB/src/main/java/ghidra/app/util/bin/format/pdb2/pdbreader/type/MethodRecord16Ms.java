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
 * This class represents the <B>16MsType</B> flavor of Method Records.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class MethodRecord16Ms extends AbstractMethodRecordMs {

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public MethodRecord16Ms(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		attributes = new ClassFieldMsAttributes(reader);
		procedureRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 16);
		// See comment in MethodRecordMs... we are adding INTRO_PURE as it might also occur, and
		//  there should be no harm on doing this
		if (attributes.getProperty() == ClassFieldMsAttributes.Property.INTRO ||
			attributes.getProperty() == ClassFieldMsAttributes.Property.INTRO_PURE) {
			optionalOffset = reader.parseUnsignedIntVal();
		}
		else {
			optionalOffset = -1;
		}
	}

}
