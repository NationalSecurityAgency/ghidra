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
 * This class represents the <B>16MsType</B> flavor of Virtual Base Class type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class VirtualBaseClass16MsType extends AbstractVirtualBaseClassMsType {

	public static final int PDB_ID = 0x0401;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public VirtualBaseClass16MsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		directVirtualBaseClassRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 16);
		virtualBasePointerRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 16);
		attribute = new ClassFieldMsAttributes(reader);
		//TODO: Check this
		Numeric numeric = new Numeric(reader);
		if (!numeric.isIntegral()) {
			throw new PdbException("Expecting integral numeric");
		}
		virtualBasePointerOffsetFromAddressPoint = numeric.getIntegral();
		numeric = new Numeric(reader);
		if (!numeric.isIntegral()) {
			throw new PdbException("Expecting integral numeric");
		}
		virtualBaseOffsetFromVBTable = numeric.getIntegral();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

}
