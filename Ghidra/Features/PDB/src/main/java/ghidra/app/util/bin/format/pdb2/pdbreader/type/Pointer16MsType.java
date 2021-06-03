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
 * This class represents the <B>16MsType</B> flavor of Pointer type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class Pointer16MsType extends AbstractPointerMsType {

	public static final int PDB_ID = 0x0002;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public Pointer16MsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		parseAttributes(reader);
		underlyingRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 16);
		parseExtendedPointerInfo(reader, 16, StringParseType.StringSt);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	protected void parseAttributes(PdbByteReader reader) throws PdbException {
		int attributes1 = reader.parseUnsignedByteVal();
		int attributes2 = reader.parseUnsignedByteVal();
		pointerType = PointerType.fromValue(attributes1 & 0x001f);
		attributes1 >>= 5;
		pointerMode = PointerMode.fromValue(attributes1 & 0x0007);

		isFlat = ((attributes2 & 0x0001) == 0x0001);
		attributes2 >>= 1;
		isVolatile = ((attributes2 & 0x0001) == 0x0001);
		attributes2 >>= 1;
		isConst = ((attributes2 & 0x0001) == 0x0001);
		attributes2 >>= 1;
		isUnaligned = ((attributes2 & 0x0001) == 0x0001);
	}

	@Override
	protected int getMySize() {
		return 2;
	}

}
