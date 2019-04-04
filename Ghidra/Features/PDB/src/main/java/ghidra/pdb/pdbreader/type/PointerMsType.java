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

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.*;

public class PointerMsType extends AbstractPointerMsType {

	public static final int PDB_ID = 0x1002;

	private boolean isRestrict;
	private int size;
	private boolean isMocom;
	private boolean isLRef;
	private boolean isRRef;

	//TODO: There is a bit set beyond this in the following data
	//000000 74 00 00 00 4c 00 00 00 1c 49 00 00 00 00 f2 f1
	// The attributes long is 00 00 4c 00. The bit on the 4 is what is unknown.
	private boolean unk;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public PointerMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isRestrict() {
		return isRestrict;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isMocom() {
		return isMocom;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isLeftReference() {
		return isLRef;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isRightReference() {
		return isRRef;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isUnknownAttributes() {
		return unk;
	}

	@Override
	public int getSize() {
		return size;
	}

	@Override
	protected void create() {
		underlyingTypeIndex = new TypeIndex32();
		memberPointerContainingClassIndex = new TypeIndex32();
		baseSymbol = new StringNt();
		name = new StringNt();
	}

	@Override
	protected void parsePointerBody(PdbByteReader reader) throws PdbException {
		underlyingTypeIndex.parse(reader);
		parseAttributes(reader);
	}

	@Override
	protected void parseAttributes(PdbByteReader reader) throws PdbException {
		long attributes = reader.parseUnsignedIntVal();
		pointerTypeAttribute = (int) (attributes & 0x001f);
		attributes >>= 5;
		pointerModeAttribute = (int) (attributes & 0x0007);
		attributes >>= 3;

		isFlat = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		isVolatile = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		isConst = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		isUnaligned = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		isRestrict = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;

		size = (int) (attributes & 0x003f);
		attributes >>= 6;

		isMocom = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		isLRef = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		isRRef = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		unk = ((attributes & 0x0001) == 0x0001);
	}

	@Override
	protected int getMySize() {
		return 4;
	}

}
