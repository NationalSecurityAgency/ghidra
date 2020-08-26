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
 * This class represents the <B>MsType</B> flavor of Label type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class LabelMsType extends AbstractMsType {

	public static final int PDB_ID = 0x000e;

	private static final int ADDRESS_MODE_NEAR = 0;
	private static final int ADDRESS_MODE_FAR = 4;

	private int mode;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public LabelMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		mode = reader.parseUnsignedShortVal();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Tells whether if is a near address.
	 * @return True if it is a near address.
	 */
	public boolean isNear() {
		return (mode == ADDRESS_MODE_NEAR);
	}

	/**
	 * Tells whether it is a far address.
	 * @return True if it is a far address.
	 */
	public boolean isFar() {
		return (mode == ADDRESS_MODE_FAR);
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// There is no documented API.
		builder.append("<<" + getClass().getSimpleName() + (isNear() ? " near" : "") +
			(isFar() ? " far" : "") + ">>");
	}

}
