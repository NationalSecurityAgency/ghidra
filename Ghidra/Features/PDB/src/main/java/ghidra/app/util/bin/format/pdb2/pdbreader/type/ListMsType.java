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

import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbByteReader;

/**
 * This class represents the <B>MsType</B> flavor of List type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class ListMsType extends AbstractMsType {

	public static final int PDB_ID = 0x0203;

	private byte[] data;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 */
	public ListMsType(AbstractPdb pdb, PdbByteReader reader) {
		super(pdb, reader);
		data = reader.parseBytesRemaining();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// There is no documented API.
		builder.append(
			String.format("<<%s dataLength=%d>>", getClass().getSimpleName(), data.length));
	}

}
