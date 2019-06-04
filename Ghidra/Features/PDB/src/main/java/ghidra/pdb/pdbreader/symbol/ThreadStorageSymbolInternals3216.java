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
package ghidra.pdb.pdbreader.symbol;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.*;

/**
 * This class represents <B>3216</B> Internals of the Thread Storage symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class ThreadStorageSymbolInternals3216 extends AbstractThreadStorageSymbolInternals {

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public ThreadStorageSymbolInternals3216(AbstractPdb pdb) {
		super(pdb);
	}

	@Override
	protected void create() {
		typeIndex = new TypeIndex16();
		offset = new Offset32();
		name = new StringUtf8St(pdb);
	}

	@Override
	public void parse(PdbByteReader reader) throws PdbException {
		offset.parse(reader);
		segment = reader.parseUnsignedShortVal();
		typeIndex.parse(reader);
		name.parse(reader);
		reader.align4();
	}

}
