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
import ghidra.pdb.pdbreader.AbstractPdb;
import ghidra.pdb.pdbreader.StringUtf8Nt;

/**
 * This class represents <B>2</B> Internals of the Reference symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class ReferenceSymbolInternals2 extends AbstractReferenceSymbolInternals {

	protected StringUtf8Nt name; // Hidden name made into a first class member?

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public ReferenceSymbolInternals2(AbstractPdb pdb) {
		super(pdb);
	}

	/**
	 * Returns the name field of this symbol internals.
	 * @return the name.
	 */
	public String getName() {
		return name.get();
	}

	@Override
	public void emit(StringBuilder builder) {
		super.emit(builder);
		builder.append(" ");
		builder.append(name.get());
	}

	@Override
	protected void create() {
		name = new StringUtf8Nt(pdb);
	}

	@Override
	public void parse(PdbByteReader reader) throws PdbException {
		sumName = reader.parseUnsignedIntVal();
		offsetActualSymbolInDollarDollarSymbols = reader.parseUnsignedIntVal();
		moduleIndex = reader.parseUnsignedShortVal();
		name.parse(reader);
		reader.align4();
	}

}
