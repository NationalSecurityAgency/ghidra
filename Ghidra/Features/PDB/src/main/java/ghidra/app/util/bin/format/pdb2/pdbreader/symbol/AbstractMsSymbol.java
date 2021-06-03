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
package ghidra.app.util.bin.format.pdb2.pdbreader.symbol;

import java.util.Objects;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This is the abstract class for PDB Symbol units.
 * <P>
 * The leaves in the {@link AbstractMsSymbol} hierarchy generally end in one of the following,
 *  which <B>generally</B> have the differences noted here:
 *  <UL>
 *  <LI> 16MsSymbol
 *  <UL>
 *  <LI> Uses 16-bit integers for fields such as type record numbers </LI>
 *  <LI> Uses 16-bit integers for offsets </LI>
 *  <LI> Uses {@link StringParseType#StringSt} </LI>
 *  </UL>
 *  <LI> StMsSymbol and 32StMsSymbol (not sure what <B>ST</B> means in MSFT parlance)
 *  <UL>
 *  <LI> Uses 32-bit integers for fields such as type record numbers </LI>
 *  <LI> Uses 16-bit integers for offsets </LI>
 *  <LI> Uses {@link StringParseType#StringSt} </LI>
 *  </UL>
 *  <LI> 3216MsSymbol
 *  <UL>
 *  <LI> Uses 16-bit integers for fields such as type record numbers </LI>
 *  <LI> Uses 32-bit integers for offsets </LI>
 *  <LI> Uses {@link StringParseType#StringNt}, {@link StringParseType#StringUtf8Nt}, or
 *   {@link StringParseType#StringWcharNt}/LI>
 *  </UL>
 *  <LI> MsSymbol or 32MsSymbol
 *  <UL>
 *  <LI> Uses 32-bit integers for fields such as type record numbers </LI>
 *  <LI> Uses 32-bit integers for offsets </LI>
 *  <LI> Uses {@link StringParseType#StringNt}, {@link StringParseType#StringUtf8Nt}, or
 *   {@link StringParseType#StringWcharNt}/LI>
 *  </UL>
 *  </UL>
 * <P>
 * Many/most of the symbol types have a {@code create()} method used to create the appropriate
 * versions of the above components.  These components then get parsed during deserialization.
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 * <P>
 * To track back to the documented API, search the above URL for where the documentation is
 *  located as "code."  Use the value of the PDB_ID for any class derived from this class to
 *  search the API code, being careful to look for symbol types instead of data types.  (Note
 *  that "PDB_ID" is not API terminology.)  Once found, you can use the defined label to find
 *  the structure that describes the layout of the serialized data; searching for that structure
 *  name can sometimes lead to methods that output information about these structures (a buffer
 *  pointer is cast to the structure pointer, leading to the ability to interpret the fields).
 *  <P>
 *  Enjoy!!!
 */
public abstract class AbstractMsSymbol extends AbstractParsableItem {
	// The following commented-out code is used when trying to discern which SYMBOL types were
	//  not yet implemented.
	//private static final Class[] parameterTypes = { StringBuilder.class };
	protected AbstractPdb pdb;

	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 */
	AbstractMsSymbol(AbstractPdb pdb, PdbByteReader reader) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
		// The following commented-out code is used when trying to discern which SYMBOL types were
		//  not yet implemented.

//		// Discern whether the derived class is implemented based upon whether it overrides "emit"
//		try {
//			if (this.getClass().getMethod("emit",
//				parameterTypes).getDeclaringClass() == AbstractMsSymbol.class) {
//				//System.out.println(this.getClass().getSimpleName());
//              //System.out.println(reader.dump(0x200));
//			}
//		}
//		catch (NoSuchMethodException e) {
//			System.out.println("No emit method");
//		}
	}

	/**
	 * Returns the unique ID (PdbId) for this symbol type.
	 * @return Identifier for this symbol type.
	 */
	public abstract int getPdbId();

	@Override
	public void emit(StringBuilder builder) {
		builder.append("NotImplemented(" + this.getClass().getSimpleName() + ")");
	}

	/**
	 * Returns the String representation of the symbol type name, per API.
	 * @return String name.
	 */
	protected abstract String getSymbolTypeName();

}
