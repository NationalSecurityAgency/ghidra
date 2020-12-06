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

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents various similar, newer flavors of Public symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractPublic32MsSymbol extends AbstractPublicMsSymbol {

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @param internals the internal structure to be used for this symbol.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractPublic32MsSymbol(AbstractPdb pdb, PdbByteReader reader,
			PublicSymbolInternals32 internals) throws PdbException {
		super(pdb, reader, internals);
	}

	@Override
	public long getOffset() {
		return ((PublicSymbolInternals32) internals).getOffset();
	}

	@Override
	public int getSegment() {
		return ((PublicSymbolInternals32) internals).getSegment();
	}

	@Override
	public String getName() {
		return ((PublicSymbolInternals32) internals).getName();
	}

	public long getFlags() {
		return ((PublicSymbolInternals32) internals).getFlags();
	}

	public boolean isCode() {
		return ((PublicSymbolInternals32) internals).isCode();
	}

	public boolean isFunction() {
		return ((PublicSymbolInternals32) internals).isFunction();
	}

	public boolean isManaged() {
		return ((PublicSymbolInternals32) internals).isManaged();
	}

	public boolean isMicrosoftIntermediateLanguage() {
		return ((PublicSymbolInternals32) internals).isMicrosoftIntermediateLanguage();
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		internals.emit(builder);
	}

}
