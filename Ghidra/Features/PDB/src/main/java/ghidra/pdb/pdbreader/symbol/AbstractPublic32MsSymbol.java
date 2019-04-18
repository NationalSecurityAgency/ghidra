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
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractPublic32MsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
	}

	@Override
	public long getOffset() {
		return ((AbstractPublicSymbolInternals32) internals).getOffset();
	}

	@Override
	public int getSegment() {
		return ((AbstractPublicSymbolInternals32) internals).getSegment();
	}

	@Override
	public String getName() {
		return ((AbstractPublicSymbolInternals32) internals).getName();
	}

	public long getFlags() {
		return ((AbstractPublicSymbolInternals32) internals).getFlags();
	}

	public boolean isCode() {
		return ((AbstractPublicSymbolInternals32) internals).isCode();
	}

	public boolean isFunction() {
		return ((AbstractPublicSymbolInternals32) internals).isFunction();
	}

	public boolean isManaged() {
		return ((AbstractPublicSymbolInternals32) internals).isManaged();
	}

	public boolean isMicrosoftIntermediateLanguage() {
		return ((AbstractPublicSymbolInternals32) internals).isMicrosoftIntermediateLanguage();
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		internals.emit(builder);
	}

}
