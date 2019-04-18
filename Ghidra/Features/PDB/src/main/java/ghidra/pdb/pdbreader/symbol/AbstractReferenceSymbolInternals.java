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
import ghidra.pdb.pdbreader.AbstractPdb;

/**
 * This class represents various flavors of Internals of Reference symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractReferenceSymbolInternals extends AbstractSymbolInternals {

	/**
	 * Implementing class's {@link #parse(PdbByteReader)} method must parse {@link #sumName},
	 * {@link #offsetActualSymbolInDollarDollarSymbols}, and {@link #moduleIndex}.
	 */
	protected long sumName; // Says SUC of the name???
	protected long offsetActualSymbolInDollarDollarSymbols;
	protected int moduleIndex;

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public AbstractReferenceSymbolInternals(AbstractPdb pdb) {
		super(pdb);
	}

	/**
	 * Returns "sum" (or "suc" or ?) name.
	 * @return Name.
	 */
	public long getSumName() {
		return sumName;
	}

	/**
	 * Returns the actual offset in $$symbol.
	 * @return Actual offset in $$symbol.
	 */
	public long getOffsetActualSymbolInDollarDollarSymbols() {
		return offsetActualSymbolInDollarDollarSymbols;
	}

	/**
	 * Returns the module index.
	 * @return Module index.
	 */
	public int getModuleIndex() {
		return moduleIndex;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format(": %08X: (%4d, %08X)", sumName, moduleIndex,
			offsetActualSymbolInDollarDollarSymbols));
	}

}
