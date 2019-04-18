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
 * This class represents various flavors of Virtual Function Table symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractVirtualFunctionTableMsSymbol extends AbstractMsSymbol {

	protected AbstractTypeIndex rootTypeIndex;
	protected AbstractTypeIndex pathTypeIndex;
	protected AbstractOffset offset;
	protected int segment;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractVirtualFunctionTableMsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		create();
		parse(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, pathTypeIndex.get()));
		pdb.popDependencyStack();
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, rootTypeIndex.get()));
		pdb.popDependencyStack();
	}

	@Override
	public void emit(StringBuilder builder) {
		// TODO: determine correct order for root and path
		builder.append(String.format("%s: [%04X:%08X], %s:%s", getSymbolTypeName(), segment,
			offset.get(), pdb.getTypeRecord(pathTypeIndex.get()).toString(),
			pdb.getTypeRecord(rootTypeIndex.get()).toString()));
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #offset}, {@link #rootTypeIndex}, and
	 * {@link #pathTypeIndex}.
	 */
	protected abstract void create();

	/**
	 * Parses this symbol.
	 * <P>
	 * Implementing class must, in the appropriate order pertinent to itself, parse
	 * {@link #offset}, {@link #rootTypeIndex}, {@link #pathTypeIndex}, and {@link #segment}.
	 * @param reader {@link PdbByteReader} from which the data is parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parse(PdbByteReader reader) throws PdbException;

}
