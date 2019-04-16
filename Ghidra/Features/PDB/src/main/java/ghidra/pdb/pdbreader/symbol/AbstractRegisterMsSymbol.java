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
 * This class represents various flavors of Register symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractRegisterMsSymbol extends AbstractMsSymbol {

	protected AbstractTypeIndex typeIndex;
	protected RegisterName register;
	protected AbstractString name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractRegisterMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		typeIndex.parse(reader);
		pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA, typeIndex.get()));
		pdb.popDependencyStack();
		register = parseRegister(reader);
		name.parse(reader);
		reader.align4();
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		builder.append(": ");
		emitRegisterInformation(builder);
		builder.append(", Type: ");
		builder.append(pdb.getTypeRecord(typeIndex.get()));
		builder.append(", ");
		builder.append(name);
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #typeIndex} and {@link #name}.
	 */
	protected abstract void create();

	/**
	 * Parses the register field for this symbol.
	 * @param reader {@link PdbByteReader} from which the data is parsed.
	 * @return The register field.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract RegisterName parseRegister(PdbByteReader reader) throws PdbException;

	/**
	 * Emits the register information to the {@link StringBuilder}
	 * @param builder {@link StringBuilder} to which the data is emitted.
	 */
	protected abstract void emitRegisterInformation(StringBuilder builder);

}
