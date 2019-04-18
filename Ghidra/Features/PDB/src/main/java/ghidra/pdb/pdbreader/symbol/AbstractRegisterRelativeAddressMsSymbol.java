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
 * This class represents various flavors of Register Relative Address symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractRegisterRelativeAddressMsSymbol extends AbstractMsSymbol {

	protected AbstractOffset offset;
	protected AbstractTypeIndex typeIndex;
	protected int registerIndex;
	protected RegisterName registerName;
	protected AbstractString name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractRegisterRelativeAddressMsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		create();
		parse(reader);
		registerName = new RegisterName(pdb, registerIndex);
		pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA, typeIndex.get()));
		pdb.popDependencyStack();
	}

	/**
	 * Returns the offset.
	 * @return Offset.
	 */
	public long getOffset() {
		return offset.get();
	}

	/**
	 * Returns the type index.
	 * @return Type index.
	 */
	public int getTypeIndex() {
		return typeIndex.get();
	}

	/**
	 * Returns the register index.
	 * @return Register index.
	 */
	public int getRegisterIndex() {
		return registerIndex;
	}

	/**
	 * Returns the register name.
	 * @return Register name.
	 */
	public String getRegisterNameString() {
		return registerName.toString();
	}

	/**
	 * Returns the name.
	 * @return Name.
	 */
	public String getName() {
		return name.get();
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: %s+%08X, Type: %s, %s", getSymbolTypeName(),
			registerName.toString(), offset.get(), pdb.getTypeRecord(typeIndex.get()), name.get()));
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #offset}, {@link #typeIndex}, and {@link #name}.
	 */
	protected abstract void create();

	/**
	 * Parsed the object's fields
	 * <P>
	 * Implementing class must, in the appropriate order pertinent to itself, parse
	 * {@link #offset}, {@link #registerIndex}, {@link #typeIndex}, and {@link #name}.
	 * @param reader {@link PdbByteReader} from which the fields are parsed.
	 * @throws PdbException upon error parsing a field.
	 */
	protected abstract void parse(PdbByteReader reader) throws PdbException;

}
