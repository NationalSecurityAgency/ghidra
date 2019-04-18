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
 * This class represents various flavors of Constant symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractConstantMsSymbol extends AbstractMsSymbol {

	protected AbstractTypeIndex typeIndex;
	protected int value;
	protected AbstractString name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractConstantMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		typeIndex.parse(reader);
		value = reader.parseUnsignedShortVal();
		name.parse(reader);
	}

	/**
	 * Returns the type index.
	 * @return Type index.
	 */
	public long getTypeIndex() {
		return typeIndex.get();
	}

	/**
	 * Returns the value.
	 * @return Value.
	 */
	public int getValue() {
		return value;
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
		builder.append(getSymbolTypeName());
		builder.append(": Type: ");
		builder.append(pdb.getTypeRecord(typeIndex.get()).toString());
		builder.append(", Value: ");
		builder.append(value);
		builder.append(", ");
		builder.append(name);
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #typeIndex} and {@link #name}.
	 */
	protected abstract void create();

}
