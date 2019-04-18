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

import java.util.ArrayList;
import java.util.List;

import ghidra.pdb.*;
import ghidra.pdb.pdbreader.*;

/**
 * This class represents various flavors of Managed Local- Or Parameter Stored in Many Register
 *  symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractManagedLocalOrParameterStoredInManyRegisterMsSymbol
		extends AbstractMsSymbol {

	protected int typeIndex;
	protected LocalVariableAttributes attributes;
	// Registers are in most-significant-first order.
	protected List<RegisterName> registerNameList = new ArrayList<>();
	protected AbstractString name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractManagedLocalOrParameterStoredInManyRegisterMsSymbol(AbstractPdb pdb,
			PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		typeIndex = reader.parseInt();
		pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA, typeIndex));
		pdb.popDependencyStack();
		attributes = new LocalVariableAttributes(reader);
		int count = parseVal(reader);
		for (int i = 0; i < count; i++) {
			int register = parseVal(reader);
			RegisterName registerName = new RegisterName(pdb, register);
			registerNameList.add(registerName);
			// TODO: Might be missing information here in the structure.  Says counter register
			//  enumerates followed by length-prefixed name.  Compare with PDB_ID = 0x110a, where
			//  the MSFT API also talks about a name, but does not have it in a separate
			//  structure member.
			// otherName = parseName(reader); //here????? (if it exists)
		}
		// otherName = parseName(reader); //here????? (if it exists)
		name.parse(reader);
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: ", getSymbolTypeName()));
		DelimiterState ds = new DelimiterState("", ", ");
		for (RegisterName registerName : registerNameList) {
			builder.append(ds.out(true, registerName));
		}
		builder.append(
			String.format(" %s %s", pdb.getTypeRecord(typeIndex).toString(), name.get()));
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #name}.
	 */
	protected abstract void create();

	/**
	 * Parses a value for this symbol.
	 * @param reader {@link PdbByteReader} from which to parse the value.
	 * @return Value parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract int parseVal(PdbByteReader reader) throws PdbException;

}
