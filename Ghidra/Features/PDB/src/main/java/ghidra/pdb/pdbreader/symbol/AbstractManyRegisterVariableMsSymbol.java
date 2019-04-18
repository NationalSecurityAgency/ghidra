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
 * This class represents various flavors of Many Register Variable symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractManyRegisterVariableMsSymbol extends AbstractMsSymbol {

	protected AbstractTypeIndex typeIndex;
	protected int count;
	// List of registers is most-significant first.
	protected List<RegisterName> registerNameList = new ArrayList<>();
	protected AbstractString name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractManyRegisterVariableMsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		create();
		typeIndex.parse(reader);
		pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA, typeIndex.get()));
		pdb.popDependencyStack();
		count = reader.parseUnsignedByteVal();
		for (int i = 0; i < count; i++) {
			int registerIndex = reader.parseUnsignedShortVal();
			RegisterName registerName = new RegisterName(pdb, registerIndex);
			registerNameList.add(registerName);
		}
		name.parse(reader);
		reader.align4();
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: ", getSymbolTypeName()));
		DelimiterState ds = new DelimiterState("", ", ");
		for (RegisterName registerName : registerNameList) {
			builder.append(ds.out(true, registerName));
		}
		builder.append(
			String.format(" %s %s", pdb.getTypeRecord(typeIndex.get()).toString(), name));
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #typeIndex} and {@link #name}.
	 */
	protected abstract void create();

}
