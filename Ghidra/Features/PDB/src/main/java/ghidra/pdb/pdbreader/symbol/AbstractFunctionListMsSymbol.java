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
import ghidra.pdb.pdbreader.AbstractPdb;
import ghidra.pdb.pdbreader.CategoryIndex;

/**
 * This class represents various flavors Function List symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractFunctionListMsSymbol extends AbstractMsSymbol {

	protected int count;
	protected List<Integer> functionTypeList = new ArrayList<>();
	protected List<Integer> invocationCountsList = new ArrayList<>();

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractFunctionListMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		count = reader.parseInt(); // Ignoring unsigned in API
		for (int i = 0; i < count; i++) {
			int typeIndex = reader.parseInt();
			pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA, typeIndex));
			pdb.popDependencyStack();
			functionTypeList.add(typeIndex);
		}
		for (int i = 0; i < count; i++) {
			// Anything beyond the record length has an implicit invocation count of zero.
			if (reader.hasMore()) {
				invocationCountsList.add(reader.parseInt());
			}
			else {
				invocationCountsList.add(0);
			}
		}
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: Count: %d", getSymbolTypeName(), count));
		DelimiterState ds = new DelimiterState("", ", ");
		for (int i = 0; i < count; i++) {
			if ((i % 4) == 0) {
				builder.append("\n");
			}
			builder.append(ds.out(true, String.format("%s (%d, args) ",
				pdb.getTypeRecord(functionTypeList.get(i)), invocationCountsList.get(i))));
		}
	}

}
