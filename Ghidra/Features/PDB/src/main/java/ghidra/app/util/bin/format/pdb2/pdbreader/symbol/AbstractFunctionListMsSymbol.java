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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents various flavors Function List symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractFunctionListMsSymbol extends AbstractMsSymbol {

	protected int count;
	protected List<RecordNumber> functionTypeList = new ArrayList<>();
	// See note below regarding invocation counts.
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
			// TODO: eventually change to parse() after we figure out what is going on with high bit
			// fixup.  Seems to point to incorrect data.
			RecordNumber typeRecordNumber =
				RecordNumber.parseNoWitness(pdb, reader, RecordCategory.TYPE, 32);
			functionTypeList.add(typeRecordNumber);
		}
		// Note: the following part of the structure is commented out on the API, but since
		//  according to that API, there is nothing remaining, so it does no real harm in 
		//  keeping the parsing here.  It really just means that the invocation counts list
		//  should not be used.
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
