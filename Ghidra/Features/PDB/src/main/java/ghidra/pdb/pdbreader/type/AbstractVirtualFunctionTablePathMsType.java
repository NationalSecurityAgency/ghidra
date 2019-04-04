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
package ghidra.pdb.pdbreader.type;

import java.util.List;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.AbstractPdb;
import ghidra.pdb.pdbreader.AbstractTypeIndex;

public abstract class AbstractVirtualFunctionTablePathMsType extends AbstractMsType {

	protected List<AbstractTypeIndex> bases;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractVirtualFunctionTablePathMsType(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		bases = parseBases(reader);
	}

	// Note: MSFT output API not documented.
	@Override
	public void emit(StringBuilder builder, Bind bind) {
		builder.append(String.format("VFTPath: count=%d\n", bases.size()));
		for (int i = 0; i < bases.size(); i++) {
			builder.append(String.format("   index[%d]=%d\n", i, bases.get(i).get()));
		}
	}

	/**
	 * Abstract internal method to parse fields in the deserialization process. 
	 * @param reader {@link PdbByteReader} that is deserialized.
	 * @return bases information.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract List<AbstractTypeIndex> parseBases(PdbByteReader reader) throws PdbException;

}
