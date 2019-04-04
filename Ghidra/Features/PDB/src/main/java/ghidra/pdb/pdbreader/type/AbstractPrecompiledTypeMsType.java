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

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.*;

public abstract class AbstractPrecompiledTypeMsType extends AbstractMsType {

	protected AbstractTypeIndex start;
	protected int count;
	protected long signature;
	protected AbstractString name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractPrecompiledTypeMsType(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		create();
		parseFields(reader);
	}

	// Note: MSFT output API not documented.
	@Override
	public void emit(StringBuilder builder, Bind bind) {
		builder.append(
			String.format("Precompiled: signature=0X%08X, name=%s, startTypeIndex=%d, count=%d",
				signature, name, start.get(), count));
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #start} and {@link #name}.
	 */
	protected abstract void create();

	/**
	 * Parses the fields of this type.
	 * <P>
	 * Implementing class must, in the appropriate order pertinent to itself, parse
	 * {@link #start}, {@link #count}, {@link #signature}, and {@link #name}.
	 * @param reader {@link PdbByteReader} from which to parse the fields.
	 * @throws PdbException upon error parsing a field.
	 */
	protected abstract void parseFields(PdbByteReader reader) throws PdbException;

}
