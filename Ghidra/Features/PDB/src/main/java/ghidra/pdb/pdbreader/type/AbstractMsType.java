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

import ghidra.pdb.AbstractParsableItem;
import ghidra.pdb.PdbByteReader;
import ghidra.pdb.pdbreader.AbstractPdb;

/**
 * This is the abstract class for PDB Data Type units.
 */
public abstract class AbstractMsType extends AbstractParsableItem {
	protected AbstractPdb pdb;

	// Order matters on these.
	public static enum Bind {
		PTR, ARRAY, PROC, NONE
	}

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 */
	AbstractMsType(AbstractPdb pdb, PdbByteReader reader) {
		this.pdb = pdb;
		//System.out.println(reader.dump());
	}

	/**
	 * If the type has a name element, returns this name; else returns an empty String.
	 *  Meant to be overloaded by derived types that have a name element.
	 * @return Name.
	 */
	public String getName() {
		return "";
	}

	/**
	 * Returns the unique ID (PdbId) for this data type.
	 * @return Identifier for this data type.
	 */
	public abstract int getPdbId();

	@Override
	public void emit(StringBuilder builder) {
		this.emit(builder, Bind.NONE);
	}

	/**
	 * Emits {@link String} output of this class into the provided {@link StringBuilder}.
	 * @param builder {@link StringBuilder} into which the output is created.
	 * @param bind Bind ordinal used for determining when parentheses should surround components. 
	 */
	public void emit(StringBuilder builder, Bind bind) {
		builder.append("IncompleteImpl(" + this.getClass().getSimpleName() + ")");
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		emit(builder, Bind.NONE);
		return builder.toString();
	}

}
