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

import org.apache.commons.lang3.Validate;

import ghidra.pdb.*;
import ghidra.pdb.pdbreader.AbstractPdb;

/**
 * An abstract class for a number of specific PDB symbol type internals that share certain
 * information.  Because java does not support multiple inheritance, we chose to implement a
 * design where classes that have the same internal architectures, but which are not of the
 * same class hierarchy, can share the same internal structures.
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 * @see AbstractMsSymbol
 */
public abstract class AbstractSymbolInternals extends AbstractParsableItem {

	protected AbstractPdb pdb;

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public AbstractSymbolInternals(AbstractPdb pdb) {
		Validate.notNull(pdb, "pdb cannot be null)");
		this.pdb = pdb;
		create();
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize any items that need to be initialized prior
	 * to their being used parsed by {@link #parse(PdbByteReader)} or used anywhere else.
	 */
	protected abstract void create();

	/**
	 * Parses the contents of these internals to a symbol.
	 * <P>
	 * Implementing class must parse any items that need to be parsed prior to use; these typically
	 * include those items that were initialized by {@link #create()}.
	 * @param reader {@link PdbByteReader} containing the information to parse.
	 * @throws PdbException upon error parsing a field.
	 */
	public abstract void parse(PdbByteReader reader) throws PdbException;

}
