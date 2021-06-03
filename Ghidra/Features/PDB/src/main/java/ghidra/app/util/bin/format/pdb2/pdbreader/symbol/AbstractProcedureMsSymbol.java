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

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * Non-MSFT class we created to represent all procedure symbols.
 */
public abstract class AbstractProcedureMsSymbol extends AbstractMsSymbol
		implements AddressMsSymbol, NameMsSymbol {
	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractProcedureMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
	}

	/**
	 * Returns the parent pointer.
	 * @return Parent pointer.
	 */
	public abstract long getParentPointer();

	/**
	 * Returns the end pointer.
	 * @return End pointer.
	 */
	public abstract long getEndPointer();

	/**
	 * Returns the next pointer.
	 * @return next pointer.
	 */
	public abstract long getNextPointer();

	/**
	 * Returns the procedure length.
	 * @return Length.
	 */
	public abstract long getProcedureLength();

	/**
	 * Returns the debug start offset.
	 * @return Debug start offset.
	 */
	public abstract long getDebugStartOffset();

	/**
	 * Returns the debug end offset.
	 * @return Debug end offset.
	 */
	public abstract long getDebugEndOffset();

	/**
	 * Returns the type record number.
	 * @return Type record number.
	 */
	public abstract RecordNumber getTypeRecordNumber();

}
