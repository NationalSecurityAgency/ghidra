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
 * This class represents various flavors of Managed Symbol With Slot Index Field symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractManagedSymbolWithSlotIndexFieldMsSymbol extends AbstractMsSymbol {

	protected long slotIndex;
	protected RecordNumber typeRecordNumber;
	protected LocalVariableAttributes attributes;
	protected String name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @param strType {@link StringParseType} to use.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractManagedSymbolWithSlotIndexFieldMsSymbol(AbstractPdb pdb, PdbByteReader reader,
			StringParseType strType) throws PdbException {
		super(pdb, reader);
		slotIndex = reader.parseUnsignedIntVal();
		typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		attributes = new LocalVariableAttributes(pdb, reader);
		name = reader.parseString(pdb, strType);
	}

	@Override
	public void emit(StringBuilder builder) {
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append(typeRecordNumber.getNumber());
		attributes.emit(myBuilder);
		builder.append(String.format("%s: %d, %s %s", getSymbolTypeName(), slotIndex,
			myBuilder.toString(), name));
	}

}
