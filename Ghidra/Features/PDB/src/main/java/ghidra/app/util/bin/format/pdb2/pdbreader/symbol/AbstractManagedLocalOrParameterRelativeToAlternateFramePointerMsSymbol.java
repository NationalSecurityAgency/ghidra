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
 * This class represents various flavors of Managed Local- Or Parameter-Relative-to-Virtual
 *  Frame Pointer symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractManagedLocalOrParameterRelativeToAlternateFramePointerMsSymbol
		extends AbstractMsSymbol {

	private long offset;
	private RecordNumber typeRecordNumber;
	private int register;
	private RegisterName registerName;
	private LocalVariableAttributes attributes;
	protected String name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @param strType {@link StringParseType} to use.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractManagedLocalOrParameterRelativeToAlternateFramePointerMsSymbol(AbstractPdb pdb,
			PdbByteReader reader, StringParseType strType) throws PdbException {
		super(pdb, reader);
		offset = reader.parseUnsignedIntVal();
		typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		register = reader.parseUnsignedShortVal();
		registerName = new RegisterName(pdb, register);
		attributes = new LocalVariableAttributes(pdb, reader);
		name = reader.parseString(pdb, strType);
	}

	@Override
	public void emit(StringBuilder builder) {
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append(typeRecordNumber.getNumber());
		attributes.emit(myBuilder);
		builder.append(String.format("%s: %s+%08X, %s, %s", getSymbolTypeName(),
			registerName.toString(), offset, myBuilder.toString(), name));
	}

}
