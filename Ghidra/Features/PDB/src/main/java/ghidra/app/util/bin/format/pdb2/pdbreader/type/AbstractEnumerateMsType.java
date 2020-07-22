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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents various flavors of Enumerate type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractEnumerateMsType extends AbstractMsType implements MsTypeField {

	protected ClassFieldMsAttributes attribute;
	protected Numeric numeric;
	protected String name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @param strType {@link StringParseType} to use.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractEnumerateMsType(AbstractPdb pdb, PdbByteReader reader, StringParseType strType)
			throws PdbException {
		super(pdb, reader);
		attribute = new ClassFieldMsAttributes(reader);
		numeric = new Numeric(reader);
		if (!numeric.isIntegral()) {
			throw new PdbException("Expecting integral numeric");
		}
		name = reader.parseString(pdb, strType);
		reader.align4();
	}

//	/**
//	 * Constructor for this type.
//	 * @param pdb {@link AbstractPdb} to which this type belongs.
//	 * @param name the name.
//	 * @param value the value.
//	 */
//	public AbstractEnumerateMsType(AbstractPdb pdb, String name, long value) {
//		super(pdb, null);
//		this.name = name;
//		this.numericValue = BigInteger.valueOf(value);
//	}
//
	/**
	 * Returns the name of this enumerate type.
	 * @return Name type of the enumerate type.
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * Returns the Numeric of this Enumerate
	 * @return The Numeric of this Enumerate.
	 */
	public Numeric getNumeric() {
		return numeric;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// Attribute and space are not in API.
		builder.append(attribute);
		builder.append(": ");
		builder.append(name);
		builder.append("=");
		builder.append(numeric);
	}

}
