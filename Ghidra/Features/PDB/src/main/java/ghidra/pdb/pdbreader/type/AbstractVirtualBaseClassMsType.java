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

import java.math.BigInteger;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.*;

public abstract class AbstractVirtualBaseClassMsType extends AbstractMsType {

	protected AbstractTypeIndex directVirtualBaseClassTypeIndex;
	protected AbstractTypeIndex virtualBasePointerTypeIndex;
	protected ClassFieldMsAttributes attribute;
	protected BigInteger virtualBaseOffsetFromAddressPoint;
	protected BigInteger virtualBaseOffsetFromVBTable;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractVirtualBaseClassMsType(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		create();
		parseInitialFields(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, directVirtualBaseClassTypeIndex.get()));
		pdb.popDependencyStack();
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, virtualBasePointerTypeIndex.get()));
		pdb.popDependencyStack();
		//TODO: Check this
		virtualBaseOffsetFromAddressPoint = reader.parseNumeric();
		virtualBaseOffsetFromVBTable = reader.parseNumeric();
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		builder.append(attribute);
		builder.append(": ");
		AbstractMsType type = pdb.getTypeRecord(directVirtualBaseClassTypeIndex.get());
		builder.append(type.getName());
		builder.append("< ");

		StringBuilder vbpBuilder = new StringBuilder();
		vbpBuilder.append("vbp");
		pdb.getTypeRecord(virtualBasePointerTypeIndex.get()).emit(vbpBuilder, Bind.NONE);
		builder.append(vbpBuilder);
		builder.append("; offVbp=");
		builder.append(virtualBaseOffsetFromAddressPoint);
		builder.append("; offVbte=");
		builder.append(virtualBaseOffsetFromVBTable);
		builder.append("; >");
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #directVirtualBaseClassTypeIndex} and
	 *  {@link #virtualBasePointerTypeIndex}.
	 */
	protected abstract void create();

	/**
	 * Parses the initial fields for this type.
	 * <P>
	 * Implementing class must, in the appropriate order pertinent to itself, allocate/parse
	 * {@link #attribute}; also parse {@link #directVirtualBaseClassTypeIndex} and
	 *  {@link #virtualBasePointerTypeIndex}.
	 * @param reader {@link PdbByteReader} from which the data is parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parseInitialFields(PdbByteReader reader) throws PdbException;

}
