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

/**
 * This class represents various flavors of Procedure type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractProcedureMsType extends AbstractMsType {

	protected AbstractTypeIndex returnValueTypeIndex;
	protected CallingConvention callingConvention;
	protected FunctionMsAttributes functionAttributes;
	protected int numParameters;
	protected AbstractTypeIndex argListTypeIndex;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractProcedureMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		returnValueTypeIndex.parse(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, returnValueTypeIndex.get()));
		pdb.popDependencyStack();
		callingConvention = CallingConvention.fromValue(reader.parseUnsignedByteVal());
		functionAttributes = new FunctionMsAttributes(reader);
		numParameters = reader.parseUnsignedShortVal();
		argListTypeIndex.parse(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, argListTypeIndex.get()));
		pdb.popDependencyStack();
		reader.skipPadding();
	}

	/**
	 * Returns the type index of the return type.
	 * @return Type index of the return type.
	 */
	public int getReturnTypeIndex() {
		return returnValueTypeIndex.get();
	}

	/**
	 * Returns the {@link CallingConvention}.
	 * @return the {@link CallingConvention}.
	 */
	public CallingConvention getCallingConventionValue() {
		return callingConvention;
	}

	/**
	 * Returns the function attributes.
	 * @return Function attributes
	 */
	public FunctionMsAttributes getFunctionAttributes() {
		return functionAttributes;
	}

	/**
	 * Returns the number of parameters.
	 * @return Number of parameters.
	 */
	public int getNumParams() {
		return numParameters;
	}

	/**
	 * Returns the type index of the arguments list type.
	 * @return Type index of the arguments list type.
	 */
	public int getArgListTypeIndex() {
		return argListTypeIndex.get();
	}

	/**
	 * Returns the type for the return value type.
	 * @return {@link AbstractMsType} of the return value type.
	 */
	public AbstractMsType getReturnType() {
		return pdb.getTypeRecord(returnValueTypeIndex.get());
	}

	/**
	 * Returns the type for the arguments list.
	 * @return {@link AbstractMsType} of the arguments list.
	 */
	public AbstractMsType getArgumentsListType() {
		return pdb.getTypeRecord(argListTypeIndex.get());
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		if (bind.ordinal() < Bind.PROC.ordinal()) {
			builder.insert(0, "(");
			builder.append(")");
		}
		builder.append(getArgumentsListType());
		getReturnType().emit(builder, Bind.PROC);
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #returnValueTypeIndex} and
	 * {@link #argListTypeIndex}.
	 */
	protected abstract void create();

}
