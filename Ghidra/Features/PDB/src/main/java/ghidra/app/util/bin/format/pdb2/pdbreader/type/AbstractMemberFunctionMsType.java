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
 * This class represents various flavors of Member Function type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractMemberFunctionMsType extends AbstractMsType {

	protected RecordNumber returnValueRecordNumber;
	protected RecordNumber containingClassRecordNumber;
	protected RecordNumber thisPointerRecordNumber; // Model-specific
	protected CallingConvention callingConvention;
	protected FunctionMsAttributes functionAttributes;
	protected int numParameters;
	protected RecordNumber argListRecordNumber;
	protected int thisAdjuster;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @param recordNumberSize size of record number to parse.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractMemberFunctionMsType(AbstractPdb pdb, PdbByteReader reader, int recordNumberSize)
			throws PdbException {
		super(pdb, reader);
		returnValueRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		containingClassRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		thisPointerRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		callingConvention = CallingConvention.fromValue(reader.parseUnsignedByteVal());
		functionAttributes = new FunctionMsAttributes(reader);
		numParameters = reader.parseUnsignedShortVal();
		argListRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		thisAdjuster = reader.parseInt();
	}

	/**
	 * Returns the record number of the return type.
	 * @return Record number of the return type.
	 */
	public RecordNumber getReturnRecordNumber() {
		return returnValueRecordNumber;
	}

	/**
	 * Returns the type for the return value type.
	 * @return The {@link AbstractMsType} return value type.
	 */
	public AbstractMsType getReturnType() {
		return pdb.getTypeRecord(returnValueRecordNumber);
	}

	/**
	 * Returns the {@link CallingConvention}.
	 * @return the {@link CallingConvention}.
	 */
	public CallingConvention getCallingConvention() {
		return callingConvention;
	}

	/**
	 * Returns the function attributes.
	 * @return The function attributes.
	 */
	public FunctionMsAttributes getFunctionAttributes() {
		return functionAttributes;
	}

	/**
	 * Returns if known to be a constructor.
	 * @return true if constructor.
	 */
	public boolean isConstructor() {
		return functionAttributes.isConstructor();
	}

	/**
	 * Returns the number of parameters to the function.
	 * @return The number of parameters.
	 */
	public int getNumParams() {
		return numParameters;
	}

	/**
	 * Returns the record number of the arguments list.
	 * @return The record number of the arguments list.
	 */
	public RecordNumber getArgListRecordNumber() {
		return argListRecordNumber;
	}

	/**
	 * Returns the type index for the arguments list.
	 * @return The {@link AbstractMsType} arguments list.
	 */
	public AbstractMsType getArgumentsListType() {
		return pdb.getTypeRecord(argListRecordNumber);
	}

	/**
	 * Returns the record number for the class containing this method.
	 * @return The record number of the {@link AbstractMsType} class containing this method.
	 */
	public RecordNumber getContainingClassRecordNumber() {
		return containingClassRecordNumber;
	}

	/**
	 * Returns the type for the class containing this method.
	 * @return The {@link AbstractMsType} class containing this method.
	 */
	public AbstractMsType getContainingClassType() {
		return pdb.getTypeRecord(containingClassRecordNumber);
	}

	/**
	 * Returns the record number for the "this" pointer type.
	 * @return The record number of the {@link AbstractMsType} "this" pointer type.
	 */
	public RecordNumber getThisPointerRecordNumber() {
		return thisPointerRecordNumber;
	}

	/**
	 * Returns the type for the "this" pointer.
	 * @return The {@link AbstractMsType} "this" pointer.
	 */
	public AbstractMsType getThisPointerType() {
		return pdb.getTypeRecord(thisPointerRecordNumber);
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		if (bind.ordinal() < Bind.PROC.ordinal()) {
			builder.insert(0, "(");
			builder.append(")");
		}
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append(getContainingClassType());
		myBuilder.append("::");
		builder.insert(0, myBuilder);
		builder.append(getArgumentsListType());
		builder.append("<");
		myBuilder = new StringBuilder();
		myBuilder.append("this");
		getThisPointerType().emit(myBuilder, Bind.NONE);
		builder.append(myBuilder);
		builder.append(",");
		builder.append(thisAdjuster);
		builder.append(",");
		builder.append(numParameters);
		builder.append(",");
		builder.append(functionAttributes);
		builder.append(">");

		getReturnType().emit(builder, Bind.PROC);
	}

}
