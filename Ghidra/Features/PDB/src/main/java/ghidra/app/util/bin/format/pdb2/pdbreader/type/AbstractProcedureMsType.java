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
 * This class represents various flavors of Procedure type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractProcedureMsType extends AbstractMsType {

	protected RecordNumber returnValueRecordNumber;
	protected CallingConvention callingConvention;
	protected FunctionMsAttributes functionAttributes;
	protected int numParameters;
	protected RecordNumber argListRecordNumber;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @param recordNumberSize size of record number to parse.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractProcedureMsType(AbstractPdb pdb, PdbByteReader reader, int recordNumberSize)
			throws PdbException {
		super(pdb, reader);
		returnValueRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		callingConvention = CallingConvention.fromValue(reader.parseUnsignedByteVal());
		functionAttributes = new FunctionMsAttributes(reader);
		numParameters = reader.parseUnsignedShortVal();
		argListRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		reader.skipPadding();
	}

	/**
	 * Returns the record number of the return type.
	 * @return Record number of the return type.
	 */
	public RecordNumber getReturnRecordNumber() {
		return returnValueRecordNumber;
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
	 * Returns the record number of the arguments list.
	 * @return Record number of the arguments list type.
	 */
	public RecordNumber getArgListRecordNumber() {
		return argListRecordNumber;
	}

	/**
	 * Returns the type for the return value type.
	 * @return {@link AbstractMsType} of the return value type.
	 */
	public AbstractMsType getReturnType() {
		return pdb.getTypeRecord(returnValueRecordNumber);
	}

	/**
	 * Returns the type for the arguments list.
	 * @return {@link AbstractMsType} of the arguments list.
	 */
	public AbstractMsType getArgumentsListType() {
		return pdb.getTypeRecord(argListRecordNumber);
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

}
