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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.util.exception.CancelledException;

/**
 * This class represents various flavors of Field List type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractFieldListMsType extends AbstractMsType {

	private List<MsTypeField> baseClassList = new ArrayList<>();
	private List<MsTypeField> memberList = new ArrayList<>();
	private List<MsTypeField> methodList = new ArrayList<>();
	// This list contains AbstractIndexMsType instances.  It seems that one of these contains
	//  the index to another AbstractFieldList.  We do not (yet) know that if a third list is
	//  needed, whether there will be a daisy-chain (last entry in second list will designate
	//  third list) or if this main list will contain multiple AbstactIndexMsType instances
	//  (a breadth-first list).  That is why we have created a list of these (to allow for more
	//  than one AbstractIndexMsType) in any AbstractFieldListMsType.
	private List<AbstractIndexMsType> indexList = new ArrayList<>();

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 * @throws CancelledException Upon user cancellation.
	 */
	public AbstractFieldListMsType(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException, CancelledException {
		super(pdb, reader);
		while (reader.hasMore()) {
			MsTypeField type = pdb.getTypeParser().parseField(reader);
//			AbstractMsType type = pdb.getTypeParser().parse(reader);
			if ((type instanceof AbstractBaseClassMsType) ||
				(type instanceof AbstractVirtualBaseClassMsType) ||
				(type instanceof AbstractIndirectVirtualBaseClassMsType)) {
				baseClassList.add(type);
			}
			else if ((type instanceof AbstractOverloadedMethodMsType) ||
				(type instanceof AbstractOneMethodMsType)) {
				methodList.add(type);
			}
			else if ((type instanceof AbstractMemberMsType) ||
				(type instanceof AbstractNestedTypeMsType) ||
				(type instanceof AbstractStaticMemberMsType) ||
				(type instanceof AbstractVirtualFunctionTablePointerMsType) ||
				(type instanceof AbstractEnumerateMsType)) {
				// Known types:
				//  AbstractMemberMsType
				//  AbstractNestedTypeMsType
				//  AbstractStaticMemberMsType
				//  AbstractVirtualFunctionTablePointerMsType
				//  AbstractEnumerateMsType
				memberList.add(type);
			}
			else if (type instanceof AbstractIndexMsType) {
				indexList.add((AbstractIndexMsType) type);
			}
			else {
				PdbLog.message("Unexpected type in Field List" + type.getClass().getSimpleName());
			}
		}
	}

	/**
	 * Returns the (ordered?) {@link List}&lt;{@link AbstractMsType}&gt; of base class types. 
	 * @return List of base class types.
	 */
	public List<MsTypeField> getBaseClassList() {
		return baseClassList;
	}

	/**
	 * Returns the (ordered?) {@link List}&lt;{@link AbstractMsType}&gt; of type members types of
	 *  this field list. 
	 * @return Field list.
	 */
	public List<MsTypeField> getMemberList() {
		return memberList;
	}

	/**
	 * Returns the (ordered?) {@link List}&lt;{@link AbstractMsType}&gt; of other types. (We have
	 *  separated these out, but are unsure about what they are at this time.) 
	 * @return List of other types.
	 */
	public List<MsTypeField> getMethodList() {
		return methodList;
	}

	/**
	 * Returns the (ordered?) {@link List}&lt;{@link AbstractIndexMsType}&gt; that we believe
	 *  will contain the reference only to other {@link AbstractFieldListMsType}s.
	 * @return List of {@link AbstractIndexMsType}s.
	 */
	public List<AbstractIndexMsType> getIndexList() {
		return indexList;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		//TODO: Note the documented API does not output field of the following types:
		// MSOverloadedMethod_16, MSOverloadedMethod,
		// MSStaticMethod_16, MSStaticMethod,
		// MSOneMethod_16, MSOneMethod.
		StringBuilder classBuilder = new StringBuilder();
		DelimiterState dsBases = new DelimiterState(" : ", ", ");
		for (MsTypeField type : baseClassList) {
			classBuilder.append(dsBases.out(true, type.toString()));
		}

		StringBuilder memberBuilder = new StringBuilder();
		memberBuilder.append(" {");
		DelimiterState dsMembers = new DelimiterState("", ",");
		for (MsTypeField type : memberList) {
			memberBuilder.append(dsMembers.out(true, type.toString()));
		}
		memberBuilder.append("}");

		StringBuilder otherBuilder = new StringBuilder();
		if (methodList.size() != 0) {
			otherBuilder.append("...");
		}
		builder.append(classBuilder);
		builder.append(memberBuilder);
		builder.append(otherBuilder);
	}

}
