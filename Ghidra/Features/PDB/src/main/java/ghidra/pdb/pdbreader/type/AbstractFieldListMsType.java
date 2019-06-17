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

import java.util.ArrayList;
import java.util.List;

import ghidra.pdb.*;
import ghidra.pdb.pdbreader.AbstractPdb;
import ghidra.util.exception.CancelledException;

/**
 * This class represents various flavors of Field List type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractFieldListMsType extends AbstractMsType {

	private List<AbstractMsType> nameSpaceList = new ArrayList<>();
	private List<AbstractMsType> memberList = new ArrayList<>();
	private List<AbstractMsType> otherList = new ArrayList<>();

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
			AbstractMsType type = pdb.getTypeParser().parse(reader);
			if ((type instanceof AbstractBaseClassMsType) ||
				(type instanceof AbstractVirtualBaseClassMsType) ||
				(type instanceof AbstractIndirectVirtualBaseClassMsType)) {
				nameSpaceList.add(type);
			}
			else if ((type instanceof AbstractMemberMsType) ||
				(type instanceof AbstractEnumerateMsType)) {
				memberList.add(type);
			}
			else {
				otherList.add(type);
			}
		}
	}

	/**
	 * Returns the (ordered?) {@link List}&lt;{@link AbstractMsType}&gt; of types in the namespace. 
	 * @return List of types in the namespace.
	 */
	public List<AbstractMsType> getNamespaceList() {
		return nameSpaceList;
	}

	/**
	 * Returns the (ordered?) {@link List}&lt;{@link AbstractMsType}&gt; of type members types of
	 *  this field list. 
	 * @return Field list.
	 */
	public List<AbstractMsType> getMemberList() {
		return memberList;
	}

	/**
	 * Returns the (ordered?) {@link List}&lt;{@link AbstractMsType}&gt; of other types. (We have
	 *  separated these out, but are unsure about what they are at this time.) 
	 * @return List of other types.
	 */
	public List<AbstractMsType> getOtherList() {
		return otherList;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		//TODO: Note the documented API does not output field of the following types:
		// MSOverloadedMethod_16, MSOverloadedMethod,
		// MSStaticMethod_16, MSStaticMethod,
		// MSOneMethod_16, MSOneMethod.
		StringBuilder classBuilder = new StringBuilder();
		DelimiterState dsBases = new DelimiterState(" : ", ", ");
		for (AbstractMsType type : nameSpaceList) {
			classBuilder.append(dsBases.out(true, type.toString()));
		}

		StringBuilder memberBuilder = new StringBuilder();
		memberBuilder.append(" {");
		DelimiterState dsMembers = new DelimiterState("", ",");
		for (AbstractMsType type : memberList) {
			memberBuilder.append(dsMembers.out(true, type.toString()));
		}
		memberBuilder.append("}");

		StringBuilder otherBuilder = new StringBuilder();
		if (otherList.size() != 0) {
			otherBuilder.append("...");
		}
		builder.append(classBuilder);
		builder.append(memberBuilder);
		builder.append(otherBuilder);
	}

}
