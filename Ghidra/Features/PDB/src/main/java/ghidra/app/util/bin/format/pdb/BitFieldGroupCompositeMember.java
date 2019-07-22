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
package ghidra.app.util.bin.format.pdb;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;

/**
 * <code>BitFieldGroupCompositeMember</code> provides the ability to collect related 
 * {@link DefaultCompositeMember} members within a group during the composite reconstruction
 * process.  
 */
public class BitFieldGroupCompositeMember extends CompositeMember {

	private List<DefaultCompositeMember> list = new ArrayList<>();

	@Override
	boolean isBitFieldMember() {
		return true;
	}

	@Override
	boolean isSingleBitFieldMember() {
		return false;
	}

	@Override
	boolean isContainer() {
		return false;
	}

	@Override
	boolean isStructureContainer() {
		return false;
	}

	@Override
	boolean isUnionContainer() {
		return false;
	}

	@Override
	int getOffset() {
		if (list.isEmpty()) {
			return 0;
		}
		return list.get(0).getOffset();
	}

	int getConsumedBits() {
		// TODO: this could be maintained as a field
		int consumed = 0;
		for (DefaultCompositeMember m : list) {
			consumed += ((BitFieldDataType) m.getDataType()).getBitSize();
		}
		return consumed;
	}

	@Override
	void setOffset(int offset) {
		for (DefaultCompositeMember m : list) {
			m.setOffset(offset);
		}
	}

	@Override
	int getLength() {
		if (list.isEmpty()) {
			return 0;
		}
		return list.get(0).getLength();
	}

	@Override
	DefaultCompositeMember getParent() {
		if (list.isEmpty()) {
			return null;
		}
		return list.get(0).getParent();
	}

	@Override
	void setParent(DefaultCompositeMember newParent) {
		for (DefaultCompositeMember m : list) {
			m.setParent(newParent);
		}
	}

	@Override
	boolean addMember(DefaultCompositeMember member) {

		DataType dt = member.getDataType();
		if (dt == null || dt.getLength() <= 0) {
			return false;
		}

		// trigger structure/union transformation
		DefaultCompositeMember bf0 = list.remove(0);

		return bf0.addMember(member);
	}

	@Override
	boolean addToStructure(DefaultCompositeMember structure) {
		// add all bit-fields to structure and allow them to regroup
		boolean success = true;
		for (DefaultCompositeMember m : list) {
			m.setBitFieldGroup(null);
			success &= m.addToStructure(structure);
		}
		return success;
	}

	@Override
	void finalizeDataType(int preferredSize) {
		return; // nothing to do
	}

	private DefaultCompositeMember validateNewMember(CompositeMember member) {
		if (!member.isSingleBitFieldMember()) {
			throw new IllegalArgumentException("expected single bit-field member");
		}
		if (!list.isEmpty() &&
			(member.getOffset() != getOffset() || member.getLength() != getLength())) {
			throw new IllegalArgumentException(
				"expected bit-field member with same offset and length");
		}
		DefaultCompositeMember m = (DefaultCompositeMember) member;
		m.setBitFieldGroup(this);
		return m;
	}

	/**
	 * Add a new member to the end of this bit-field group.  The caller should ensure that the
	 * specified member is a suitable addition to this group (must be single bit field whose 
	 * member offset and length match this group's). 
	 * @param member bit-field member (must have data type of BitFieldDataType).
	 * @throws IllegalArgumentException if specified member is not suitable for this group.
	 */
	void addToGroup(CompositeMember member) {
		list.add(validateNewMember(member));
	}

}
