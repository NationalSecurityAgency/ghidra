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
package ghidra.app.util.pdb.pdbapplicator;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb.DefaultCompositeMember;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.VtShapeDescriptorMsProperty;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.VtShapeMsType;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link VtShapeMsType} types.
 */
public class VtShapeTypeApplier extends MsTypeApplier {

	/**
	 * Constructor for vtshape type applier.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link VtShapeMsType} to process.
	 */
	public VtShapeTypeApplier(PdbApplicator applicator, VtShapeMsType msType) {
		super(applicator, msType);
	}

	@Override
	BigInteger getSize() {
		return BigInteger.valueOf(applicator.getDataOrganization().getPointerSize() *
			((VtShapeMsType) msType).getCount());
	}

	/**
	 * Returns the name.
	 * @return the name.
	 */
	String getName() {
		return "vtshape_" + index;
	}

	@Override
	void apply() throws PdbException, CancelledException {
		dataType = createVtShape((VtShapeMsType) msType);
	}

	// TODO: We are creating a structure for the vtshape.  Is there anything different we would
	//  like to do instead?
	private DataType createVtShape(VtShapeMsType msShape) throws CancelledException {
		List<VtShapeDescriptorMsProperty> list = msShape.getDescriptorList();
		// TODO: what are correct/appropriate CategoryPath and name
		StructureDataType shape = new StructureDataType(applicator.getAnonymousTypesCategory(),
			"vtshape" + index, 0, applicator.getDataTypeManager());
		List<DefaultPdbUniversalMember> members = new ArrayList<>();
		int offset = 0;
		for (VtShapeDescriptorMsProperty descriptor : list) {
			switch (descriptor) {
				case NEAR:
				case FAR:
				case THIN:
				case OUTER:
				case META:
				case NEAR32:
				case FAR32:
					Pointer pointer = new PointerDataType(applicator.getDataTypeManager());
					DefaultPdbUniversalMember member =
						new DefaultPdbUniversalMember(applicator, "", pointer, offset);
					offset += pointer.getLength();
					members.add(member);
					break;
				case UNUSED:
					offset += applicator.getDataOrganization().getPointerSize();
					break;
			}
		}
		int size = applicator.getDataOrganization().getPointerSize() * msShape.getCount();
		if (!DefaultCompositeMember.applyDataTypeMembers(shape, false, size, members,
			msg -> Msg.warn(this, msg), applicator.getCancelOnlyWrappingMonitor())) {
			CompositeTypeApplier.clearComponents(shape);
		}
		return shape; // not resolved
	}
}
