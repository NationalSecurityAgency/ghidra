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
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working.
	 * @param msType {@link VtShapeMsType} to process.
	 */
	public VtShapeTypeApplier(DefaultPdbApplicator applicator, VtShapeMsType msType) {
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
		// Note that focused investigation as shown that both the VTShape as well as the pointer
		// to the particular VTShapes are not specific to one class; they can be shared by
		// totally unrelated classes; moreover, no duplicates of any VTShape or pointer to a
		// particular VTShape were found either.  Because of this, for now, the VTShape is going
		// into an anonymous types category.
		dataType = createVtShape((VtShapeMsType) msType);
	}

	// We are creating a structure for the vtshape.
	private DataType createVtShape(VtShapeMsType msShape)
			throws CancelledException {
		List<VtShapeDescriptorMsProperty> list = msShape.getDescriptorList();
		StructureDataType shape = new StructureDataType(applicator.getAnonymousTypesCategory(),
			"vtshape" + index, 0, applicator.getDataTypeManager());
		List<DefaultPdbUniversalMember> members = new ArrayList<>();
		int offset = 0;
		int defaultSize = applicator.getDataTypeManager().getDataOrganization().getPointerSize();
		// Since each element has its own property, we have to assume there can be mixed
		//  properties in the table, thus each element must be set separately.
		// However, note that the data types referenced by the symbols (e.g., GDATAx) at the
		// vftable locations in memory seem to have these as an array of constant pointers to
		//  functions with no argument and void return; to me, this does not quite agree with what
		//  we have here where each element having its own pointer property.  For now,
		//  using a structure here.  Moreover, we might want to eventually fix-up the arrays put
		//  down with the GDATAx symbols with structures that contain pointers to func specs that
		//  match the real function signatures at each element.
		for (VtShapeDescriptorMsProperty descriptor : list) {
			DataType elementType;
			switch (descriptor) {
				case NEAR:
					// near16:
					//   16-bit offset
					elementType = Undefined2DataType.dataType;
					break;
				case FAR:
					// far16:
					//   16-bit segment
					//   16-bit offset
					elementType = Undefined4DataType.dataType;
					break;
				case NEAR32:
					// near32:
					//   32-bit offset
					elementType = Undefined4DataType.dataType;
					break;
				case FAR32:
					// far32:
					//   16-bit segment
					//   32-bit offset
					elementType = Undefined6DataType.dataType;
					break;
				// lump remaining together; we do not know about thin, outer, or meta
				case UNUSED:
					// Special message for unused, followed by fall through case
					applicator.appendLogMsg("PDB Warning: UNUSED propery found in VTShape.");
				case THIN:
				case OUTER:
				case META:
				default:
					// If any element type is not know, we will not return a full shape structure
					// Instead, we return void type.
					applicator.appendLogMsg(
						"PDB Warning: No type conversion for " + msShape.toString() +
							" as underlying type for pointer. Using void.");
					return VoidDataType.dataType;
			}
			int size = elementType.getLength();
			if (size == defaultSize) {
				elementType = PointerDataType.dataType;
			}
			DefaultPdbUniversalMember member =
				new DefaultPdbUniversalMember(applicator, "", elementType, offset);
			offset += size;
			members.add(member);
		}
		// offset has the total size at this point
		if (!DefaultCompositeMember.applyDataTypeMembers(shape, false, offset, members,
			msg -> Msg.warn(this, msg), applicator.getCancelOnlyWrappingMonitor())) {
			CompositeTypeApplier.clearComponents(shape);
		}
		return shape; // not resolved
	}
}
