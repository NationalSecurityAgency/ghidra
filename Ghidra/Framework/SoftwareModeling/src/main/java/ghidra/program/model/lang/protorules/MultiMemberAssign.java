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
package ghidra.program.model.lang.protorules;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.lang.protorules.PrimitiveExtractor.Primitive;
import ghidra.program.model.pcode.Encoder;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.InvalidInputException;
import ghidra.xml.*;

/**
 * Consume a register per primitive member of an aggregate data-type
 * 
 * The data-type is split up into its underlying primitive elements, and each one
 * is assigned storage as if it were a separate parameter, or alternately assigned a
 * register from a specific resource list. The storage elements are returned together
 * as a single Address in JOIN space.  Constant zeroes are used as placeholders for any
 * padding between elements.  No packing of elements into a single register occurs.
 */
public class MultiMemberAssign extends AssignAction {

	private StorageClass resourceType;	// Resource list from which to consume
	private boolean isRecursive;		// True if primitives are assigned recursively
	private boolean consumeFromStack;	// True if resources should be consumed from the stack
	private boolean consumeMostSig;		// True if resources are consumed starting with most significant bytes
	private ParamEntry stackEntry;		// Parameter Entry corresponding to the stack
	private AddressSpace constSpace;	// Address space used for padding

	public MultiMemberAssign(StorageClass store, boolean recurse, boolean stack, boolean mostSig,
			ParamListStandard res) {
		super(res);
		constSpace = resource.getLanguage().getAddressFactory().getConstantSpace();

		resourceType = store;
		isRecursive = recurse;
		consumeFromStack = stack;
		consumeMostSig = mostSig;
		stackEntry = resource.getStackEntry();
	}

	@Override
	public AssignAction clone(ParamListStandard newResource) throws InvalidInputException {
		return new MultiMemberAssign(resourceType, isRecursive, consumeFromStack, consumeMostSig,
			newResource);
	}

	@Override
	public boolean isEquivalent(AssignAction op) {
		if (this.getClass() != op.getClass()) {
			return false;
		}
		MultiMemberAssign otherOp = (MultiMemberAssign) op;
		if (resourceType != otherOp.resourceType) {
			return false;
		}
		if (isRecursive != otherOp.isRecursive) {
			return false;
		}
		if (consumeFromStack != otherOp.consumeFromStack) {
			return false;
		}
		return consumeMostSig == otherOp.consumeMostSig;
	}

	private boolean addPadding(ArrayList<Varnode> pieces, int pad)

	{
		if (pad == 0)
			return true;
		if (pad < 0)
			return false;

		Varnode vn = new Varnode(constSpace.getAddress(0), pad);
		pieces.add(vn);
		return true;
	}

	@Override
	public int assignAddress(DataType dt, PrototypePieces proto, int pos, DataTypeManager dtManager,
			int[] status, ParameterPieces res) {
		int[] tmpStatus = status.clone();
		ArrayList<Varnode> pieces = new ArrayList<>();
		ParameterPieces param = new ParameterPieces();
		// If we are recursive, treat arrays as primitive so other rules can (recursively) apply
		PrimitiveExtractor primitives = new PrimitiveExtractor(dt, false, isRecursive, 0, 16);
		if (!primitives.isValid() || primitives.size() == 0 || primitives.containsUnknown() ||
			!primitives.isAligned() || primitives.containsHoles()) {
			return FAIL;
		}
		if (isRecursive) {		// Recursive assignments
			if (primitives.size() == 1) {
				if (primitives.get(0).dt == dt)
					return FAIL;		// Prevent infinite recursion
			}
			int size = 0;
			int before = (stackEntry != null) ? tmpStatus[stackEntry.getGroup()] : -1;
			for (int i = 0; i < primitives.size(); ++i) {
				Primitive primitive = primitives.get(i);
				if (resource.assignAddress(primitive.dt, proto, pos, dtManager, tmpStatus,
					param) == FAIL) {
					return FAIL;
				}
				if (!consumeFromStack && stackEntry != null) {
					if (before != tmpStatus[stackEntry.getGroup()])
						return FAIL;
				}
				if (!addPadding(pieces, primitive.offset - size)) {
					return FAIL;
				}
				size = primitive.offset + primitive.dt.getLength();
				Varnode vn = new Varnode(param.address, primitive.dt.getLength());
				pieces.add(vn);
			}
			if (!addPadding(pieces, dt.getLength() - size)) {
				return FAIL;
			}
		}
		else {		// Assignment from a specific resourceType
			int size = 0;
			for (int i = 0; i < primitives.size(); ++i) {
				Primitive primitive = primitives.get(i);
				if (resource.assignAddressFallback(resourceType, primitive.dt, !consumeFromStack,
					tmpStatus,
					param) == FAIL) {
					return FAIL;
				}
				if (!addPadding(pieces, primitive.offset - size)) {
					return FAIL;
				}
				size = primitive.offset + primitive.dt.getLength();
				Varnode vn = new Varnode(param.address, primitive.dt.getLength());
				pieces.add(vn);
			}
			if (!addPadding(pieces, dt.getLength() - size)) {
				return FAIL;
			}
		}

		System.arraycopy(tmpStatus, 0, status, 0, tmpStatus.length);	// Commit resource usage for all the pieces
		res.type = dt;
		res.assignAddressFromPieces(pieces, consumeMostSig, false, resource.getLanguage());
		return SUCCESS;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_JOIN_PER_PRIMITIVE);
		if (!isRecursive) {
			encoder.writeString(ATTRIB_STORAGE, resourceType.toString());
		}
		encoder.closeElement(ELEM_JOIN_PER_PRIMITIVE);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		isRecursive = true;
		XmlElement elem = parser.start(ELEM_JOIN_PER_PRIMITIVE.name());
		String attribString = elem.getAttribute(ATTRIB_STORAGE.name());
		if (attribString != null) {
			resourceType = StorageClass.getClass(attribString);
			isRecursive = false;
		}
		parser.end(elem);
	}

}
