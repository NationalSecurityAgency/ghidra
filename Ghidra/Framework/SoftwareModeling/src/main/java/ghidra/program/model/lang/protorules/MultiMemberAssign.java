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

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Encoder;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.InvalidInputException;
import ghidra.xml.*;

/**
 * Consume a register per primitive member of an aggregate data-type
 * 
 * The data-type is split up into its underlying primitive elements, and each one
 * is assigned a register from the specific resource list.  There must be no padding between
 * elements.  No packing of elements into a single register occurs.
 */
public class MultiMemberAssign extends AssignAction {

	private StorageClass resourceType;	// Resource list from which to consume
	private boolean consumeFromStack;	// True if resources should be consumed from the stack
	private boolean consumeMostSig;		// True if resources are consumed starting with most significant bytes

	public MultiMemberAssign(StorageClass store, boolean stack, boolean mostSig,
			ParamListStandard res) {
		super(res);
		resourceType = store;
		consumeFromStack = stack;
		consumeMostSig = mostSig;
	}

	@Override
	public AssignAction clone(ParamListStandard newResource) throws InvalidInputException {
		return new MultiMemberAssign(resourceType, consumeFromStack, consumeMostSig, newResource);
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
		if (consumeFromStack != otherOp.consumeFromStack) {
			return false;
		}
		return consumeMostSig == otherOp.consumeMostSig;
	}

	@Override
	public int assignAddress(DataType dt, PrototypePieces proto, int pos, DataTypeManager dtManager,
			int[] status, ParameterPieces res) {
		int[] tmpStatus = status.clone();
		ArrayList<Varnode> pieces = new ArrayList<>();
		ParameterPieces param = new ParameterPieces();
		PrimitiveExtractor primitives = new PrimitiveExtractor(dt, false, 0, 16);
		if (!primitives.isValid() || primitives.size() == 0 || primitives.containsUnknown() ||
			!primitives.isAligned() || primitives.containsHoles()) {
			return FAIL;
		}
		for (int i = 0; i < primitives.size(); ++i) {
			DataType curType = primitives.get(i).dt;
			if (resource.assignAddressFallback(resourceType, curType, !consumeFromStack, tmpStatus,
				param) == FAIL) {
				return FAIL;
			}
			Varnode vn = new Varnode(param.address, curType.getLength());
			pieces.add(vn);
		}

		System.arraycopy(tmpStatus, 0, status, 0, tmpStatus.length);	// Commit resource usage for all the pieces
		res.type = dt;
		if (pieces.size() == 1) {
			res.address = pieces.get(0).getAddress();
			return SUCCESS;
		}
		res.joinPieces = new Varnode[pieces.size()];
		if (!consumeMostSig) {
			for (int i = 0; i < res.joinPieces.length; ++i) {
				res.joinPieces[i] = pieces.get(pieces.size() - 1 - i);
			}
		}
		else {
			for (int i = 0; i < pieces.size(); ++i) {
				res.joinPieces[i] = pieces.get(i);
			}
		}
		res.address = Address.NO_ADDRESS;		// Placeholder for join space address
		return SUCCESS;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_JOIN_PER_PRIMITIVE);
		if (resourceType != StorageClass.GENERAL) {
			encoder.writeString(ATTRIB_STORAGE, resourceType.toString());
		}
		encoder.closeElement(ELEM_JOIN_PER_PRIMITIVE);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_JOIN_PER_PRIMITIVE.name());
		String attribString = elem.getAttribute(ATTRIB_STORAGE.name());
		if (attribString != null) {
			resourceType = StorageClass.getClass(attribString);
		}
		parser.end(elem);
	}

}
