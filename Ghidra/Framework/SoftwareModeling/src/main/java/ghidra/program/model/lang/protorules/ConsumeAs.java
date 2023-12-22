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

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Encoder;
import ghidra.xml.*;

/**
 * Consume a parameter from a specific resource list
 * 
 * Normally the resource list is determined by the parameter data-type, but this
 * action specifies an overriding resource list.
 */
public class ConsumeAs extends AssignAction {

	private StorageClass resourceType;		// The resource list the parameter is consumed from

	public ConsumeAs(StorageClass store, ParamListStandard res) {
		super(res);
		resourceType = store;
	}

	@Override
	public AssignAction clone(ParamListStandard newResource) {
		return new ConsumeAs(resourceType, newResource);
	}

	@Override
	public boolean isEquivalent(AssignAction op) {
		if (this.getClass() != op.getClass()) {
			return false;
		}
		ConsumeAs otherAction = (ConsumeAs) op;
		if (resourceType != otherAction.resourceType) {
			return false;
		}
		return true;
	}

	@Override
	public int assignAddress(DataType dt, PrototypePieces proto, int pos, DataTypeManager dtManager,
			int[] status, ParameterPieces res) {
		return resource.assignAddressFallback(resourceType, dt, true, status, res);
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_CONSUME);
		encoder.writeString(ATTRIB_STORAGE, resourceType.toString());
		encoder.closeElement(ELEM_CONSUME);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_CONSUME.name());
		resourceType = StorageClass.getClass(elem.getAttribute(ATTRIB_STORAGE.name()));
		parser.end(elem);
	}
}
