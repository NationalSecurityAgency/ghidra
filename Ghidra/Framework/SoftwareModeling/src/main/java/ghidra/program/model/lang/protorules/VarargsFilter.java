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

import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;

import ghidra.program.model.lang.PrototypePieces;
import ghidra.program.model.pcode.Encoder;
import ghidra.xml.*;

/**
 * A filter that selects function parameters that are considered optional.
 * If the underlying function prototype is considered to take variable arguments, the first
 * n parameters (as determined by PrototypePieces.firstVarArgSlot) are considered non-optional.
 * If additional data-types are provided beyond the initial n, these are considered optional.
 * This filter returns true for these optional parameters
 */
public class VarargsFilter implements QualifierFilter {
	@Override
	public QualifierFilter clone() {
		return new VarargsFilter();
	}

	@Override
	public boolean isEquivalent(QualifierFilter op) {
		return (this.getClass() == op.getClass());
	}

	@Override
	public boolean filter(PrototypePieces proto, int pos) {
		if (proto.firstVarArgSlot < 0) {
			return false;
		}
		return (pos >= proto.firstVarArgSlot);
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_VARARGS);
		encoder.closeElement(ELEM_VARARGS);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_VARARGS.name());
		parser.end(elem);
	}
}
