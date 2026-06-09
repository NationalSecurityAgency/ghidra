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

import ghidra.program.model.lang.PrototypePieces;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * A filter that selects a range of function parameters that are considered optional.
 * If the underlying function prototype takes variable arguments, the first n
 * parameters (as determined by PrototypePieces.firstVarArgSlot) are considered non-optional.
 * If additional data-types are provided beyond the initial n, these are considered optional.
 * By default this filter matches on all parameters in a prototype with variable arguments.
 * Optionally, it can filter on a range of parameters that are specified relative to the
 * first variable argument.
 *    {@code <varargs first="0"/>}   - matches optional arguments but not non-optional ones.
 *    {@code <varargs first="0" last="0"/>}  -  matches the first optional argument.
 *    {@code <varargs first="-1"/>} - matches the last non-optional argument and all optional ones.
 */
public class VarargsFilter implements QualifierFilter {
	private int firstPos;		// Range of params to match (relative to first variable arg)
	private int lastPos;

	public VarargsFilter() {
		firstPos = Integer.MIN_VALUE;
		lastPos = Integer.MAX_VALUE;
	}

	public VarargsFilter(int first, int last) {
		firstPos = first;
		lastPos = last;
	}

	@Override
	public QualifierFilter clone() {
		return new VarargsFilter(firstPos, lastPos);
	}

	@Override
	public boolean isEquivalent(QualifierFilter op) {
		if (this.getClass() != op.getClass()) {
			return false;
		}
		VarargsFilter otherFilter = (VarargsFilter) op;
		return (firstPos == otherFilter.firstPos && lastPos == otherFilter.lastPos);
	}

	@Override
	public boolean filter(PrototypePieces proto, int pos) {
		if (proto.firstVarArgSlot < 0) {
			return false;
		}
		pos -= proto.firstVarArgSlot;
		return (pos >= firstPos && pos <= lastPos);
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_VARARGS);
		if (firstPos != Integer.MIN_VALUE) {
			encoder.writeSignedInteger(ATTRIB_FIRST, firstPos);
		}
		if (lastPos != Integer.MAX_VALUE) {
			encoder.writeSignedInteger(ATTRIB_LAST, lastPos);
		}
		encoder.closeElement(ELEM_VARARGS);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_VARARGS.name());
		String firstPosString = elem.getAttribute(ATTRIB_FIRST.name());
		if (firstPosString != null) {
			firstPos = SpecXmlUtils.decodeInt(firstPosString);
		}
		String lastPosString = elem.getAttribute(ATTRIB_LAST.name());
		if (lastPosString != null) {
			lastPos = SpecXmlUtils.decodeInt(lastPosString);
		}
		parser.end(elem);
	}
}
