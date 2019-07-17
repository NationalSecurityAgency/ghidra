/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.pcodeCPort.context;

import ghidra.pcodeCPort.slghsymbol.Constructor;

public class ParserWalkerChange extends ParserWalker {
	// Extension to walker that allows for on the fly modifications to tree
	ParserContext context;

	public ParserWalkerChange(ParserContext c) {
		super(c);
		context = c;
	}

	@Override
	public ParserContext getParserContext() {
		return context;
	}

	public ConstructState getPoint() {
		return point;
	}

	public void setOffset(int off) {
		point.offset = off;
	}

	public void setConstructor(Constructor c) {
		point.ct = c;
	}

	public void setCurrentLength(int len) {
		point.length = len;
	}

	public void calcCurrentLength(int length, int numopers) {
		// Calculate the length of the current constructor
		// state assuming all its operands are constructed
		length += point.offset;	// Convert relative length to absolute length
		for (int i = 0; i < numopers; ++i) {
			ConstructState subpoint = point.resolve.get(i);
			int sublength = subpoint.length + subpoint.offset;
			// Since subpoint->offset is an absolute offset
			// (relative to beginning of instruction) sublength
			if (sublength > length) {
				length = sublength;
			}
		}
		point.length = length - point.offset; // Convert back to relative length
	}
}
