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
package ghidra.util.bytesearch;

import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * ByteSearch post search rule when a pattern is found, The pattern must have a certain
 * alignment at an offset from the location the pattern matches.  The alignment is
 * specified by the mask bits that must be zero.
 * 
 *   mark is the offset in bytes from the start of the matching pattern.
 *   
 *   align 2 = 0x1 - lower bit must be zero
 *   align 4 = 0x3 - lower two bits must be zero
 *   align 8 = 0x7 - lower three bits must be zero
 *   align 16 = 0xF - lower four bits must be zero
 *   ....
 * Other strange alignments could be specified, but most likely the above suffice.
 * 
 * The pattern can be constructed or restored from XML of the form:
 * 
 *     <align mark="0" bits="1"/>
 *   
 */

public class AlignRule implements PostRule {

	private int mark;		// Position, relative to start of pattern, to check alignment at
	private int alignmask;  // Mask of bits that must be zero

	public AlignRule() {
	}

	public AlignRule(int mark, int alignmask) {
		this.mark = mark;
		this.alignmask = alignmask;
	}

	@Override
	public boolean apply(Pattern pat, long matchoffset) {
		int off = (int) matchoffset;
		return (((off + mark) & alignmask) == 0);
	}

	@Override
	public void restoreXml(XmlPullParser parser) {
		XmlElement el = parser.start("align");
		mark = SpecXmlUtils.decodeInt(el.getAttribute("mark"));
		int bits = SpecXmlUtils.decodeInt(el.getAttribute("bits"));
		alignmask = (1 << bits) - 1;
		parser.end();
	}

	public int getAlignMask() {
		return alignmask;
	}

}
