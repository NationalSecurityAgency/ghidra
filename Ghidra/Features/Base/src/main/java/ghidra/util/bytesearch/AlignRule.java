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
 * ByteSearch post search rule when a pattern is found. Used when a pattern must have a certain
 * alignment at an offset from the location the pattern matches. 
 * 
 * The pattern can be constructed or restored from XML of the form,
 * where alignOffset=mark, alignmask=bits
 * 
 *     <align mark="0" bits="1"/>
 *   
 */

public class AlignRule implements PostRule {

	private int alignOffset;  // Position, relative to start of pattern, to check alignment at
	private int alignmask;    // Mask of bits that must be zero

	public AlignRule() {
	}

	/**
	 * ByteSearch post search rule when a pattern is found. Used when a pattern must have a certain
	 * alignment at an offset from the location the pattern matches. The alignment is
	 * specified by the alignmask bits that must be zero.
	 * 
	 *   Normally alignOffset is 0, since most patterns will match at the address that must be aligned
	 *   To align a match, use the following
	 *
	 *  align to  2 = alignmask 0x1 - lower bit must be zero
	 *  align to  4 = alignmask 0x3 - lower two bits must be zero
	 *  align to  8 = alignmask 0x7 - lower three bits must be zero
	 *  align to 16 = alignmask 0xF - lower four bits must be zero
	 *  ....
	 *  Other strange alignments could be specified, but most likely the above suffice.
	 * @param alignOffset - bytes offset from pattern to check for alignment
	 * @param alignmask - the mask where a 1 bit must be zero
	 */
	public AlignRule(int alignOffset, int alignmask) {
		this.alignOffset = alignOffset;
		this.alignmask = alignmask;
	}

	@Override
	public boolean apply(Pattern pat, long matchoffset) {
		int off = (int) matchoffset;
		return (((off + alignOffset) & alignmask) == 0);
	}

	@Override
	public void restoreXml(XmlPullParser parser) {
		XmlElement el = parser.start("align");
		alignOffset = SpecXmlUtils.decodeInt(el.getAttribute("mark"));
		int bits = SpecXmlUtils.decodeInt(el.getAttribute("bits"));
		alignmask = (1 << bits) - 1;
		parser.end();
	}

	public int getAlignMask() {
		return alignmask;
	}

}
