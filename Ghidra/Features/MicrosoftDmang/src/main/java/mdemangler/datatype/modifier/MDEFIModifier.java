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
package mdemangler.datatype.modifier;

import java.util.ArrayList;
import java.util.List;

import mdemangler.MDMang;
import mdemangler.MDParsableItem;

/**
 * This class represents the E, F, I portions of a modifier type within a Microsoft
 *  mangled symbol.
 */
// TODO: come up with a better class name... MDPointerModifier?  MDAddressModifier <--*** ?
public class MDEFIModifier extends MDParsableItem {
	public static final char SPACE = ' ';

	public final static String PTR64 = "__ptr64";
	private static final String UNALIGNED = "__unaligned";
	private static final String RESTRICT = "__restrict";

	// EFI Modifiers
	private boolean isPointer64; // Can be pointer or reference
	private boolean isUnaligned;
	private boolean isRestrict;

	public MDEFIModifier(MDMang dmang) {
		super(dmang);
	}

	private enum CvPrefix {
		_PTR64, _UNALIGNED, _RESTRICT
	}

	private List<CvPrefix> prefixList = new ArrayList<>();

//	public MDEFIModifier() {
//		// use defaults
//	}

	public boolean isPointer64() {
		return isPointer64;
	}

	public boolean isUnaligned() {
		return isUnaligned;
	}

	public boolean isRestrict() {
		return isRestrict;
	}

	@Override
	protected void parseInternal() {
		boolean prefixDone = false;
		while (!prefixDone) {
			switch (dmang.peek()) {
				case 'E':
					isPointer64 = true;
					prefixList.add(CvPrefix._PTR64);
					dmang.increment();
					break;
				case 'F':
					isUnaligned = true;
					prefixList.add(CvPrefix._UNALIGNED);
					dmang.increment();
					break;
				case 'I':
					isRestrict = true;
					prefixList.add(CvPrefix._RESTRICT);
					dmang.increment();
					break;
				default:
					prefixDone = true;
					break;
			}
		}
	}

	public String emit(StringBuilder builder) {
		StringBuilder left = new StringBuilder();
		StringBuilder right = new StringBuilder();

		for (CvPrefix p : prefixList) {
			switch (p) {
				case _UNALIGNED:
					left.insert(0, UNALIGNED + SPACE);
					break;
				default:
					break;
			}
		}
//		ListIterator<cvPrefix> li = prefixList.listIterator(prefixList.size());
//		while (li.hasPrevious()) {
//			cvPrefix p = li.previous();
		for (CvPrefix p : prefixList) {
			switch (p) {
				case _PTR64:
					right.append(SPACE + PTR64);
					break;
				case _RESTRICT:
					right.append(SPACE + RESTRICT);
					break;
				default:
					break;
			}
		}
		if ((builder.length() == 0) && (left.length() != 0) && (right.length() != 0)) {
			left.setLength(left.length() - 1);
		}
		builder.insert(0, left);
		if ((builder.length() != 0) && (builder.charAt(builder.length() - 1) == ' ') &&
			(right.length() != 0) && (right.charAt(0) == ' ')) {
			builder.setLength(builder.length() - 1);
		}
		builder.append(right);
		return builder.toString();
	}
}

/******************************************************************************/
/******************************************************************************/
