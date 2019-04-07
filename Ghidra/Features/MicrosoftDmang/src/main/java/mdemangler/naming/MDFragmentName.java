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
package mdemangler.naming;

import mdemangler.*;

/**
 * This class represents a name fragment within a Microsoft mangled symbol.
 */
public class MDFragmentName extends MDParsableItem {
	private String name;
	private boolean stripTerminator = true;

	public MDFragmentName(MDMang dmang) {
		super(dmang);
	}

	public void keepTerminator() {
		stripTerminator = false;
	}

	@Override
	public void insert(StringBuilder builder) {
		dmang.insertString(builder, name);
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	@Override
	protected void parseInternal() throws MDException {
		// MDMANG SPECIALIZATION USED.
		name = dmang.parseFragmentName(this);
		// The stripping of the '@' character must occur after the
		// specialization call--not
		// inside one of the special routines below. If not, it affects at least
		// one of
		// the specializations (MDMangGenericize) in an adverse way.
		if ((dmang.peek() == '@') && stripTerminator) {
			dmang.increment(); // Skip past the '@'
		}
	}

	public String parseFragmentName_Md() {
		StringBuilder frag = new StringBuilder();
		char ch;
		while ((ch = dmang.peek()) != MDMang.DONE) {
			if (!(Character.isLetter(ch) || Character.isDigit(ch) || ch == '_' || ch == '$' ||
				ch == '<' || ch == '>' || ch == '-' || ch == '.')) {
				break;
			}
			frag.append(ch);
			dmang.next();
		}
		return frag.toString();
	}

	public String parseFragmentName_VS2All() throws MDException {
		StringBuilder frag = new StringBuilder();
		char ch;
		while ((ch = dmang.peek()) != MDMang.DONE) {
			if (ch == '.') {
				throw new MDException("Illegal '.' character in MDFragmentName");
			}
			if (!(Character.isLetter(ch) || Character.isDigit(ch) || ch == '_' || ch == '$' ||
				ch == '<' || ch == '>' || ch == '-')) { // No '.' for VS2015
				break;
			}
			frag.append(ch);
			dmang.next();
		}
		return frag.toString();
	}

}

/******************************************************************************/
/******************************************************************************/
