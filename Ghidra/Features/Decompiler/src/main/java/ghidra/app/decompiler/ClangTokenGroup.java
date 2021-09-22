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
package ghidra.app.decompiler;

import java.awt.Color;
import java.util.*;
import java.util.stream.Stream;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeFactory;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * A node in a tree of C code tokens. 
 */
public class ClangTokenGroup implements ClangNode, Iterable<ClangNode> {
	private ClangNode parent;
	Address minaddress, maxaddress;
	private ArrayList<ClangNode> tokgroup;

	public ClangTokenGroup(ClangNode par) {
		parent = par;
		tokgroup = new ArrayList<>();
		minaddress = null;
		maxaddress = null;
	}

	@Override
	public Address getMinAddress() {
		return minaddress;
	}

	@Override
	public Address getMaxAddress() {
		return maxaddress;
	}

	public void AddTokenGroup(Object obj) {
		Address minaddr = ((ClangNode) obj).getMinAddress();
		Address maxaddr = ((ClangNode) obj).getMaxAddress();

		if (minaddr != null) {
			if (minaddress == null) {
				minaddress = minaddr;
			}
			else if (minaddr.compareTo(minaddress) < 0) {
				minaddress = minaddr;
			}
		}
		if (maxaddr != null) {
			if (maxaddress == null) {
				maxaddress = maxaddr;
			}
			else if (maxaddress.compareTo(maxaddr) < 0) {
				maxaddress = maxaddr;
			}
		}
		tokgroup.add((ClangNode) obj);
	}

	@Override
	public ClangNode Parent() {
		return parent;
	}

	@Override
	public int numChildren() {
		return tokgroup.size();
	}

	@Override
	public ClangNode Child(int i) {
		return tokgroup.get(i);
	}

	@Override
	public ClangFunction getClangFunction() {
		return parent.getClangFunction();
	}

	@Override
	public void setHighlight(Color val) {
		for (ClangNode element : tokgroup) {
			element.setHighlight(val);
		}
	}

	@Override
	public void flatten(List<ClangNode> list) {
		for (ClangNode element : tokgroup) {
			element.flatten(list);
		}
	}

	public void restoreFromXML(XmlPullParser parser, PcodeFactory pfactory) {
		XmlElement node = parser.start(ClangXML.FUNCTION, ClangXML.RETURN_TYPE, ClangXML.VARDECL,
			ClangXML.STATEMENT, ClangXML.FUNCPROTO, ClangXML.BLOCK, ClangXML.VARIABLE, ClangXML.OP,
			ClangXML.SYNTAX, ClangXML.BREAK, ClangXML.FUNCNAME, ClangXML.TYPE, ClangXML.COMMENT,
			ClangXML.LABEL);
		while (parser.peek().isStart()) {
			XmlElement elem = parser.peek();
			if (elem.getName().equals(ClangXML.RETURN_TYPE)) {
				ClangReturnType child = new ClangReturnType(this);
				child.restoreFromXML(parser, pfactory);
				AddTokenGroup(child);
			}
			else if (elem.getName().equals(ClangXML.VARDECL)) {
				ClangVariableDecl child = new ClangVariableDecl(this);
				child.restoreFromXML(parser, pfactory);
				AddTokenGroup(child);
			}
			else if (elem.getName().equals(ClangXML.STATEMENT)) {
				ClangStatement child = new ClangStatement(this);
				child.restoreFromXML(parser, pfactory);
				AddTokenGroup(child);
			}
			else if (elem.getName().equals(ClangXML.FUNCPROTO)) {
				ClangFuncProto child = new ClangFuncProto(this);
				child.restoreFromXML(parser, pfactory);
				AddTokenGroup(child);
			}
			else if (elem.getName().equals(ClangXML.BLOCK)) {
				ClangTokenGroup child = new ClangTokenGroup(this);
				child.restoreFromXML(parser, pfactory);
				AddTokenGroup(child);
			}
			else {
				ClangToken tok = ClangToken.buildToken(this, parser, pfactory);
				AddTokenGroup(tok);
			}
		}
		parser.end(node);
	}

	private boolean isLetterDigitOrUnderscore(char c) {
		return Character.isLetterOrDigit(c) || c == '_';
	}

	@Override
	public String toString() {
		String lastTokenStr = null;
		StringBuffer buffer = new StringBuffer();
		Iterator<ClangNode> iter = tokgroup.iterator();
		while (iter.hasNext()) {
			ClangNode node = iter.next();
			String tokenStr = node.toString();
			if (tokenStr.length() == 0) {
				continue;
			}
			if (lastTokenStr != null && isLetterDigitOrUnderscore(tokenStr.charAt(0)) &&
				isLetterDigitOrUnderscore(lastTokenStr.charAt(lastTokenStr.length() - 1))) {
				// avoid concatenating names together
				buffer.append(' ');
			}
			lastTokenStr = tokenStr;
			buffer.append(tokenStr);
		}
		return buffer.toString();
	}

	@Override
	public Iterator<ClangNode> iterator() {
		return tokgroup.iterator();
	}

	/**
	 * Gets a stream over this group's children
	 * @return a stream of this group's children
	 */
	public Stream<ClangNode> stream() {
		return tokgroup.stream();
	}
}
