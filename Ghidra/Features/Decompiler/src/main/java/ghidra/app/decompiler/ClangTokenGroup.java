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

import static ghidra.program.model.pcode.ElementId.*;

import java.awt.Color;
import java.util.*;
import java.util.stream.Stream;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.*;

/**
 * A sequence of tokens that form a meaningful group in source code.  This group may
 * break up into subgroups and may be part of a larger group.
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

	/**
	 * Add additional text to this group
	 * @param obj is the additional text
	 */
	public void AddTokenGroup(ClangNode obj) {
		Address minaddr = obj.getMinAddress();
		Address maxaddr = obj.getMaxAddress();

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
		tokgroup.add(obj);
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

	/**
	 * Decode this text from an encoded stream.
	 * @param decoder is the decoder for the stream
	 * @param pfactory is used to look up p-code attributes to associate with tokens
	 * @throws DecoderException for problems decoding the stream
	 */
	public void decode(Decoder decoder, PcodeFactory pfactory) throws DecoderException {
		for (;;) {
			int elem = decoder.openElement();
			if (elem == 0) {
				break;
			}
			if (elem == ELEM_RETURN_TYPE.id()) {
				ClangReturnType child = new ClangReturnType(this);
				child.decode(decoder, pfactory);
				AddTokenGroup(child);
			}
			else if (elem == ELEM_VARDECL.id()) {
				ClangVariableDecl child = new ClangVariableDecl(this);
				child.decode(decoder, pfactory);
				AddTokenGroup(child);
			}
			else if (elem == ELEM_STATEMENT.id()) {
				ClangStatement child = new ClangStatement(this);
				child.decode(decoder, pfactory);
				AddTokenGroup(child);
			}
			else if (elem == ELEM_FUNCPROTO.id()) {
				ClangFuncProto child = new ClangFuncProto(this);
				child.decode(decoder, pfactory);
				AddTokenGroup(child);
			}
			else if (elem == ELEM_BLOCK.id()) {
				ClangTokenGroup child = new ClangTokenGroup(this);
				child.decode(decoder, pfactory);
				AddTokenGroup(child);
			}
			else {
				ClangToken tok = ClangToken.buildToken(elem, this, decoder, pfactory);
				AddTokenGroup(tok);
			}
			decoder.closeElement(elem);
		}
	}

	/**
	 * @param c is a character
	 * @return true if the given character is a letter, digit, or underscore
	 */
	private static boolean isLetterDigitOrUnderscore(char c) {
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
