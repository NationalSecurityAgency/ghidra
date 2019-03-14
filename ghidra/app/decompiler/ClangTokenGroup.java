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
/*
 * Created on Jun 12, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.app.decompiler;

//import ghidra.app.plugin.core.decompile.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import ghidra.xml.*;

import java.awt.Color;
import java.util.*;

/**
 * 
 *
 * A node in a tree of C code tokens. 
 */
public class ClangTokenGroup implements ClangNode {
	private ClangNode parent;
	Address minaddress,maxaddress;
	private ArrayList<ClangNode> tokgroup;

	public ClangTokenGroup(ClangNode par) {
		parent=par;
		tokgroup = new ArrayList<ClangNode>();
		minaddress = null;
		maxaddress = null;
	}
	public Address getMinAddress() { return minaddress; }
	public Address getMaxAddress() { return maxaddress; }
	
	public void AddTokenGroup(Object obj) {
		Address minaddr = ((ClangNode)obj).getMinAddress();
		Address maxaddr = ((ClangNode)obj).getMaxAddress();
		
		if (minaddr != null) {
			if (minaddress == null)
				minaddress = minaddr;
			else if (minaddr.compareTo(minaddress)<0)
				minaddress = minaddr;
		}
		if (maxaddr != null) {
			if (maxaddress == null)
				maxaddress = maxaddr;
			else if (maxaddress.compareTo(maxaddr)<0)
				maxaddress = maxaddr;
		}
		tokgroup.add((ClangNode)obj);
	}
	
	public ClangNode Parent() { return parent; }
	public int numChildren() { return tokgroup.size(); }
	public ClangNode Child(int i) { return tokgroup.get(i); }
	public ClangFunction getClangFunction() { return parent.getClangFunction(); }

	public void setHighlight(Color val) {
		for(int i=0;i<tokgroup.size();++i)
			tokgroup.get(i).setHighlight(val);		
	}
	
	public void flatten(List<ClangNode> list) {
		for(int i=0;i<tokgroup.size();++i) {
			tokgroup.get(i).flatten(list);
		}
	}
	
	public void restoreFromXML(XmlPullParser parser,PcodeFactory pfactory) {
	    XmlElement node = parser.start(ClangXML.FUNCTION, ClangXML.RETURN_TYPE, ClangXML.VARDECL, ClangXML.STATEMENT, ClangXML.FUNCPROTO, ClangXML.BLOCK, ClangXML.VARIABLE, ClangXML.OP, ClangXML.SYNTAX, ClangXML.BREAK, ClangXML.FUNCNAME, ClangXML.TYPE, ClangXML.COMMENT, ClangXML.LABEL);
		while(parser.peek().isStart()) {
		    XmlElement elem = parser.peek();
			if (elem.getName().equals(ClangXML.RETURN_TYPE)) {
				ClangReturnType child = new ClangReturnType(this);
				child.restoreFromXML(parser,pfactory);
				AddTokenGroup(child);
			}
			else if (elem.getName().equals(ClangXML.VARDECL)) {
				ClangVariableDecl child = new ClangVariableDecl(this);
				child.restoreFromXML(parser,pfactory);
				AddTokenGroup(child);
			}
			else if (elem.getName().equals(ClangXML.STATEMENT)) {
				ClangStatement child = new ClangStatement(this);
				child.restoreFromXML(parser,pfactory);
				AddTokenGroup(child);
			}
			else if (elem.getName().equals(ClangXML.FUNCPROTO)) {
				ClangFuncProto child = new ClangFuncProto(this);
				child.restoreFromXML(parser,pfactory);
				AddTokenGroup(child);
			}
			else if (elem.getName().equals(ClangXML.BLOCK)) {
				ClangTokenGroup child = new ClangTokenGroup(this);
				child.restoreFromXML(parser,pfactory);
				AddTokenGroup(child);
			}
			else {
				ClangToken tok = ClangToken.buildToken(this,parser,pfactory);
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
	        if (lastTokenStr != null && 
	        		isLetterDigitOrUnderscore(tokenStr.charAt(0)) && 
	        		isLetterDigitOrUnderscore(lastTokenStr.charAt(lastTokenStr.length()-1))) {
	        	// avoid concatenating names together
	        	buffer.append(' ');
	        }
	        lastTokenStr = tokenStr;
	        buffer.append(tokenStr);
	    }
	    return buffer.toString();
	}
}
