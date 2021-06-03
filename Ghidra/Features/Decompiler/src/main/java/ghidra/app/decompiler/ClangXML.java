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
/*
 * Created on Jun 18, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.app.decompiler;

import ghidra.program.model.pcode.*;
import ghidra.xml.*;
/**
 * 
 *
 * To change the template for this generated type comment go to
 *{@literal Window>Preferences>Java>Code Generation>Code and Comments}
 */
public abstract class ClangXML {			// Placeholder for CLANG XML identifiers

	public static final String DOCUMENT = "clang_document";
	public static final String FUNCTION = "function";
	public static final String BLOCK = "block";
	public static final String RETURN_TYPE = "return_type";
	public static final String VARDECL = "vardecl";
	public static final String STATEMENT = "statement";
	public static final String FUNCPROTO = "funcproto";
	public static final String SYNTAX = "syntax";
	public static final String BREAK = "break";
	public static final String VARIABLE = "variable";
	public static final String OP = "op";
	public static final String FUNCNAME="funcname";
	public static final String TYPE = "type";
	public static final String FIELD = "field";
	public static final String COMMENT = "comment";
	public static final String LABEL = "label";

// Attributes	
	public static final String INDENT="indent";
	public static final String COLOR="color";
	public static final String OPREF = "opref";
	public static final String BLOCKREF = "blockref";
	public static final String VARNODEREF="varref";
	public static final String SPACE="space";
	public static final String OFFSET="off";
	public static final String PCSPACE="pcspace";
	public static final String PCOFFSET="pcoff";
	public static final String SYMREF="symref";

// Attribute values
   public static final String KEYWORD_COLOR = "keyword";
   public static final String COMMENT_COLOR ="comment";
   public static final String TYPE_COLOR = "type";
   public static final String FUNCNAME_COLOR = "funcname";
   public static final String VARIABLE_COLOR = "var";
   public static final String CONST_COLOR = "const";
   public static final String PARAMETER_COLOR = "param";
   public static final String GLOBAL_COLOR = "global";
   
   public static ClangTokenGroup buildClangTree(XmlPullParser parser,HighFunction hfunc) {
		ClangTokenGroup docroot;
		if (parser.peek().getName().equals("function"))
			docroot = new ClangFunction(null,hfunc);
		else
			docroot = new ClangTokenGroup(null);
		docroot.restoreFromXML(parser,hfunc);
		return docroot;
   }
}
