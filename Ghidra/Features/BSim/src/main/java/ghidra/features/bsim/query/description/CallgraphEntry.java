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
package ghidra.features.bsim.query.description;

import java.io.IOException;
import java.io.Writer;

import ghidra.features.bsim.query.LSHException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class CallgraphEntry implements Comparable<CallgraphEntry> {
	private FunctionDescription dest;	// Function being called
	private int lochash;				// Location hash of callsite
	
	public CallgraphEntry(FunctionDescription d,int lhash) {
		dest = d;
		lochash = lhash;
	}
	
	public FunctionDescription getFunctionDescription() { return dest; }
	
	public int getLocalHash() { return lochash; }
	
	public void saveXml(FunctionDescription src,Writer fwrite) throws IOException {
		StringBuilder buf = new StringBuilder();
		buf.append("<call");
		SpecXmlUtils.xmlEscapeAttribute(buf, "dest", dest.getFunctionName());
		if (dest.getAddress() != -1) {
			SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "addr", dest.getAddress());
		}
		if (lochash != 0) {
			SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "local", lochash);
		}
		ExecutableRecord srcexe = src.getExecutableRecord();
		ExecutableRecord destexe = dest.getExecutableRecord();
		if (srcexe != destexe) {		// Compare as objects
			buf.append(">\n");
			if (!destexe.isLibrary()) {
				buf.append("  <md5>").append(destexe.getMd5()).append("</md5>\n");
			}
			buf.append("  <name>");
			SpecXmlUtils.xmlEscape(buf, destexe.getNameExec());
			buf.append("</name>\n");
			if (!srcexe.getArchitecture().equals(destexe.getArchitecture())) {
				buf.append("  <arch>");
				SpecXmlUtils.xmlEscape(buf, destexe.getArchitecture());
				buf.append("</arch>\n");
			}
			if (!srcexe.getNameCompiler().equals(destexe.getNameCompiler())) {
				buf.append("  <compiler>");
				SpecXmlUtils.xmlEscape(buf, destexe.getNameCompiler());
				buf.append("</compiler>\n");
			}
			buf.append("</call>\n");
		}
		else {
			buf.append("/>\n");
		}
		fwrite.append(buf.toString());
	}
	
	static public void restoreXml(XmlPullParser parser,DescriptionManager man,FunctionDescription src) throws LSHException {
		XmlElement el = parser.start("call");
		String destnm = el.getAttribute("dest");
		long address = -1;			// Default if no "addr" attribute present
		String addrString = el.getAttribute("addr");
		if (addrString != null) {
			address = SpecXmlUtils.decodeLong(addrString);
		}
		int val = SpecXmlUtils.decodeInt(el.getAttribute("local"));
		if (parser.peek().isStart()) {
			ExecutableRecord srcexe = src.getExecutableRecord();
			String md5 = null;
			String dest_enm = null;
			String dest_cnm = srcexe.getNameCompiler();
			String dest_arch = srcexe.getArchitecture();
			do {
				String elname = parser.next().getName();
				String content = parser.end().getText();
				if (elname.equals("md5")) {
					md5 = content;
				}
				else if (elname.equals("name")) {
					dest_enm = content;
				}
				else if (elname.equals("compiler")) {
					dest_cnm = content;
				}
				else if (elname.equals("arch")) {
					dest_arch = content;
				}
			} while(parser.peek().isStart());
			if (md5 == null) {
				ExecutableRecord destexe = man.newExecutableLibrary(dest_enm,dest_arch,null);
				FunctionDescription destfunc = man.newFunctionDescription(destnm, address, destexe);
				man.makeCallgraphLink(src, destfunc, val);
			}
			else {
				ExecutableRecord destexe = man.newExecutableRecord(md5, dest_enm, dest_cnm, dest_arch, null, srcexe.getRepository(), srcexe.getPath(), null);
				FunctionDescription destfunc = man.newFunctionDescription(destnm, address, destexe);
				man.makeCallgraphLink(src, destfunc, val);
			}
		}
		else {	// Assume dest is in same executable as src
			FunctionDescription destfunc =
				man.newFunctionDescription(destnm, address, src.getExecutableRecord());
			man.makeCallgraphLink(src, destfunc, val);
		}
		parser.end();
	}

	@Override
	public int compareTo(CallgraphEntry o) {
		return dest.compareTo(o.dest);
	}
	
}
