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
package ghidra.features.bsim.query.protocol;

import java.io.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class ExeSpecifier implements Comparable<ExeSpecifier> {

	public String exename = "";
	public String arch = "";
	public String execompname = "";
	public String exemd5 = "";

	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append(" <exe>\n");
		if (exemd5.length() != 0) {
			fwrite.append("  <md5>").append(exemd5).append("</md5>\n");
			fwrite.append("  <name>");
			if (exename.length() != 0) {
				SpecXmlUtils.xmlEscapeWriter(fwrite, exename);
			}
			fwrite.append("</name>\n");
		}
		else {
			fwrite.append("  <name>");
			if (exename.length() != 0) {
				SpecXmlUtils.xmlEscapeWriter(fwrite, exename);
			}
			fwrite.append("</name>\n");
			fwrite.append("  <arch>");
			if (arch.length() != 0) {
				SpecXmlUtils.xmlEscapeWriter(fwrite, arch);
			}
			fwrite.append("</arch>\n");
			fwrite.append("  <compiler>");
			if (execompname.length() != 0) {
				SpecXmlUtils.xmlEscapeWriter(fwrite, execompname);
			}
			fwrite.append("</compiler>\n");
		}
		fwrite.append(" </exe>\n");
	}

	public void restoreXml(XmlPullParser parser) {
		parser.start();
		XmlElement el = parser.start();
		if (el.getName().equals("md5")) {
			exemd5 = parser.end().getText();
			parser.start();
			exename = parser.end().getText();
			arch = "";
			execompname = "";
		}
		else {
			exemd5 = "";
			exename = parser.end().getText();
			parser.start("arch");
			arch = parser.end().getText();
			parser.start("compiler");
			execompname = parser.end().getText();
		}
		parser.end();
	}

	public void transfer(ExecutableRecord op2) {
		exemd5 = op2.getMd5();
		exename = op2.getNameExec();
		arch = "";
		execompname = "";
	}

	public String getExeNameWithMD5() {
		StringBuilder buf = new StringBuilder();
		boolean addspace = false;
		if (!StringUtils.isBlank(exename)) {
			buf.append(exename);
			addspace = true;
		}
		if (!StringUtils.isBlank(exemd5)) {
			if (addspace) {
				buf.append(' ');
			}
			buf.append(exemd5);
		}
		return buf.toString();
	}

	@Override
	public boolean equals(Object obj) {
		ExeSpecifier o = (ExeSpecifier) obj;
		if (exemd5.length() != 0) {
			return exemd5.equals(o.exemd5);
		}
		boolean cmp = exename.equals(o.exename);
		if (!cmp) {
			return false;
		}
		cmp = arch.equals(o.arch);
		if (!cmp) {
			return false;
		}
		return execompname.equals(o.execompname);
	}

	@Override
	public int compareTo(ExeSpecifier o) {
		if (exemd5.length() != 0) {
			return exemd5.compareTo(o.exemd5);
		}
		int comp = exename.compareTo(o.exename);
		if (comp != 0) {
			return comp;
		}
		comp = arch.compareTo(o.arch);
		if (comp != 0) {
			return comp;
		}
		return execompname.compareTo(o.execompname);
	}
}
