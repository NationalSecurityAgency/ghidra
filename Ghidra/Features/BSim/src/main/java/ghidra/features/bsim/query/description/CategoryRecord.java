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

import ghidra.features.bsim.query.LSHException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

import java.io.IOException;
import java.io.Writer;

/**
 * A user-defined category associated associated with an executable
 * Specified by a -type- and then the particular -category- (within the type) that
 * the executable belongs to.
 *
 */
public class CategoryRecord implements Comparable<CategoryRecord> {

	private String type;			// The type of category  (must not be null)
	private String category;		// The type specific category

	public CategoryRecord(String t,String c) {
		type = t;
		category = c;		
	}
	
	public String getType() {
		return type;
	}
	
	public String getCategory() {
		return category;
	}
	
	@Override
	public boolean equals(Object obj) {
		CategoryRecord op2 = (CategoryRecord)obj;
		if (!type.equals(op2.type)) return false;
		return category.equals(op2.category);
	}

	@Override
	public int compareTo(CategoryRecord arg0) {
		int cmp = type.compareTo(arg0.type);
		if (cmp != 0)
			return cmp;
		if (category == null) {
			if (arg0.category == null) return 0;
			return -1;		// this precedes anything non-null
		}
		if (arg0.category==null)
			return 1;		// this comes after null
		return category.compareTo(arg0.category);
	}

	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append("  <category type=\"");
		fwrite.append(type);
		fwrite.append("\">");
		SpecXmlUtils.xmlEscapeWriter(fwrite, category);
		fwrite.append("</category>\n");		
	}
	
	public static CategoryRecord restoreXml(XmlPullParser parser) throws LSHException {
		XmlElement el = parser.start("category");
		String type = el.getAttribute("type");
		String category = parser.end().getText();
		if (type==null || category==null)
			throw new LSHException("Bad category tag");
		return new CategoryRecord(type,category);
	}
	
	public static boolean enforceTypeCharacters(String val) {
		if (val==null) return false;
		if (val.length()==0) return false;
		for(int i=0;i<val.length();++i) {
			char c = val.charAt(i);
			if (!Character.isLetterOrDigit(c)&&(c!=' ')&&(c!='.')&&(c!='_')&&(c!=':')&&(c!='/')&&(c!='(')&&(c!=')'))
				return false;
		}
		return true;
	}
}
