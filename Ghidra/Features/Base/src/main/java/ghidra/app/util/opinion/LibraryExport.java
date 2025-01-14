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
package ghidra.app.util.opinion;

import org.jdom.Element;

public class LibraryExport {

	private int ordinal;
	private String symbolName;
	private int purge;
	private String comment;
	private String forwardLibName;
	private String forwardSymName;

	private String noReturnStr;
	private boolean noReturn;
	

	public LibraryExport(Element export) {
		ordinal = Integer.parseInt(export.getAttributeValue("ORDINAL"));
		symbolName = export.getAttributeValue("NAME");
		purge = Integer.parseInt(export.getAttributeValue("PURGE"));
		comment = export.getAttributeValue("COMMENT");
		forwardLibName = export.getAttributeValue("FOWARDLIBRARY");
		forwardSymName = export.getAttributeValue("FOWARDSYMBOL");

		noReturnStr = export.getAttributeValue("NO_RETURN");
		noReturn = noReturnStr != null && "y".equals(noReturnStr);
	}


	public int getOrdinal() {
		return ordinal;
	}


	public String getName() {
		return symbolName;
	}


	public int getPurge() {
		return purge;
	}


	public String getComment() {
		return comment;
	}


	public String getForwardLibName() {
		return forwardLibName;
	}


	public String getForwardSymName() {
		return forwardSymName;
	}


	public String getNoReturnStr() {
		return noReturnStr;
	}


	public boolean isNoReturn() {
		return noReturn;
	}

}
