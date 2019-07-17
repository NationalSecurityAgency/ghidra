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
 * Created on Feb 7, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.symbol;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.program.model.lang.*;
import ghidra.util.xml.*;
import ghidra.xml.*;

/**
 * 
 *
 * Base class for symbols in sleigh
 */
public abstract class Symbol {
	private String name;
	private int id;			// Unique id across all symbols
	private int scopeid;	// id of scope this symbol is in
	
	public String getName() { return name; }
	public int getId() { return id; }
	public int getScopeId() { return scopeid; }
	
	public void restoreHeaderXml(XmlPullParser parser) {
	    XmlElement el = parser.start();
		name = el.getAttribute("name");
		id = SpecXmlUtils.decodeInt(el.getAttribute("id"));
		scopeid = SpecXmlUtils.decodeInt(el.getAttribute("scope"));
		parser.end(el);
	}
	
	public abstract void restoreXml(XmlPullParser parser,SleighLanguage sleigh) throws UnknownInstructionException;	// Always overridden by subclass
}
