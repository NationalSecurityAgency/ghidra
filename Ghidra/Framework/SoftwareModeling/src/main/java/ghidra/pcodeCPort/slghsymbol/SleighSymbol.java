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
package ghidra.pcodeCPort.slghsymbol;

import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.utils.XmlUtils;
import ghidra.sleigh.grammar.Location;

import java.io.PrintStream;

import org.jdom.Element;

public class SleighSymbol implements Comparable<SleighSymbol> {
	@Override
	public String toString() {
		return name;
	}

	public String toDetailedString() {
		return name + "-" + scopeid + ":" + id;
	}

	private String name;
	int id; // Unique id across all symbols
	int scopeid; // Unique id of scope this symbol is in
	private boolean wasSought = false;

	public void setWasSought(boolean wasSought) {
		this.wasSought = wasSought;
	}

	public boolean wasSought() {
		return wasSought;
	}

	public SleighSymbol(Location location) {
		this.location = location;
	} // For use with restoreXml

	public SleighSymbol(Location location, String nm) {
		this.location = location;
		name = nm;
		id = 0;
	}

	public void dispose() {
	}

	public String getName() {
		return name;
	}

	public int getId() {
		return id;
	}

	public symbol_type getType() {
		return symbol_type.dummy_symbol;
	}

	public void saveXml(PrintStream s) {
	}

	public void restoreXml(Element el, SleighBase trans) {
	}

	protected final void saveSleighSymbolXmlHeader(PrintStream s) {
		s.append(" name=\"").append(name).append("\"");
		s.append(" id=\"0x").print(Long.toHexString(id));
		s.append("\"");
		s.append(" scope=\"0x");
		s.print(Long.toHexString(scopeid));
		s.append("\"");
	}

	// Save the basic attributes of a symbol
	protected void saveXmlHeader(PrintStream s) {
		saveSleighSymbolXmlHeader(s);
	}

	void restoreXmlHeader(Element el) {
		name = el.getAttributeValue("name");
		id = XmlUtils.decodeUnknownInt(el.getAttributeValue("id"));
		scopeid = XmlUtils.decodeUnknownInt(el.getAttributeValue("scope"));
	}

	@Override
	public int compareTo(SleighSymbol o) {
		return id - o.id;
	}

	public final Location location;

	public Location getLocation() {
		return location;
	}

	public void setLocation(Location location) {
//        this.location = location;
	}
}
