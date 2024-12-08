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
package ghidra.pcodeCPort.slghsymbol;

import static ghidra.pcode.utils.SlaFormat.*;

import java.io.IOException;

import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

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
	}

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

	public void encode(Encoder encoder) throws IOException {
		throw new IOException("Symbol " + name + " cannot be encoded directly");
	}

	protected final void encodeSleighSymbolHeader(Encoder encoder) throws IOException {
		encoder.writeString(ATTRIB_NAME, name);
		encoder.writeUnsignedInteger(ATTRIB_ID, id);
		encoder.writeUnsignedInteger(ATTRIB_SCOPE, scopeid);
	}

	// Save the basic attributes of a symbol
	protected void encodeHeader(Encoder encoder) throws IOException {
		encodeSleighSymbolHeader(encoder);
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
