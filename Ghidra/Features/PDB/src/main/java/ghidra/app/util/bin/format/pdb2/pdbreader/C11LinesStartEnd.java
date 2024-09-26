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
package ghidra.app.util.bin.format.pdb2.pdbreader;

/**
 * An individual PDB C11 Line Start/End record (think these are offsets in a segment)
 */
public class C11LinesStartEnd {
	private long start; // unsigned long
	private long end; // unsigned long

	public void parse(PdbByteReader reader) throws PdbException {
		start = reader.parseUnsignedIntVal();
		end = reader.parseUnsignedIntVal();
	}

	/**
	 * Returns the start line value
	 * @return the start value
	 */
	public long getStart() {
		return start;
	}

	/**
	 * Returns the end line value
	 * @return the end value
	 */
	public long getEnd() {
		return end;
	}
}
