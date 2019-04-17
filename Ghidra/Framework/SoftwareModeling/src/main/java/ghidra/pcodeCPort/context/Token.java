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
package ghidra.pcodeCPort.context;

public class Token {

	private String name;
	private int size; // Number of bytes in token;
	private int index; // Index of this token, for resolving offsets
	private boolean bigendian;

	public Token( String nm, int sz, boolean be, int ind ) {
		name = nm;
		size = sz;
		bigendian = be;
		index = ind;
	}

	public int getSize() {
		return size;
	}

	public boolean isBigEndian() {
		return bigendian;
	}

	public int getIndex() {
		return index;
	}

	public String getName() {
		return name;
	}

	@Override
    public String toString() {
	    return "Token{" + name + ":" + size + ":" + index + ":" + (bigendian ? "big" : "little") + "}";
	}
}
