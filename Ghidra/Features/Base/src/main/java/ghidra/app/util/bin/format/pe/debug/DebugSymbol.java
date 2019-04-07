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
package ghidra.app.util.bin.format.pe.debug;

/**
 * A base class for Object Module Format (OMF) symbols.
 * 
 */
public abstract class DebugSymbol {
	protected short  length;
	protected short  type;
	protected String name;
	protected short  section;
	protected int    offset;

	protected DebugSymbol() { }

	protected void processDebugSymbol(short length, short type) {
		this.length = length;
		this.type   = type;
	}

	/**
	 * Returns the length of the symbol.
	 * @return the length of the symbol
	 */
	public short getLength() {
		return length;
	}

	/**
	 * Returns the type of the symbol.
	 * @return the type of the symbol
	 */
	public short getType() {
		return type;
	}

    /**
     * Returns the name of the symbol.
     * @return the name of the symbol
     */
    public String getName() {
    	return name;
    }

    /**
     * Returns the section number.
     * @return the section number
     */
    public short getSection() {
    	return section;
    }

    /**
     * Returns the offset.
     * @return the offset
     */
    public int getOffset() {
    	return offset;
    }
}
