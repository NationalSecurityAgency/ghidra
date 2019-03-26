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
package ghidra.app.util.bin.format.pe;

public class ImportInfo {
    private int address;
    private String comment;
    private String dll;
    private String name;
    private boolean isBound;

    ImportInfo(int address, String cmt, String dll, String name, boolean isBound) {
        this.address = address;
        this.comment = cmt;
        this.dll     = dll.toUpperCase();
        this.name    = name;
        this.isBound = isBound;
    }

	/**
	 * Returns the adjusted address where the import occurs.
	 * @return the adjusted address where the import occurs
	 */
    public int getAddress() {
        return address;
    }

	/**
	 * Returns a comment string containing extra information about the import.
	 * @return a comment string containing extra information about the import
	 */
    public String getComment() {
        return comment;
    }

	/**
	 * Returns the name of the imported DLL.
	 * @return the name of the imported DLL
	 */
    public String getDLL() {
        return dll;
    }

	/**
	 * Returns the name of the imported symbol.
	 * @return the name of the imported symbol
	 */
    public String getName() {
        return name;
    }

	/**
	 * Returns true if this is a bound import.
	 * @return true if this is a bound import
	 */
    public boolean isBound() {
        return isBound;
    }
}
