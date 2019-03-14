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

/**
 * A class to hold the information extracted from a 
 * delay import descriptor.
 * 
 * NOTE:
 * This class is simply a storage class created for 
 * parsing the PE header data structures.
 * It does not map back to a PE data data structure.
 * 
 * 
 */
public class DelayImportInfo {
    private long ordinal;
    private String name;

    DelayImportInfo(long ordinal) {
        this.ordinal = ordinal;
    }

    DelayImportInfo(int ordinal, String name) {
        this.ordinal = ordinal;
        this.name = name;
    }

	/**
	 * Returns the ordinal number of the imported DLL.
	 * @return the ordinal number of the imported DLL
	 */
    public long getOrdinal() {
        return ordinal;
    }

	/**
	 * Returns the name of the imported DLL.
	 * @return the name of the imported DLL
	 */
    public String getName() {
        return name;
    }

	/**
	 * Returns true if the import is 'by name'.
	 * @return true if the import is 'by name'
	 */
    public boolean hasName() {
        return name != null;
    }
}
