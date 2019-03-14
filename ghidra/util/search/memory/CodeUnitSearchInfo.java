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
package ghidra.util.search.memory;

public class CodeUnitSearchInfo {

    private final boolean searchInstructions;
    private final boolean searchDefinedData;
    private final boolean searchUndefinedData;

    public CodeUnitSearchInfo( boolean searchInstructions, boolean searchDefinedData, 
            boolean searchUndefinedData ) {
        this.searchInstructions = searchInstructions;
        this.searchDefinedData = searchDefinedData;
        this.searchUndefinedData = searchUndefinedData;
    }

    public boolean isSearchInstructions() {
        return searchInstructions;
    }

    public boolean isSearchDefinedData() {
        return searchDefinedData;
    }

    public boolean isSearchUndefinedData() {
        return searchUndefinedData;
    }
    
    public boolean searchAll() {
        return searchInstructions && searchDefinedData && searchUndefinedData;
    }
}
