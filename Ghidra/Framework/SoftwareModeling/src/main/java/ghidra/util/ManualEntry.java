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
package ghidra.util;

public class ManualEntry {
    private final String mnemonic;
    private final String manualPath;
    private final String missingManualDescription;
    private final String pageNumber;

    public String getMnemonic() {
        return mnemonic;
    }

    public String getManualPath() {
        return manualPath;
    }

    public String getMissingManualDescription() {
        return missingManualDescription;
    }

    public String getPageNumber() {
        return pageNumber;
    }

    public ManualEntry(String mnemonic, String manualPath, String missingManualDescription, String pageNumber) {
        this.mnemonic = mnemonic;
        this.manualPath = manualPath;
        this.missingManualDescription = missingManualDescription;
        this.pageNumber = pageNumber;
    }
}
