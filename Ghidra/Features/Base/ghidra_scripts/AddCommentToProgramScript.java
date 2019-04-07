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
//@category Examples

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;


public class AddCommentToProgramScript extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address minAddress = currentProgram.getMinAddress();
        Listing listing = currentProgram.getListing();
        CodeUnit codeUnit = listing.getCodeUnitAt( minAddress );
        codeUnit.setComment( CodeUnit.PLATE_COMMENT, "AddCommentToProgramScript - This is an added comment!" );
    }
}
