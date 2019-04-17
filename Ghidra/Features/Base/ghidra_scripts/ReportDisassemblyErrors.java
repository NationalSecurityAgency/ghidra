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
// Reports the the number of disassembly error bookmarks currently in the program.
// This can be an "indicator" of bad analysis, strange instructions, or non-returning functions.
//
// Assumes a program is open.
//
//@category Examples

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.Iterator;

public class ReportDisassemblyErrors extends GhidraScript {

    public void run() throws Exception {
		    Program prog = currentProgram;
	    	Iterator<Bookmark> bookmarkIter = prog.getBookmarkManager().getBookmarksIterator("Error");
	    	int count = 0;
	    	while(bookmarkIter.hasNext()){
	    		bookmarkIter.next();
	    		count++;
	    	}

			Msg.info(this, "REPORT DISASSEMBLY ERROR BOOKMARKS: " + prog.getName() + ": " + count + " disassembly error bookmarks.");

	return;
    }
}
