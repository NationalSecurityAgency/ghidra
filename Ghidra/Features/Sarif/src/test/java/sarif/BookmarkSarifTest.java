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
package sarif;

import org.junit.Test;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.util.ProgramDiff;

public class BookmarkSarifTest extends AbstractSarifTest {

	public BookmarkSarifTest() {
		super();
	}

	@Test
	public void testBookMarks() throws Exception {
		block.putBytes(entry, asm, 0, asm.length);

		BookmarkManager bookmarkManager = program.getBookmarkManager();
		bookmarkManager.setBookmark(entry, "Alpha", "Assembly Succeeded", "first");
		bookmarkManager.setBookmark(entry.add(1), "Beta", "Assembly Failed", "second");
		Bookmark mark = bookmarkManager.setBookmark(entry.add(2), "Gamma", "Bookmark Removed", "third");
		bookmarkManager.removeBookmark(mark);

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

}
