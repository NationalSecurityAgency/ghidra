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
package ghidra.feature.vt.api.markupitem;

import static ghidra.feature.vt.db.VTTestUtils.addr;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.markuptype.EolCommentMarkupType;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.feature.vt.gui.task.ApplyMarkupItemTask;
import ghidra.program.model.listing.CodeUnit;
import ghidra.util.task.TaskMonitor;

public class ApplyMultipleMarkupItemsTest extends AbstractVTMarkupItemTest {

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		sourceBuilder.createComment("1002248", "Comment 1", CodeUnit.EOL_COMMENT);
		sourceBuilder.createComment("100224b", "Comment 2", CodeUnit.EOL_COMMENT);
		sourceProgram = sourceBuilder.getProgram();

	}

	@Test
	public void testApplyMultipleMarkupItemsSomeGoodSomeBad() throws Exception {

		VTSessionDB session = createNewSession();
		VTMatch match = createMatchSetWithOneMatch(session, addr("1002239", sourceProgram),
			addr("1002239", destinationProgram));
		List<VTMarkupItem> items =
			EolCommentMarkupType.INSTANCE.createMarkupItems(match.getAssociation());

		// make the first item have an illegal destination address and then make sure the other
		// one still gets applied using the ApplyMarkupTask

		int id = session.startTransaction("test");

		items.get(0).setDestinationAddress(addr("0x100224c", destinationProgram));

		ApplyMarkupItemTask task = new ApplyMarkupItemTask(session, items, new VTOptions("Test"));
		task.run(TaskMonitor.DUMMY);
		session.endTransaction(id, true);
		assertTrue(task.wasSuccessfull());
		assertTrue(task.hasErrors());
	}

}
