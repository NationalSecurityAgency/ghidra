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
package help.screenshot;

import javax.swing.JComponent;

import org.junit.Test;

import docking.ComponentProvider;
import docking.widgets.filter.FilterTextField;
import docking.widgets.table.GTable;
import docking.widgets.table.GTableFilterPanel;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.program.model.listing.*;

public class CommentWindowPluginScreenShots extends GhidraScreenShotGenerator {

	public CommentWindowPluginScreenShots() {
		super();
	}

	@Test
	public void testCommentsWindow() throws Exception {

		//create some interesting comments for the image
		createComments(program);

		// open the comments window
		performAction("Comments", "DockingWindows", true);

		// set the filter text for our comments
		ComponentProvider provider = getProvider("Comment Window");
		setFilterText(provider, "My");

		captureIsolatedProviderWindow(provider.getClass(), 440, 260);
	}

	private void setFilterText(ComponentProvider provider, String text) {

		JComponent component = provider.getComponent();
		GTable commentTable = (GTable) findComponentByName(component, "CommentTable");
		ThreadedTableModel<?, ?> tableModel = (ThreadedTableModel<?, ?>) commentTable.getModel();
		FilterTextField filterField = (FilterTextField) findComponentByName(component,
			GTableFilterPanel.FILTER_TEXTFIELD_NAME);
		setFilterText(filterField, text);
		waitForTableModel(tableModel);
	}

	private void setFilterText(FilterTextField field, String text) {
		runSwing(() -> field.setText(text));
		waitForSwing();
	}

	private void createComments(Program prog) throws Exception {

		int id = prog.startTransaction("Test");
		Listing listing = prog.getListing();
		listing.setComment(addr(0x00401006), CodeUnit.EOL_COMMENT, "My EOL comment");
		listing.setComment(addr(0x0040101b), CodeUnit.PRE_COMMENT, "My Pre comment");
		listing.setComment(addr(0x0040101c), CodeUnit.POST_COMMENT, "My Post comment");
		listing.setComment(addr(0x00401020), CodeUnit.PLATE_COMMENT, "My Plate comment");
		listing.setComment(addr(0x0040100d), CodeUnit.REPEATABLE_COMMENT, "My Repeatable comment");
		prog.endTransaction(id, true);
		prog.flushEvents();
		waitForSwing();
	}

}
