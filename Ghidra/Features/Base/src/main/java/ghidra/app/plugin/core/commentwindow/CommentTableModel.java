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
package ghidra.app.plugin.core.commentwindow;

import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.table.field.AddressTableColumn;
import ghidra.util.task.TaskMonitor;

/*
 * This is the model for the Comment Window Table
 */
class CommentTableModel extends AddressBasedTableModel<CommentRowObject> {

	static final int TYPE_COL_WIDTH = 150;
	static final int COMMENT_COL_WIDTH = 350;

	static final int LOCATION_COL = 0;
	static final int TYPE_COL = 1;
	static final int COMMENT_COL = 2;

	private Listing listing;

	CommentTableModel(CommentWindowPlugin plugin) {
		super("Comment Window", plugin.getTool(), null, null);
	}

	@Override
	protected TableColumnDescriptor<CommentRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<CommentRowObject> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
		descriptor.addVisibleColumn(new TypeTableColumn());
		descriptor.addVisibleColumn(new CommentTableColumn());

		return descriptor;
	}

	void reload(Program newProgram) {
		this.setProgram(newProgram);

		if (newProgram != null) {
			listing = newProgram.getListing();
		}
		else {
			listing = null;
		}
		reload();
	}

	@Override
	protected void doLoad(Accumulator<CommentRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {

		if (listing == null) {
			return; // no active program
		}

		AddressIterator commentIterator =
			listing.getCommentAddressIterator(getProgram().getMemory(), true);
		while (commentIterator.hasNext()) {
			Address commentAddr = commentIterator.next();
			CodeUnit cu = listing.getCodeUnitContaining(commentAddr);
			if (!(cu instanceof Data)) {
				// avoid too many comments in the table by not showing offcut instruction comments
				cu = listing.getCodeUnitAt(commentAddr);
			}

			if (cu == null) {
				continue;
			}

			if (cu.getComment(CodeUnit.PRE_COMMENT) != null) {
				accumulator.add(new CommentRowObject(commentAddr, CodeUnit.PRE_COMMENT));
			}
			if (cu.getComment(CodeUnit.POST_COMMENT) != null) {
				accumulator.add(new CommentRowObject(commentAddr, CodeUnit.POST_COMMENT));
			}
			if (cu.getComment(CodeUnit.EOL_COMMENT) != null) {
				accumulator.add(new CommentRowObject(commentAddr, CodeUnit.EOL_COMMENT));
			}
			if (cu.getComment(CodeUnit.PLATE_COMMENT) != null) {
				accumulator.add(new CommentRowObject(commentAddr, CodeUnit.PLATE_COMMENT));
			}
			if (cu.getComment(CodeUnit.REPEATABLE_COMMENT) != null) {
				accumulator.add(new CommentRowObject(commentAddr, CodeUnit.REPEATABLE_COMMENT));
			}
		}

	}

	void commentAdded(Address addr, int commentType) {
		String comment = listing.getComment(commentType, addr);

		if (comment == null) {
			Msg.debug(this, "Received a commentAdded() with a null comment");
			return;
		}

		addObject(new CommentRowObject(addr, commentType));

	}

	void commentRemoved(Address addr, int commentType) {
		removeObject(new CommentRowObject(addr, commentType));
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		AddressSet set = new AddressSet();
		for (int element : rows) {
			CommentRowObject rowObject = getRowObject(element);
			set.addRange(rowObject.getAddress(), rowObject.getAddress());
		}
		return new ProgramSelection(set);
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row).getAddress();
	}

	private String getCommentForRowObject(CommentRowObject t) {
		return listing.getComment(t.getCommentType(), t.getAddress());
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class TypeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<CommentRowObject, String> {

		@Override
		public String getColumnName() {
			return "Type";
		}

		@Override
		public String getValue(CommentRowObject rowObject, Settings settings, Program program,
				ServiceProvider provider) throws IllegalArgumentException {

			String returnString = "";
			if (rowObject.getCommentType() == CodeUnit.EOL_COMMENT) {
				return "EOL Comment";
			}
			if (rowObject.getCommentType() == CodeUnit.PLATE_COMMENT) {
				return "Plate Comment";
			}
			if (rowObject.getCommentType() == CodeUnit.PRE_COMMENT) {
				return "Pre Comment";
			}
			if (rowObject.getCommentType() == CodeUnit.POST_COMMENT) {
				return "Post Comment";
			}
			if (rowObject.getCommentType() == CodeUnit.REPEATABLE_COMMENT) {
				return "Repeatable Comment";
			}
			return returnString;
		}

		@Override
		public int getColumnPreferredWidth() {
			return TYPE_COL_WIDTH;
		}
	}

	private class CommentTableColumn
			extends AbstractProgramBasedDynamicTableColumn<CommentRowObject, String> {

		@Override
		public String getColumnName() {
			return "Comment";
		}

		@Override
		public String getValue(CommentRowObject rowObject, Settings settings, Program program,
				ServiceProvider provider) throws IllegalArgumentException {
			String comment = getCommentForRowObject(rowObject);
			return comment;
		}

		@Override
		public int getColumnPreferredWidth() {
			return COMMENT_COL_WIDTH;
		}
	}
}
