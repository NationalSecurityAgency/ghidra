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
package ghidra.features.bsim.gui;

import static org.junit.Assert.*;

import java.sql.SQLException;
import java.util.List;

import org.junit.Test;

import ghidra.features.bsim.gui.filters.*;
import ghidra.features.bsim.gui.search.dialog.*;
import ghidra.features.bsim.query.client.*;
import ghidra.features.bsim.query.protocol.BSimFilter;
import ghidra.util.exception.AssertException;

/**
 * Tests the ability of the filter validators to correctly parse inputs.
 *
 */
public class QueryFilterTest extends AbstractBSimPluginTest {

	private BSimFilterPanel filterPanel;

	/**
	 * Tests that we can construct a proper SQL statement using the filters on the BSIM query panel. 
	 * 
	 * To do this we open the query dialog, add a few filters, populate them with several filters, then 
	 * call the appropriate functions in the ExecutableFilter class that generate the SLQ string, and 
	 * compare it to what we expect.
	 */
	@Test
	public void sqlConstructionTest() {

		// This is the SQL statement we want to produce.
		final String SQL_TRUTH =
			"AND (desctable.id_exe = exetable.id) AND (exetable.name_exec != 'bad exec name' AND exetable.name_exec != 'bad exec name 2') AND (exetable.name_exec = 'exec name 1' OR exetable.name_exec = 'exec name 3')";

		BSimFilterSet filterSet = new BSimFilterSet();
		filterSet.addEntry(new ExecutableNameBSimFilterType(), List.of("exec name 1"));
		filterSet.addEntry(new Md5BSimFilterType(), List.of("0x0123456789"));
		filterSet.addEntry(new NotExecutableNameBSimFilterType(),
			List.of("bad exec name", "bad exec name 2"));
		filterSet.addEntry(new DateEarlierBSimFilterType(""), List.of("Jan 01, 2000"));
		filterSet.addEntry(new ExecutableNameBSimFilterType(), List.of("exec name 3"));

		runSwing(() -> filterPanel.setFilterSet(filterSet));
		// Now go ahead and generate the SQL and verify it's correct.
		IDSQLResolution[] ids = new IDSQLResolution[] { null, null, null, null, null };
		String sql = runSwing(() -> generateSQL(ids));
		assertEquals(SQL_TRUTH, sql);
	}

	protected void initializeTool() throws Exception {
		super.initializeTool();
		goTo(FUN1_ADDR);
		performAction(searchAction, false);

		searchDialog = waitForDialogComponent(BSimSearchDialog.class);
		filterPanel = BSimSearchDialogTestHelper.getFilterPanel(searchDialog);
	}

	/**
	 * Generates the SQL that will be used in the query, based on the current 
	 * filter settings.
	 * 
	 * @param ids resolution IDs
	 * @return the query string
	 * @throws SQLException if there is a problem creating the filter
	 */
	private String generateSQL(IDSQLResolution[] ids) {
		try {
			BSimFilterSet filterSet = filterPanel.getFilterSet();
			BSimFilter filter = filterSet.getBSimFilter();
			BSimSqlClause sql = SQLEffects.createFilter(filter, ids, null);
			return sql.whereClause().trim();
		} catch (SQLException e) {
			throw new AssertException(e);
		}
	}
}
