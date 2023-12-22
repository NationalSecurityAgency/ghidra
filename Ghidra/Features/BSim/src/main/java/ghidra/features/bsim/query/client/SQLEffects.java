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
package ghidra.features.bsim.query.client;

import java.sql.SQLException;
import java.util.*;
import java.util.Map.Entry;

import ghidra.features.bsim.gui.filters.BSimFilterType;
import ghidra.features.bsim.query.SQLFunctionDatabase;
import ghidra.features.bsim.query.protocol.BSimFilter;
import ghidra.features.bsim.query.protocol.FilterAtom;

/**
 * Container for collecting and sorting SQL string representations of FilterTemplates
 *
 */
public class SQLEffects {
	private boolean exetable = false;		// true if the filter needs to reference (join) against the exetable
	private boolean pathtable = false;		// true if the filter needs to reference (join) against the pathtable
	private int filterMask = 0;				// Each 1-bit represents a single function tag that needs to be matched
	private int filterValue = 0;			// With the filterMask, bits indicate whether an individual
	//   function tag should match as true (1) or false(0)

	// Collection of SQL string pieces, sorted by the FilterTemplate that created them
	private Map<BSimFilterType, List<String>> wherelist =
		new TreeMap<BSimFilterType, List<String>>();

	// Collection of SQL string pieces holding a join expression or the final function tag expression
	private List<String> linkClauses = new ArrayList<String>();

//	/**
//	 * Container for final SQL string sections;
//	 *
//	 */
//	public static class Cache {
//		public String tableclause;
//		public String whereclause;
//	}

	public void setExeTable() {
		exetable = true;
	}

	public void setPathTable() {
		pathtable = true;
	}

	public void addFunctionFilter(int flag, boolean val) {
		filterMask |= flag;				// Check the specific bit
		if (val) {
			filterValue |= flag;		//      must be set to 1		
		}
	}

	/**
	 * Generate the string pieces of the WHERE clause, based on the FilterAtoms within the general filter,
	 * sort them into the wherelist container
	 * @param exefilter is the general filter
	 * @param idres is an array of precalculated ids associated with each FilterAtom
	 * @throws SQLException for errors building the SQL clause
	 */
	private void generateWhereClause(BSimFilter exefilter, IDSQLResolution idres[],
		SQLFunctionDatabase db) throws SQLException {

		for (int i = 0; i < exefilter.numAtoms(); ++i) {
			FilterAtom atom = exefilter.getAtom(i);
			atom.type.gatherSQLEffect(this, atom, idres[i]);
		}

		if (filterMask != 0) {
			StringBuilder buf = new StringBuilder();
			String maskedFlags =
				db.formatBitAndSQL("desctable.flags", Integer.toString(filterMask));
			buf.append(maskedFlags).append(" = ").append(filterValue);
			addLink(buf.toString());
		}

		if (exetable) {
			addLink("desctable.id_exe = exetable.id");
		}
		if (pathtable) {
			addLink("exetable.path = pathtable.id");
		}
	}

	/**
	 * Given our sorted container of string pieces, combine them into a single SQL where clause,
	 * connecting them appropriately with 'AND' and 'OR' keywords and parentheses.
	 * @return the final where String
	 */
	private String buildWhereClause() {
		StringBuilder builder = new StringBuilder();
		if (!linkClauses.isEmpty()) {
			builder.append(" AND (");
			boolean printAnd = false;
			for (String link : linkClauses) {
				if (printAnd) {
					builder.append(" AND ");
				}
				builder.append(link);
				printAnd = true;
			}
			builder.append(')');
		}

		for (Entry<BSimFilterType, List<String>> entry : wherelist.entrySet()) {
			// Start with an AND clause because there are other clauses in the SQL string that may
			// have been added before this - even if there aren't, having this here will not cause
			// a problem.
			builder.append(" AND ");

			BSimFilterType filter = entry.getKey();
			String finalClause = filter.buildSQLCombinedClause(entry.getValue());
			builder.append(finalClause);
		}

		return builder.toString();
	}

	private String buildTableClause() {
		StringBuilder buf = new StringBuilder();
		if (exetable) {
			buf.append(",exetable");
		}
		if (pathtable) {
			buf.append(",pathtable");
		}
		return buf.toString();
	}

	public void addLink(String value) {
		linkClauses.add(value);
	}

	public void addWhere(BSimFilterType filter, String val) {
		List<String> list = wherelist.get(filter);
		if (list == null) {
			list = new ArrayList<String>();
			wherelist.put(filter, list);
		}
		list.add(val);
	}

	/**
	 * Given a general ExecutableFilter object, return a set of matching SQL string pieces,
	 * ready to be pasted into the full SQL statement.  The routine is handed an array of IDResolution references
	 * matching individual FilterAtoms as returned by ExecutableFilter.getAtom(i).  The IDResolution, if non-null,
	 * holds any pre-calculated ids associated with the corresponding FilterAtom
	 * @param exeFilter is the general filter
	 * @param idres is the array holding pre-calculated ids
	 * @param db SQL function database
	 * @return BSimFilterSQL, holding the table clause and the where clause
	 * @throws SQLException for errors building the SQL clause
	 */
	public static BSimSqlClause createFilter(BSimFilter exeFilter, IDSQLResolution idres[],
		SQLFunctionDatabase db) throws SQLException {
		String tableclause = null;
		String whereclause = null;

		SQLEffects effects = new SQLEffects();
		effects.generateWhereClause(exeFilter, idres, db);
		whereclause = effects.buildWhereClause();
		if ((whereclause == null) || (whereclause.length() == 0)) {
			return null;
		}

		tableclause = effects.buildTableClause();

		return new BSimSqlClause(tableclause, whereclause);
	}
}
