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
package ghidra.features.bsim.query.client.tables;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

import ghidra.features.bsim.query.description.CategoryRecord;
import ghidra.features.bsim.query.description.ExecutableRecord;

public class ExeToCategoryTable extends SQLComplexTable {

	private static final String INSERT_STMT =
		"INSERT INTO execattable (id_exe,id_type,id_category) VALUES(?,?,?)";
	private static final String SELECT_STMT = "SELECT ALL * FROM execattable WHERE id_exe = ?";

	private final SQLStringTable catstringtable;

	private final CachedStatement<PreparedStatement> selectCategoriesStatement =
		new CachedStatement<>();
	private final CachedStatement<PreparedStatement> insertExeCatStatement =
		new CachedStatement<>();

	protected static class CategoryRow {
		public long id_exe;
		public long id_type;
		public long id_category;
	}

	/**
	 * Constructor 
	 * 
	 * @param catstringtable table containing all category values
	 */
	public ExeToCategoryTable(SQLStringTable catstringtable) {
		super("execattable", "id_exe");
		this.catstringtable = catstringtable;
	}

	@Override
	public void close() {
		selectCategoriesStatement.close();
		insertExeCatStatement.close();
		super.close();
	}

	@Override
	public void create(Statement st) throws SQLException {
		st.executeUpdate(
			"CREATE TABLE execattable (id_exe INTEGER,id_type INTEGER,id_category INTEGER)");
		st.executeUpdate("CREATE INDEX execatindex ON execattable (id_exe,id_category)");
	}

	@Override
	public void drop(Statement st) throws SQLException {
		throw new UnsupportedOperationException("ExeToCategoryTable may not be dropped");
	}

	@Override
	public long insert(Object... arguments) throws SQLException {

		if (arguments == null || arguments.length != 2 ||
			!(arguments[0] instanceof CategoryRecord)) {
			throw new IllegalArgumentException(
				"Insert method for ExeToCategoryTable must take exactly 2 arguments: CategoryRecord and a long(id_exe)");
		}

		CategoryRecord catrec = (CategoryRecord) arguments[0];
		long id_type = catstringtable.writeString(catrec.getType());
		long id_category = catstringtable.writeString(catrec.getCategory());
		long exe_id = (long) arguments[1];

		// Insert a new row referencing that existing row into the execattable.
		PreparedStatement s =
			insertExeCatStatement.prepareIfNeeded(() -> db.prepareStatement(INSERT_STMT));
		s.setInt(1, (int) exe_id);
		s.setInt(2, (int) id_type);
		s.setInt(3, (int) id_category);
		s.executeUpdate();

		// Return value is meaningless here.
		return 0;

	}

	protected static void extractCategoryRow(ResultSet pgres, CategoryRow res) throws SQLException {
		res.id_exe = pgres.getInt(1);
		res.id_type = pgres.getInt(2);
		res.id_category = pgres.getInt(3);
	}

	protected void extractCategoryRecords(ResultSet rs, List<CategoryRecord> vecres, int max)
		throws SQLException {
		List<CategoryRow> catrows = new ArrayList<CategoryRow>();
		boolean finished = false;

		while (rs.next()) {
			if (!finished) {
				CategoryRow row = new CategoryRow();
				catrows.add(row);
				extractCategoryRow(rs, row);
				if ((max > 0) && (catrows.size() >= max)) {
					finished = true;
				}
			}
		}
		for (int i = 0; i < catrows.size(); ++i) {
			CategoryRow row = catrows.get(i);
			String type = catstringtable.getString(row.id_type);
			String category = catstringtable.getString(row.id_category);
			CategoryRecord catrec = new CategoryRecord(type, category);
			vecres.add(catrec);
		}
	}

	/**
	 * 
	 * @param exeid the executable table id
	 * @param max the max number of records to return
	 * @return the list of category records
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	public List<CategoryRecord> queryExecutableCategories(long exeid, int max)
		throws SQLException {

		if (exeid == 0) {
			throw new SQLException("ExecutableRecord does not have id");
		}

		PreparedStatement s =
			selectCategoriesStatement.prepareIfNeeded(() -> db.prepareStatement(SELECT_STMT));
		s.setInt(1, (int) exeid);
		try (ResultSet rs = s.executeQuery()) {
			List<CategoryRecord> catvec = new ArrayList<CategoryRecord>();
			extractCategoryRecords(rs, catvec, max);
			return catvec;
		}
	}

	/**
	 * 
	 * @param erec the executable record
	 * @throws SQLException if there is a problem inserting the category 
	 */
	public void storeExecutableCategories(ExecutableRecord erec) throws SQLException {
		if (erec.isAlreadyStored()) {
			return;
		}
		// TODO: We are NOT checking if the stored exe has the same categories as this exe
		List<CategoryRecord> catrecs = erec.getAllCategories();
		if (catrecs == null) {
			return;
		}
		long exeid = erec.getRowId().getLong();
		for (CategoryRecord catrec : catrecs) {
			insert(catrec, exeid);
		}
	}
}
