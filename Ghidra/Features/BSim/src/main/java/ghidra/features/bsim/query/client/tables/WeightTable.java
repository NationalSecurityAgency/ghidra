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

import generic.lsh.vector.WeightFactory;

public class WeightTable extends SQLComplexTable {

	public WeightTable() {
		super("weighttable", "id");
	}

	@Override
	public void create(Statement st) throws SQLException {
		st.executeUpdate("CREATE TABLE weighttable(id integer,weight NUMERIC(24,20))");
	}

	@Override
	public void drop(Statement st) throws SQLException {
		String sql = "DROP TABLE IF EXISTS " + tableName;
		st.executeUpdate(sql);
	}

	@Override
	public long insert(Object... arguments) throws SQLException {

		if (arguments == null || arguments.length != 2) {
			throw new IllegalArgumentException(
				"Insert method for WeightTable must take exactly two arguments: int and double");
		}

		final Statement st = db.createStatement();

		final int row = (int) arguments[0];
		final double val = (double) arguments[1];

		final StringBuffer buf = new StringBuffer();
		buf.append("INSERT INTO weighttable (id,weight) VALUES(");
		buf.append(row).append(',').append(val).append(')');
		st.executeUpdate(buf.toString());

		return 0;
	}

	/**
	 * 
	 * @param factory the weight factory
	 * @throws SQLException if there is an error creating/executing the query
	 */
	public void recoverWeights(WeightFactory factory) throws SQLException {
		try (Statement st = db.createStatement();
				ResultSet rs = st.executeQuery("SELECT all * FROM weighttable")) {
			double vals[] = new double[factory.getIDFSize() + factory.getTFSize() + 7];
			int numrows = 0;
			while (rs.next()) {
				int id = rs.getInt(1);
				double val = rs.getDouble(2);
				vals[id] = val;
				numrows += 1;
			}
			if (numrows != factory.getIDFSize() + factory.getTFSize() + 7) {
				throw new SQLException("weighttable has wrong number of rows");
			}

			factory.set(vals);
		}
	}
}
