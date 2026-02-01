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

import generic.lsh.vector.IDFLookup;

public class IdfLookupTable extends SQLComplexTable {

	public IdfLookupTable() {
		super("idflookup", null);
	}

	@Override
	public void create(Statement st) throws SQLException {
		st.executeUpdate("CREATE TABLE idflookup(hash bigint,lookup integer)");
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
				"Insert method for IdfLookupTable must take exactly two integer arguments");
		}

		try (Statement st = db.createStatement()) {

			int cnt = (int) arguments[0];
			if (cnt == 0xffffffff) {
				return 0;
			}
			StringBuffer buf = new StringBuffer();
			buf.append("INSERT INTO idflookup (hash,lookup) VALUES(");
			long rawhash = (int) arguments[1];
			if (rawhash < 0) {
				rawhash += 0x100000000L;
			}
			buf.append(rawhash);
			buf.append(',').append(cnt).append(')');
			st.executeUpdate(buf.toString());

			return 0; // return value is meaningless here
		}
	}

	/**
	 * 
	 * @param lookup the IDF lookup
	 * @throws SQLException if there is an error creating/executing the query
	 */
	public void recoverIDFLookup(IDFLookup lookup) throws SQLException {
		try (Statement st = db.createStatement();
				ResultSet rs = st.executeQuery("SELECT ALL * from idflookup")) {
			int buffer[] = new int[5000];
			int numentries = 0;
			while (rs.next()) {
				buffer[numentries] = (int) rs.getLong(1);
				numentries += 1;
				buffer[numentries] = rs.getInt(2);
				numentries += 1;
			}

			int[] finalArray = new int[numentries];
			for (int i = 0; i < finalArray.length; ++i) {
				finalArray[i] = buffer[i];
			}
			lookup.set(finalArray);
		}
	}

}
