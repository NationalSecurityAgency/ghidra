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
package ghidra.features.bsim.query.file;

import java.io.*;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

import generic.lsh.vector.LSHVector;
import ghidra.features.bsim.query.client.tables.CachedStatement;
import ghidra.features.bsim.query.client.tables.SQLComplexTable;
import ghidra.features.bsim.query.description.VectorResult;
import ghidra.features.bsim.query.elastic.Base64Lite;
import ghidra.features.bsim.query.elastic.Base64VectorFactory;

public class H2VectorTable extends SQLComplexTable {

	// FIXME: refine column type and vector storage format (consider binary)

	public static final String TABLE_NAME = "h2_vectable";

	private final Base64VectorFactory vectorFactory;
	private final VectorStore vectorStore; // in-memory cache

	private final CachedStatement<PreparedStatement> insert_stmt = new CachedStatement<>();
	private final CachedStatement<PreparedStatement> select_by_rowid_stmt = new CachedStatement<>();
	private final CachedStatement<PreparedStatement> select_id_by_hash_stmt =
		new CachedStatement<>();
	private final CachedStatement<PreparedStatement> update_by_hash_stmt = new CachedStatement<>();
	private final CachedStatement<PreparedStatement> select_count_by_rowid_stmt =
		new CachedStatement<>();
	private final CachedStatement<PreparedStatement> update_by_rowid_stmt = new CachedStatement<>();

	public H2VectorTable(Base64VectorFactory vectorFactory, VectorStore vectorStore) {
		super(TABLE_NAME, "id");
		this.vectorFactory = vectorFactory;
		this.vectorStore = vectorStore;
	}

	@Override
	public void close() {
		insert_stmt.close();
		select_by_rowid_stmt.close();
		select_id_by_hash_stmt.close();
		update_by_hash_stmt.close();
		select_count_by_rowid_stmt.close();
		update_by_rowid_stmt.close();
		super.close();
	}

	@Override
	public void create(Statement st) throws SQLException {
		st.executeUpdate("CREATE TABLE " + TABLE_NAME +
			"(id SERIAL PRIMARY KEY, count INTEGER, vec_hash BIGINT, vec CLOB)");
		st.executeUpdate("CREATE UNIQUE INDEX h2_vectable_index ON " + TABLE_NAME + " (vec_hash)");
	}

	@Override
	public void drop(Statement st) throws SQLException {
		vectorStore.invalidate();
		st.executeUpdate("DROP INDEX h2_vectable_index");
		super.drop(st);
	}

	@Override
	public long insert(Object... arguments) throws SQLException {

		if (arguments == null || arguments.length != 2) {
			throw new IllegalArgumentException(
				"Insert method for H2VectorTable accepts two arguments: count(int) and LSHVector");
		}

		int count = (int) arguments[0];
		LSHVector vec = (LSHVector) arguments[1];

		PreparedStatement s = insert_stmt.prepareIfNeeded(() -> db.prepareStatement(
			"INSERT INTO " + TABLE_NAME + " (count,vec_hash,vec) VALUES(?,?,?)",
			Statement.RETURN_GENERATED_KEYS));

		StringBuilder vecBuf = new StringBuilder();
		vec.saveBase64(vecBuf, Base64Lite.encode);

		s.setInt(1, count);
		s.setLong(2, vec.calcUniqueHash());
		s.setString(3, vecBuf.toString());
		if (s.executeUpdate() != 1) {
			throw new SQLException("Insert failed for vector table");
		}
		long id;
		try (ResultSet rs = s.getGeneratedKeys()) {
			if (!rs.next()) {
				throw new SQLException("Unable to obtain vector id for insert");
			}
			id = rs.getLong(1);
		}
		vectorStore.update(
			new VectorStoreEntry(id, vec, count, vectorFactory.getSelfSignificance(vec)));
		return id;
	}

	/**
	 * Read all vectors from table and generate an ID-based vector map
	 * @return vector map (ID->VectorStoreEntry)
	 * @throws SQLException if error occurs
	 */
	public Map<Long, VectorStoreEntry> readVectors() throws SQLException {
		char[] vectorDecodeBuffer = Base64VectorFactory.allocateBuffer();
		HashMap<Long, VectorStoreEntry> map = new HashMap<>();
		try (Statement st = db.createStatement();
				ResultSet rs = st.executeQuery("SELECT id,count,vec FROM " + TABLE_NAME)) {
			while (rs.next()) {
				long id = rs.getLong(1);
				int count = rs.getInt(2);
				Reader r = new StringReader(rs.getString(3));
				LSHVector vec = vectorFactory.restoreVectorFromBase64(r, vectorDecodeBuffer);
				VectorStoreEntry entry =
					new VectorStoreEntry(id, vec, count, vectorFactory.getSelfSignificance(vec));
				map.put(id, entry);
			}
		}
		catch (IOException e) {
			throw new SQLException(e); // unexpected for StringReader
		}
		return map;
	}

	/**
	 * Get vector details which correspond to specified vector ID
	 * @param id vector ID
	 * @return vector details
	 * @throws SQLException if error occurs
	 */
	public VectorResult queryVectorById(long id) throws SQLException {

		VectorStoreEntry entry = vectorStore.getVectorById(id);
		if (entry != null) {
			return new VectorResult(id, entry.count(), 0, 0, entry.vec());
		}

		PreparedStatement s = select_by_rowid_stmt.prepareIfNeeded(
			() -> db.prepareStatement("SELECT id,count,vec FROM " + TABLE_NAME + " WHERE id = ?"));
		s.setLong(1, id);
		try (ResultSet rs = s.executeQuery()) {
			if (!rs.next()) {
				throw new SQLException("Bad vector table rowid");
			}
			char[] vectorDecodeBuffer = Base64VectorFactory.allocateBuffer();
			VectorResult rowres;
			try {
				rowres = new VectorResult();
				rowres.vectorid = rs.getLong(1);
				rowres.hitcount = rs.getInt(2);
				Reader r = new StringReader(rs.getString(3));
				rowres.vec = vectorFactory.restoreVectorFromBase64(r, vectorDecodeBuffer);
			}
			catch (final IOException e) {
				throw new SQLException(e.getMessage()); // unexpected for StringReader
			}
			return rowres;
		}
	}

	/**
	 * Get vector count which correspond to specified vector ID
	 * @param id vector ID
	 * @return vector count
	 * @throws SQLException if error occurs
	 */
	private int queryVectorCountById(long id) throws SQLException {
		PreparedStatement s = select_count_by_rowid_stmt.prepareIfNeeded(
			() -> db.prepareStatement("SELECT count FROM " + TABLE_NAME + " WHERE id = ?"));
		s.setLong(1, id);
		try (ResultSet rs = s.executeQuery()) {
			if (!rs.next()) {
				throw new SQLException("Bad vector table rowid");
			}
			return rs.getInt(1);
		}
	}

	/**
	 * Update or insert vector table entry with the specified positive countDiff. 
	 * @param vec vector
	 * @param countDiff positive vector count change
	 * @return vector ID which was updated or created
	 * @throws SQLException if an error occurs
	 */
	public long updateVector(LSHVector vec, int countDiff) throws SQLException {

		if (countDiff <= 0) {
			throw new IllegalArgumentException("Invalid countDiff: " + countDiff);
		}

		// TODO: it may be possible to optimize the technique employed here

		PreparedStatement s = update_by_hash_stmt.prepareIfNeeded(() -> db.prepareStatement(
			"UPDATE " + TABLE_NAME + " SET count = count + ? WHERE vec_hash = ?"));
		long vecHash = vec.calcUniqueHash();
		s.setInt(1, countDiff);
		s.setLong(2, vecHash);
		int rc = s.executeUpdate();
		if (rc == 0) {
			return insert(countDiff, vec);
		}
		if (rc > 1) {
			throw new SQLException("Unexpected updated row count: " + rc);
		}

		s = select_id_by_hash_stmt.prepareIfNeeded(() -> db
				.prepareStatement("SELECT id, count FROM " + TABLE_NAME + " WHERE vec_hash = ?"));
		s.setLong(1, vecHash);

		long id;
		int count;
		try (ResultSet rs = s.executeQuery()) {
			if (!rs.next()) {
				throw new SQLException("Unknown vector hash");
			}
			id = rs.getLong(1);
			count = rs.getInt(2);
		}
		vectorStore.update(
			new VectorStoreEntry(id, vec, count, vectorFactory.getSelfSignificance(vec)));
		return id;
	}

	/**
	 * Update vector table entry with the specified countDiff.  Record will be removed
	 * if reduced vector count less-than-or-equal zero. 
	 * @param id vector ID
	 * @param countDiff positive vector count reduction
	 * @return 0 if decrement short of 0, return 1 if record was removed, return
	 *         -1 if there was a problem
	 * @throws SQLException if an error occurs
	 */
	public int deleteVector(long id, int countDiff) throws SQLException {

		if (countDiff <= 0) {
			throw new IllegalArgumentException("Invalid countDiff: " + countDiff);
		}

		// TODO: it may be possible to optimize the technique employed here

		PreparedStatement s = update_by_rowid_stmt.prepareIfNeeded(() -> db.prepareStatement(
			"UPDATE " + TABLE_NAME + " SET count = count - ? WHERE id = ? AND count >= ?"));
		s.setInt(1, countDiff);
		s.setLong(2, id);
		s.setInt(3, countDiff); // needed for comparison
		int rc = s.executeUpdate();
		if (rc == 0) {
			return -1;
		}
		if (rc > 1) {
			throw new SQLException("Unexpected updated row count: " + rc);
		}

		int count = queryVectorCountById(id);
		if (count > 0) {
			vectorStore.update(id, count);
			return 0;
		}

		delete(id);
		return 1;
	}

	@Override
	public int delete(long id) throws SQLException {
		int rc = super.delete(id);
		vectorStore.delete(id);
		return rc;
	}

}
