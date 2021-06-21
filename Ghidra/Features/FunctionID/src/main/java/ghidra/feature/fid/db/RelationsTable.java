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
package ghidra.feature.fid.db;

import java.io.IOException;

import db.*;
import ghidra.feature.fid.hash.FidHashQuad;

public class RelationsTable {
	static final String INFERIOR_RELATIONS_TABLE = "Inferior Table";
	static final String SUPERIOR_RELATIONS_TABLE = "Superior Table";

//	static final int CACHE_SIZE = 10000;

	// @formatter:off
	static final Schema SCHEMA = new Schema(LibrariesTable.VERSION, "Relation Smash", 
			new Field[] { }, new String[] {
		});
	// @formatter:on

	Table inferiorTable;
	Table superiorTable;

	/**
	 * Creates or attaches a relations table.
	 * @param handle the database handle
	 * @param create whether to create or attach
	 * @throws IOException if the database system encounters a problem
	 */
	public RelationsTable(DBHandle handle) throws IOException {
		inferiorTable = handle.getTable(INFERIOR_RELATIONS_TABLE);
		superiorTable = handle.getTable(SUPERIOR_RELATIONS_TABLE);
	}

	public static void createTables(DBHandle handle) throws IOException {
		handle.createTable(INFERIOR_RELATIONS_TABLE, SCHEMA);
		handle.createTable(SUPERIOR_RELATIONS_TABLE, SCHEMA);
	}

	/**
	 * Creates a relation in the database from caller (superior) to callee (inferior) with
	 * the designated relation type.
	 * @param superiorFunction the caller function
	 * @param inferiorFunction the callee function
	 * @param relationType the relation type
	 * @throws IOException if the database has a problem creating the record
	 */
	public void createRelation(FunctionRecord superiorFunction, FunctionRecord inferiorFunction,
			RelationType relationType) throws IOException {
		long superiorKey =
			FidDBUtils.generateSuperiorFullHashSmash(superiorFunction, inferiorFunction);
		DBRecord superiorRecord = SCHEMA.createRecord(superiorKey);
		superiorTable.putRecord(superiorRecord);
		if (relationType != RelationType.INTER_LIBRARY_CALL) {
			long inferiorKey =
				FidDBUtils.generateInferiorFullHashSmash(superiorFunction, inferiorFunction);
			DBRecord inferiorRecord = SCHEMA.createRecord(inferiorKey);
			inferiorTable.putRecord(inferiorRecord);
		}
	}

	/**
	 * Creates only an inferior relation, used for special distinguishing parent relationships with
	 * common functions
	 * @param superiorFunction is the special parent
	 * @param inferiorFunction is the common function
	 * @throws IOException 
	 */
	public void createInferiorRelation(FunctionRecord superiorFunction,
			FunctionRecord inferiorFunction) throws IOException {
		long inferiorKey =
			FidDBUtils.generateInferiorFullHashSmash(superiorFunction, inferiorFunction);
		DBRecord inferiorRecord = SCHEMA.createRecord(inferiorKey);
		inferiorTable.putRecord(inferiorRecord);
	}

	/**
	 * Return true if a relation exists, between a superior (caller) function and a
	 * full hash representing the inferior (callee) function.
	 * @param superiorFunction the caller function
	 * @param inferiorFunction a hash representing the callee function
	 * @return true if the relation exists
	 * @throws IOException if the database encounters an error seeking
	 */
	public boolean getSuperiorFullRelation(FunctionRecord superiorFunction,
			FidHashQuad inferiorFunction) throws IOException {
		long superiorKey =
			FidDBUtils.generateSuperiorFullHashSmash(superiorFunction, inferiorFunction);
		DBRecord record = superiorTable.getRecord(superiorKey);
		return (record != null);
	}

	/**
	 * Returns true if a relation exists, between an inferior (callee) function and a
	 * full hash representing the superior (caller) function.
	 * @param superiorFunction a hash representing the caller function
	 * @param inferiorFunction the callee function
	 * @return true if the relation exists
	 * @throws IOException if the database encounters an error seeking
	 */
	public boolean getInferiorFullRelation(FidHashQuad superiorFunction,
			FunctionRecord inferiorFunction) throws IOException {
		long inferiorKey =
			FidDBUtils.generateInferiorFullHashSmash(superiorFunction, inferiorFunction);
		DBRecord record = inferiorTable.getRecord(inferiorKey);
		return (record != null);
	}
}
