/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package db;

/**
 * Database Listener.
 */
public interface DBListener {

	/**
	 * Provides notification that an undo or redo was performed.
	 * Separate notification will be provided if tables were added/removed.
	 * The state of the database may still be in transition and should not be accessed
	 * by this callback method.
	 * @param dbh associated database handle
	 */
	void dbRestored(DBHandle dbh);
	
	/**
	 * Database has been closed
	 * @param dbh associated database handle
	 */
	void dbClosed(DBHandle dbh);
	
	/**
	 * Provides notification that a table was deleted.
	 * The state of the database may still be in transition and should not be accessed
	 * by this callback method.
	 * @param dbh associated database handle
	 * @param table
	 */
	void tableDeleted(DBHandle dbh, Table table);
	
	/**
	 * Provides notification that a table was added.
	 * The state of the database may still be in transition and should not be accessed
	 * by this callback method.
	 * @param dbh associated database handle
	 * @param table
	 */
	void tableAdded(DBHandle dbh, Table table);
}
