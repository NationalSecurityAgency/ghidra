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
package ghidra.program.database;

import db.DBRecord;

/**
 * Interface for Factories that create {@link DbObject}s. Required by the {@link DbCache}
 * <P>
 * NOTE: This factory is used to instantiate dbObject instances that are already backed
 * by records in the database. In general, these methods should only be used by the
 * DbCache class to insure that the objects aren't already cached if they are created using
 * this factor, they are added to the cache in a thread safe way.
 *
 * @param <T> the type of database object
 */
public interface DbFactory<T extends DbObject> {

	/**
	 * Creates a new DatabaseObject of type T for the given key. It is
	 * expected that a record for this object already exists in the database. This method is
	 * simply creating the unique instance that is associated with that record.
	 * @param key the database key the database key
	 * @return the newly created instance of type T or null if no record found
	 */
	public T instantiate(long key);

	/**
	 * Creates a new DatabaseObject of type T for the given record.
	 * @param record the database record to create its associated unique instance of T
	 * @return the newly created instance of type T
	 */
	public T instantiate(DBRecord record);

}
