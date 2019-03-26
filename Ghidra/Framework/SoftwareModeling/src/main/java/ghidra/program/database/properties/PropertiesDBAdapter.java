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
package ghidra.program.database.properties;

import java.io.IOException;

import db.RecordIterator;

interface PropertiesDBAdapter {

	/**
	 * Iterate over the records contained within the Properties table.
	 * @return RecordIterator
	 */
	RecordIterator getRecords() throws IOException;

	/**
	 * Create a new property map definition record.
	 * @param propertyName unique property name.
	 * @param type property map type
	 * @param objClassName full class name for Saveable objects when
	 * type is OBJECT_PROPERTY_TYPE, else value should be null. 
	 */
	void putRecord(String propertyName, byte type, String objClassName) throws IOException;

	/**
	 * Remove a specific property map definition record.
	 * @param propertyName
	 */
	void removeRecord(String propertyName) throws IOException;

}
