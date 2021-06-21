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
package db;

public interface RecordTranslator {
	
	/**
	 * Translate the indicated old database record into a current database record. 
	 * @param oldRecord the old database record.
	 * @return the new data base record in the form required for the current database version.
	 */
	DBRecord translateRecord(DBRecord oldRecord);
}
