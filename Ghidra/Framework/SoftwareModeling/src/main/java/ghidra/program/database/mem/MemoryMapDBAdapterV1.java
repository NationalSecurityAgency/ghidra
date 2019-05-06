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
package ghidra.program.database.mem;

import java.io.IOException;

import db.DBHandle;
import ghidra.util.exception.VersionException;

/**
 * Adapter for version 1
 */
class MemoryMapDBAdapterV1 extends MemoryMapDBAdapterV0 {
	private final static int VERSION = 1;

//	private Schema SCHEMA = new Schema(VERSION, "Key", 
//								new Class[] {StringField.class, 
//								IntField.class, StringField.class,
//								StringField.class, StringField.class,
//								LongField.class, BooleanField.class, 
//								BooleanField.class, BooleanField.class,
//								LongField.class, IntField.class, 
//								ShortField.class, LongField.class,
//								LongField.class, IntField.class}, 
//							new String[] {"Name", "Chain Buffer ID",
//								"Comments", "Description", "Source Name",
//								"Source Offset", "Is Read", "Is Write",
//								"Is Execute", "Start Address", "Length",
//								"Block Type", "Base Address", 
//								"Source Block ID","Segment"});
//

	/**
	 * @param handle
	 */
	MemoryMapDBAdapterV1(DBHandle handle, MemoryMapDB memMap) throws VersionException, IOException {
		super(handle, memMap, VERSION);
	}
}
