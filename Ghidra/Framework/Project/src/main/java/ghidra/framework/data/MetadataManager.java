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
package ghidra.framework.data;

import java.io.IOException;
import java.util.Iterator;
import java.util.Map;

import db.*;

class MetadataManager {
	private final static String TABLE_NAME = "Metadata";
    private final static Schema SCHEMA = new Schema(0,"ID", 
    		new Class[] {StringField.class, StringField.class},
    		new String[] {"Key", "Value"});

	static void loadData(DomainObjectAdapterDB dobj, Map<String, String> metadata) throws IOException {
		metadata.clear();
		
		Table table = dobj.getDBHandle().getTable(TABLE_NAME);
		if (table != null) {
			RecordIterator iterator = table.iterator();
			while(iterator.hasNext()) {
				DBRecord record = iterator.next();
				String key = record.getString(0);
				String value = record.getString(1);
				metadata.put(key, value);
			}
		}
	}
	
	static void saveData(DomainObjectAdapterDB dobj, Map<String, String> metadata) throws IOException {
		int transactionID = dobj.startTransaction("Update Metadata");
		try {
			Table table = dobj.getDBHandle().getTable(TABLE_NAME);
			if (table == null) {
				table = dobj.getDBHandle().createTable(TABLE_NAME, SCHEMA);
			}
			else {
				table.deleteAll();
			}
			Iterator<String> keyIterator = metadata.keySet().iterator();
			long id = 1;
			while(keyIterator.hasNext()) {
				String key = keyIterator.next();
				String value = metadata.get(key);
				DBRecord record = SCHEMA.createRecord(id++);
				record.setString(0, key);
				record.setString(1, value);
				table.putRecord(record);
			}
		}
		finally {
			dobj.endTransaction(transactionID, true);
		}
	}

}
