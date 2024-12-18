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
package ghidra.app.plugin.core.compositeeditor;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import db.*;
import db.util.ErrorHandler;

/**
 * {@link IDMapDB} provides a bidirectional map for tracking view to/from original datatype ID
 * correspondence and faciliate recovery across undo/redo of the view's datatype manager.
 */
class IDMapDB {
	private final static String TABLE_NAME = "IDMap";

	private final static Schema SCHEMA =
		new Schema(0, "ViewID", new Class[] { LongField.class }, new String[] { "OriginalID" });

	private static final int ORIGINAL_ID_COL = 0;

	private final ErrorHandler errorHandler;
	private final Table table;

	private Map<Long, Long> viewToOriginalMap;
	private Map<Long, Long> originalToViewMap;

	/**
	 * Construct database-backed bidirectional datatype ID map
	 * @param dbHandle database handle for {@link CompositeViewerDataTypeManager}
	 * @param errorHandler error handler
	 */
	IDMapDB(DBHandle dbHandle, ErrorHandler errorHandler) {
		this.errorHandler = errorHandler;
		table = init(dbHandle, errorHandler);
		viewToOriginalMap = new HashMap<>();
		originalToViewMap = new HashMap<>();
	}

	private static Table init(DBHandle dbHandle, ErrorHandler errorHandler) {
		try {
			return dbHandle.createTable(TABLE_NAME, SCHEMA);
		}
		catch (IOException e) {
			errorHandler.dbError(e); // will throw runtime exception
		}
		return null;
	}

	void invalidate() {
		viewToOriginalMap = null;
		originalToViewMap = null;
		// delay reload until needed
	}

	void clearAll() throws IOException {
		table.deleteAll();
		viewToOriginalMap = new HashMap<>();
		originalToViewMap = new HashMap<>();
	}

	private void reloadIfNeeded() {
		if (viewToOriginalMap != null) {
			return;
		}

		viewToOriginalMap = new HashMap<>();
		originalToViewMap = new HashMap<>();
		try {
			RecordIterator it = table.iterator();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				long viewId = rec.getKey();
				long originalId = rec.getLongValue(ORIGINAL_ID_COL);
				viewToOriginalMap.put(viewId, originalId);
				originalToViewMap.put(originalId, viewId);
			}
		}
		catch (IOException e) {
			errorHandler.dbError(e);
		}
	}

	Long getOriginalIDFromViewID(long viewId) {
		reloadIfNeeded();
		return viewToOriginalMap.get(viewId);
	}

	Long getViewIDFromOriginalID(long originalId) {
		reloadIfNeeded();
		return originalToViewMap.get(originalId);
	}

	void put(long viewId, long originalId) {
		try {
			DBRecord rec = SCHEMA.createRecord(viewId);
			rec.setLongValue(ORIGINAL_ID_COL, originalId);
			table.putRecord(rec);

			if (viewToOriginalMap != null) {
				viewToOriginalMap.put(viewId, originalId);
				originalToViewMap.put(originalId, viewId);
			}
		}
		catch (IOException e) {
			errorHandler.dbError(e);
		}
	}

	Long remove(long viewId) {
		Long originalId = null;
		try {
			DBRecord rec = table.getRecord(viewId);
			if (rec != null) {
				originalId = rec.getLongValue(ORIGINAL_ID_COL);
				table.deleteRecord(viewId);

				if (viewToOriginalMap != null) {
					viewToOriginalMap.remove(viewId);
					originalToViewMap.remove(originalId);
				}
			}
		}
		catch (IOException e) {
			errorHandler.dbError(e);
		}
		return originalId;
	}

}
