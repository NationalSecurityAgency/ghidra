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

import java.io.IOException;

import javax.help.UnsupportedOperationException;

import db.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.util.LanguageTranslator;
import ghidra.util.exception.VersionException;

class OverlaySpaceDBAdapterV0 extends OverlaySpaceDBAdapter {

	private static final int VERSION = 0;

/* Do not remove the following commented out schema! It shows the version 0 overlay table schema. */
//	private static final Schema SCHEMA_V0 = new Schema(VERSION, "ID",
//		new Field[] { StringField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE },
//		new String[] { "Overlay Space Name", "Base Space Name", "Minimum Offset", "Maximum Offset" });

	private static final int OV_SPACE_NAME_COL_V0 = 0;
	private static final int OV_SPACE_BASE_COL_V0 = 1;
	//private static final int OV_MIN_OFFSET_COL_V0 = 2; // OBSOLETE - Ignored
	//private static final int OV_MAX_OFFSET_COL_V0 = 3; // OBSOLETE - Ignored

	private Table table;

	OverlaySpaceDBAdapterV0(DBHandle dbHandle) throws VersionException {
		super(dbHandle);
		table = dbHandle.getTable(TABLE_NAME);
		if (table == null) {
			// Missing table case is OK but should be handled by latest version
			throw new VersionException("Missing Table: " + TABLE_NAME);
		}
		if (table.getSchema().getVersion() != VERSION) {
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
	}

	@Override
	ProgramOverlayAddressSpace createOverlaySpace(ProgramAddressFactory factory, String blockName,
			AddressSpace baseSpace) {
		throw new UnsupportedOperationException();
	}

	@Override
	boolean removeOverlaySpace(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	boolean renameOverlaySpace(String oldName, String newName) {
		throw new UnsupportedOperationException();
	}

	@Override
	void updateOverlayRecord(DBRecord rec) {
		throw new UnsupportedOperationException();
	}

	@Override
	void updateOverlaySpaces(ProgramAddressFactory factory) {
		throw new UnsupportedOperationException();
	}

	@Override
	void setLanguage(Language newLanguage, ProgramAddressFactory addrFactory,
			LanguageTranslator translator) {
		throw new UnsupportedOperationException();
	}

	@Override
	RecordIterator getOverlayRecords() throws IOException {
		return new V0ConvertedRecordIterator(table.iterator());
	}

	private DBRecord convertV0Record(DBRecord v0Rec) {
		String overlayName = v0Rec.getString(OV_SPACE_NAME_COL_V0);
		String baseSpaceName = v0Rec.getString(OV_SPACE_BASE_COL_V0);

		DBRecord rec = SCHEMA.createRecord(v0Rec.getKey());
		rec.setString(OV_SPACE_NAME_COL, overlayName);
		rec.setString(OV_SPACE_BASE_COL, baseSpaceName);
		return rec;
	}

	private class V0ConvertedRecordIterator extends ConvertedRecordIterator {

		V0ConvertedRecordIterator(RecordIterator originalIterator) {
			super(originalIterator, false);
		}

		@Override
		protected DBRecord convertRecord(DBRecord record) {
			return convertV0Record(record);
		}
	}
}
