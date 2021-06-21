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
import java.util.HashMap;
import java.util.Map;

import db.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.util.LanguageTranslator;
import ghidra.util.exception.DuplicateNameException;

class OverlaySpaceAdapterDB {
	private static String TABLE_NAME = "Overlay Spaces";
	static final Schema SCHEMA = new Schema(0, "ID",
		new Field[] { StringField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE,
			LongField.INSTANCE },
		new String[] { "Overlay Space", "Template Space", "Minimum Offset", "Maximum Offset" });

	private static final int OV_SPACE_NAME_COL = 0;
	private static final int OV_SPACE_BASE_COL = 1;
	private static final int OV_MIN_OFFSET_COL = 2;
	private static final int OV_MAX_OFFSET_COL = 3;

	DBHandle db;

	OverlaySpaceAdapterDB(DBHandle dbHandle) {
		this.db = dbHandle;
	}

	/**
	 * Adds existing overlay spaces to the factory.
	 * @param factory the factory to add overlay spaces to
	 * @throws IOException
	 */
	void initializeOverlaySpaces(ProgramAddressFactory factory) throws IOException {
		Table table = db.getTable(TABLE_NAME);
		if (table != null) {
			RecordIterator it = table.iterator();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				String spaceName = rec.getString(OV_SPACE_NAME_COL);
				String templateSpaceName = rec.getString(OV_SPACE_BASE_COL);
				long minOffset = rec.getLongValue(OV_MIN_OFFSET_COL);
				long maxOffset = rec.getLongValue(OV_MAX_OFFSET_COL);
				AddressSpace space = factory.getAddressSpace(templateSpaceName);
				try {
					OverlayAddressSpace sp =
						factory.addOverlayAddressSpace(spaceName, true, space, minOffset, maxOffset);
					sp.setDatabaseKey(rec.getKey());
				}
				catch (IllegalArgumentException e) {
					throw new RuntimeException(
						"Unexpected error initializing overlay address spaces", e);
				}
			}
		}
	}

	/**
	 * Adds a new overlay space to the database
	 * @param id the name of the new overlay space to add
	 * @param space the template space used to create the new space.
	 * @param minOffset the lowest offset in this overlay.
	 * @param maxOffset the highest offset in this overlay.
	 * @throws IOException
	 */
	void addOverlaySpace(OverlayAddressSpace ovSpace) throws IOException {
		Table table = db.getTable(TABLE_NAME);
		if (table == null) {
			table = db.createTable(TABLE_NAME, SCHEMA);
		}
		DBRecord rec = SCHEMA.createRecord(table.getKey());
		rec.setString(0, ovSpace.getName());
		rec.setString(1, ovSpace.getOverlayedSpace().getName());
		rec.setLongValue(OV_MIN_OFFSET_COL, ovSpace.getMinOffset());
		rec.setLongValue(OV_MAX_OFFSET_COL, ovSpace.getMaxOffset());
		table.putRecord(rec);
		ovSpace.setDatabaseKey(rec.getKey());
	}

	/**
	 * Removes the named space from the database
	 * @param name the name of the overlay space to remove
	 * @throws IOException
	 */
	void removeOverlaySpace(String name) throws IOException {
		Table table = db.getTable(TABLE_NAME);
		if (table != null) {
			RecordIterator it = table.iterator();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				String spaceName = rec.getString(0);
				if (name.equals(spaceName)) {
					it.delete();
					return;
				}
			}
		}
	}

	void updateOverlaySpaces(ProgramAddressFactory factory) throws IOException {
		Map<Long, OverlayAddressSpace> map = new HashMap<>();
		for (AddressSpace space : factory.getAllAddressSpaces()) {
			if (space instanceof OverlayAddressSpace) {
				OverlayAddressSpace os = (OverlayAddressSpace) space;
				map.put(os.getDatabaseKey(), os);
			}
		}
		Table table = db.getTable(TABLE_NAME);
		if (table != null) {
			RecordIterator it = table.iterator();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				OverlayAddressSpace space = map.remove(rec.getKey());
				if (space != null) {
					//maxId = Math.max(maxId, space.getUnique());
					String spaceName = rec.getString(OV_SPACE_NAME_COL);
					if (!spaceName.equals(space.getName())) {
						factory.removeOverlaySpace(space.getName());
						space.setName(rec.getString(OV_SPACE_NAME_COL));
						try {
							factory.addOverlayAddressSpace(space);
						}
						catch (DuplicateNameException e) {
							throw new RuntimeException(
								"Unexpected error updating overlay address spaces", e);
						}
					}
				}
				else {
					String spaceName = rec.getString(OV_SPACE_NAME_COL);
					long minOffset = rec.getLongValue(OV_MIN_OFFSET_COL);
					long maxOffset = rec.getLongValue(OV_MAX_OFFSET_COL);
					AddressSpace origSpace =
						factory.getAddressSpace(rec.getString(OV_SPACE_BASE_COL));
					try {
						space = factory.addOverlayAddressSpace(spaceName, true, origSpace,
							minOffset,
							maxOffset);
						space.setDatabaseKey(rec.getKey());
					}
					catch (IllegalArgumentException e) {
						throw new RuntimeException(
							"Unexpected error updating overlay address spaces", e);
					}
				}
			}
		}
		for (OverlayAddressSpace space : map.values()) {
			factory.removeOverlaySpace(space.getName());
		}
	}

	public void renameOverlaySpace(String oldName, String newName) throws IOException {
		Table table = db.getTable(TABLE_NAME);
		if (table != null) {
			RecordIterator it = table.iterator();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				String spaceName = rec.getString(0);
				if (oldName.equals(spaceName)) {
					it.delete();
					rec.setString(0, newName);
					table.putRecord(rec);
					return;
				}
			}
		}
	}

	/**
	 * Translate overlay address spaces for a new language provider
	 * and initialize the new addrFactory with the translated overlay spaces.
	 * All non-overlay address spaces within the address factory should already
	 * have been mapped to the new language. 
	 * @param newLanguage new language to be used
	 * @param addrFactory old address factory
	 * @param translator language translator to assist with mapping of address spaces
	 * @throws IOException
	 */
	void setLanguage(Language newLanguage, ProgramAddressFactory addrFactory,
			LanguageTranslator translator) throws IOException {

		Table table = db.getTable(TABLE_NAME);
		if (table != null) {
			RecordIterator it = table.iterator();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				String oldUnderlyingSpaceName = rec.getString(OV_SPACE_BASE_COL);
				AddressSpace space = addrFactory.getAddressSpace(oldUnderlyingSpaceName);
				if (space != null && space.isNonLoadedMemorySpace()) {
					// skip overlays associated with non-loaded spaces such as OTHER space
					continue;
				}
				AddressSpace newSpace = translator.getNewAddressSpace(oldUnderlyingSpaceName);
				if (newSpace == null) {
					throw new IOException(
						"Failed to map old address space: " + oldUnderlyingSpaceName);
				}
				rec.setString(OV_SPACE_BASE_COL, newSpace.getName());
				table.putRecord(rec);
			}
		}
		initializeOverlaySpaces(addrFactory);
	}

}
