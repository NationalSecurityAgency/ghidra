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
import java.util.*;

import db.*;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.util.LanguageTranslator;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;

class OverlaySpaceDBAdapterV1 extends OverlaySpaceDBAdapter {

	private static final int VERSION = 1;

	static final Schema SCHEMA_V1 =
		new Schema(VERSION, "ID", new Field[] { StringField.INSTANCE, StringField.INSTANCE },
			new String[] { "Overlay Space Name", "Base Space Name" });

	static final int OV_SPACE_NAME_COL_V1 = 0;
	static final int OV_SPACE_BASE_COL_V1 = 1;

	OverlaySpaceDBAdapterV1(DBHandle dbHandle, OpenMode openMode)
			throws IOException, VersionException {
		super(dbHandle);

		Table table = dbHandle.getTable(TABLE_NAME);
		if (openMode == OpenMode.CREATE) {
			if (table != null) {
				throw new IOException("Table already exists: " + TABLE_NAME);
			}
			return; // lazy table creation
		}

		if (table != null && table.getSchema().getVersion() != VERSION) {
			int version = table.getSchema().getVersion();
			if (version < VERSION) {
				throw new VersionException(true);
			}
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
	}

	@Override
	ProgramOverlayAddressSpace createOverlaySpace(ProgramAddressFactory factory, String spaceName,
			AddressSpace baseSpace)
			throws IOException, DuplicateNameException, InvalidNameException {

		if (!factory.isValidOverlayBaseSpace(baseSpace)) {
			throw new IllegalArgumentException(
				"Invalid address space for overlay: " + baseSpace.getName());
		}

		factory.checkValidOverlaySpaceName(spaceName);

		if (factory.getAddressSpace(spaceName) != null) {
			throw new DuplicateNameException(
				"Overlay space '" + spaceName + "' duplicates name of another address space");
		}

		Table table = db.getTable(TABLE_NAME);
		if (table == null) {
			table = db.createTable(TABLE_NAME, SCHEMA_V1);
		}
		DBRecord rec = SCHEMA_V1.createRecord(table.getKey());
		rec.setString(OV_SPACE_NAME_COL_V1, spaceName);
		rec.setString(OV_SPACE_BASE_COL_V1, baseSpace.getName());
		table.putRecord(rec);

		return factory.addOverlaySpace(rec.getKey(), spaceName, baseSpace);
	}

	@Override
	protected RecordIterator getOverlayRecords() throws IOException {
		Table table = db.getTable(TABLE_NAME);
		if (table == null) {
			return EmptyRecordIterator.INSTANCE;
		}
		return table.iterator();
	}

	@Override
	protected void updateOverlayRecord(DBRecord rec) throws IOException {
		Table table = db.getTable(TABLE_NAME);
		if (table == null) {
			table = db.createTable(TABLE_NAME, SCHEMA_V1);
		}
		table.putRecord(rec);
	}

	@Override
	boolean removeOverlaySpace(String name) throws IOException {
		Table table = db.getTable(TABLE_NAME);
		if (table == null) {
			return false;
		}

		RecordIterator it = table.iterator();
		while (it.hasNext()) {
			DBRecord rec = it.next();
			String overlayName = rec.getString(0);
			if (name.equals(overlayName)) {
				it.delete();
				return true;
			}
		}
		return false;
	}

	@Override
	boolean renameOverlaySpace(String oldName, String newName) throws IOException {
		Table table = db.getTable(TABLE_NAME);
		if (table == null) {
			return false;
		}

		RecordIterator it = table.iterator();
		while (it.hasNext()) {
			DBRecord rec = it.next();
			String spaceName = rec.getString(0);
			if (oldName.equals(spaceName)) {
				it.delete();
				rec.setString(0, newName);
				table.putRecord(rec);
				return true;
			}
		}
		return false;
	}

	@Override
	void updateOverlaySpaces(ProgramAddressFactory factory) throws IOException {

		// Perform reconciliation of overlay address spaces while attempting to preserve 
		// address space instances associated with a given key

		// Put all overlay records into key-based map
		Map<Long, DBRecord> keyToRecordMap = new HashMap<>();
		Table table = db.getTable(TABLE_NAME);
		if (table != null) {
			RecordIterator it = table.iterator();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				keyToRecordMap.put(rec.getKey(), rec);
			}
		}

		// Examine existing overlay spaces for removals and renames
		List<ProgramOverlayAddressSpace> renameList = new ArrayList<>();
		for (AddressSpace space : factory.getAllAddressSpaces()) {
			if (space instanceof ProgramOverlayAddressSpace os) {
				String name = os.getName();
				DBRecord rec = keyToRecordMap.get(os.getKey());
				if (rec == null || !isCompatibleOverlay(os, rec, factory)) {
					// Remove overlay if record does not exist or base space differs
					factory.removeOverlaySpace(name);
				}
				else if (name.equals(rec.getString(OV_SPACE_NAME_COL_V1))) {
					keyToRecordMap.remove(os.getKey());
					continue; // no change to space
				}
				else {
					// Add space to map of those that need to be renamed
					renameList.add(os);
					factory.removeOverlaySpace(name);
				}
			}
		}

		try {
			// Handle all renamed overlays which had been temporarily removed from factory
			for (ProgramOverlayAddressSpace existingSpace : renameList) {
				long key = existingSpace.getKey();
				DBRecord rec = keyToRecordMap.get(key);
				existingSpace.setName(rec.getString(OV_SPACE_NAME_COL_V1));
				factory.addOverlaySpace(existingSpace); // re-add renamed space
				keyToRecordMap.remove(key);
			}

			// Add any remaing overlay which are missing from factory
			for (long key : keyToRecordMap.keySet()) {
				DBRecord rec = keyToRecordMap.get(key);
				String spaceName = rec.getString(OV_SPACE_NAME_COL_V1);
				AddressSpace baseSpace =
					factory.getAddressSpace(rec.getString(OV_SPACE_BASE_COL_V1));
				factory.addOverlaySpace(key, spaceName, baseSpace);
			}
		}
		catch (IllegalArgumentException | DuplicateNameException e) {
			throw new AssertionError("Unexpected error updating overlay address spaces", e);
		}

		factory.refreshStaleOverlayStatus();
	}

	private boolean isCompatibleOverlay(ProgramOverlayAddressSpace os, DBRecord rec,
			ProgramAddressFactory factory) throws IOException {
		String baseSpaceName = rec.getString(OV_SPACE_BASE_COL_V1);
		AddressSpace baseSpace = factory.getAddressSpace(baseSpaceName);
		if (baseSpace == null) {
			throw new IOException("Base space for overlay not found: " + baseSpaceName);
		}
		return baseSpace == os.getOverlayedSpace();
	}

	@Override
	void setLanguage(Language newLanguage, ProgramAddressFactory addrFactory,
			LanguageTranslator translator) throws IOException {

		Table table = db.getTable(TABLE_NAME);
		if (table != null) {
			RecordIterator it = table.iterator();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				String oldUnderlyingSpaceName = rec.getString(OV_SPACE_BASE_COL_V1);
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
				rec.setString(OV_SPACE_BASE_COL_V1, newSpace.getName());
				table.putRecord(rec);
			}
		}
		initializeOverlaySpaces(addrFactory);
	}
}
