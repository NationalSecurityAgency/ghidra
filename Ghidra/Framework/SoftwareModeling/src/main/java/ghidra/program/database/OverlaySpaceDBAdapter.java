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

import db.*;
import ghidra.framework.data.OpenMode;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.util.LanguageTranslator;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

abstract class OverlaySpaceDBAdapter {

	// TODO: Duplication of address space names must be avoided.  There is the possibility of
	// of a language change triggering such duplication with an existing overlay space.
	// Such a condition is currently unsupported and may cause severe errors. 

	static String TABLE_NAME = "Overlay Spaces";
	static final Schema SCHEMA = OverlaySpaceDBAdapterV1.SCHEMA_V1;
	static final int OV_SPACE_NAME_COL = OverlaySpaceDBAdapterV1.OV_SPACE_NAME_COL_V1;
	static final int OV_SPACE_BASE_COL = OverlaySpaceDBAdapterV1.OV_SPACE_BASE_COL_V1;

	final DBHandle db;

	OverlaySpaceDBAdapter(DBHandle dbHandle) {
		this.db = dbHandle;
	}

	static OverlaySpaceDBAdapter getOverlaySpaceAdapter(DBHandle dbHandle, OpenMode openMode,
			TaskMonitor monitor) throws IOException, VersionException, CancelledException {
		try {
			return new OverlaySpaceDBAdapterV1(dbHandle, openMode);
		}
		catch (VersionException e) {
			if (openMode == OpenMode.UPGRADE) {
				return upgrade(dbHandle, findReadOnlyAdapter(dbHandle), monitor);
			}
			if (e.isUpgradable() && openMode == OpenMode.IMMUTABLE) {
				return findReadOnlyAdapter(dbHandle);
			}
			throw e;
		}
	}

	private static OverlaySpaceDBAdapter findReadOnlyAdapter(DBHandle handle)
			throws VersionException {

		try {
			return new OverlaySpaceDBAdapterV0(handle);
		}
		catch (VersionException e1) {
			// failed - can't handle whatever version this is trying to open
		}

		throw new VersionException(false);
	}

	private static OverlaySpaceDBAdapter upgrade(DBHandle dbHandle,
			OverlaySpaceDBAdapter oldAdapter, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		monitor.setMessage("Upgrading Overlay Table...");
		monitor.initialize(oldAdapter.getRecordCount() * 2);

		DBHandle tmpHandle = dbHandle.getScratchPad();

		try {
			OverlaySpaceDBAdapter tmpAdapter =
				new OverlaySpaceDBAdapterV1(tmpHandle, OpenMode.CREATE);
			copyRecords(oldAdapter, tmpAdapter, monitor);

			dbHandle.deleteTable(TABLE_NAME);

			OverlaySpaceDBAdapter newAdapter =
				new OverlaySpaceDBAdapterV1(dbHandle, OpenMode.CREATE);
			copyRecords(tmpAdapter, newAdapter, monitor);

			tmpHandle.deleteTable(TABLE_NAME);

			return newAdapter;
		}
		finally {
			tmpHandle.deleteTable(TABLE_NAME);
		}
	}

	private static void copyRecords(OverlaySpaceDBAdapter fromAdapter,
			OverlaySpaceDBAdapter toAdapter, TaskMonitor monitor)
			throws IOException, CancelledException {

		RecordIterator iter = fromAdapter.getOverlayRecords();
		while (iter.hasNext()) {
			monitor.checkCancelled();
			DBRecord rec = iter.next();
			toAdapter.updateOverlayRecord(rec);
			monitor.incrementProgress(1);
		}
	}

	final int getRecordCount() {
		Table table = db.getTable(TABLE_NAME);
		return table != null ? table.getRecordCount() : 0;
	}

	/**
	 * Adds existing overlay spaces to the factory.
	 * @param factory the program address factory to add overlay spaces to
	 * @throws IOException if database error occurs
	 * @throws RuntimeException for various unsupported address space naming conditions
	 */
	final void initializeOverlaySpaces(ProgramAddressFactory factory) throws IOException {

		RecordIterator it = getOverlayRecords();
		while (it.hasNext()) {
			DBRecord rec = it.next();
			try {
				String spaceName = rec.getString(OV_SPACE_NAME_COL);
				if (factory.getAddressSpace(spaceName) != null) {
					throw new DuplicateNameException("Overlay space '" + spaceName +
						"' duplicates name of another address space");
				}

				String baseSpaceName = rec.getString(OV_SPACE_BASE_COL);
				AddressSpace space = factory.getAddressSpace(baseSpaceName);
				if (space == null) {
					throw new RuntimeException("Overlay base space '" + baseSpaceName +
						"' not found for overlay space '" + spaceName + "'");
				}
				factory.addOverlaySpace(rec.getKey(), spaceName, space);
			}
			catch (Exception e) {
				throw new IOException("Unexpected error initializing overlay address spaces", e);
			}
		}
	}

	/**
	 * Provide overlay space record iterator.  Older adapters will must translate records into
	 * the latest schema format.
	 * @return overlay space record iterator
	 * @throws IOException if database error occurs
	 */
	abstract RecordIterator getOverlayRecords() throws IOException;

	/**
	 * Update the overlay database table with the specified record
	 * @param rec overlay record in latest schema format
	 * @throws IOException if database error occurs
	 */
	abstract void updateOverlayRecord(DBRecord rec) throws IOException;

	/**
	 * Create a new overlay address space and associated record
	 * @param factory program address factory which retains address spaces
	 * @param overlayName overlay space name (may not contain `:`, space or other non-printable
	 *         characters.
	 * @param baseSpace underlying physical/base address space which is to be overlayed 
	 *        (must not be an overlay space)
	 * @return new overlay space (without regions defined)
	 * @throws IOException if database error occurs
	 * @throws DuplicateNameException if overlay name duplicates another address space name
	 * @throws InvalidNameException if specified overlay name is invalid
	 */
	abstract ProgramOverlayAddressSpace createOverlaySpace(ProgramAddressFactory factory,
			String overlayName, AddressSpace baseSpace)
			throws IOException, DuplicateNameException, InvalidNameException;

	/**
	 * Removes the named space from the database.  Caller is responsible for updating address
	 * factory.
	 * @param name the name of the overlay space to remove
	 * @return true if overlay record updated, false if not found
	 * @throws IOException if database error occurs
	 */
	abstract boolean removeOverlaySpace(String name) throws IOException;

	/**
	 * Rename the overlay space from oldName to newName.  Caller is responsible for updating
	 * address factory and ensuring that newName does not duplicate that of another address space.
	 * @param oldName old overlay name
	 * @param newName new overlay name
	 * @return true if overlay record updated, false if not found
	 * @throws IOException if database error occurs
	 */
	abstract boolean renameOverlaySpace(String oldName, String newName) throws IOException;

	/**
	 * Reconcile overlay spaces following cache invalidation (e.g., undo/redo)
	 * @param factory program address factory which retains address spaces
	 * @throws IOException if database error occurs
	 */
	abstract void updateOverlaySpaces(ProgramAddressFactory factory) throws IOException;

	/**
	 * Translate overlay address spaces for a new language provider
	 * and initialize the new addrFactory with the translated overlay spaces.
	 * All non-overlay address spaces within the address factory should already
	 * have been mapped to the new language. 
	 * @param newLanguage new language to be used
	 * @param addrFactory old address factory
	 * @param translator language translator to assist with mapping of address spaces
	 * @throws IOException if database error occurs
	 */
	abstract void setLanguage(Language newLanguage, ProgramAddressFactory addrFactory,
			LanguageTranslator translator) throws IOException;

}
