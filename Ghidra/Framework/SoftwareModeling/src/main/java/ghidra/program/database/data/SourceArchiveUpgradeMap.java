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
package ghidra.program.database.data;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.util.UniversalID;

public class SourceArchiveUpgradeMap {
	private static final long OLD_CLIB_ARCHIVE_ID = 2585014296036210369L;
	private static final long OLD_WINDOWS_ARCHIVE_ID = 2592694847825635591L;
	private static final long OLD_NTDDK_ARCHIVE_ID = 2585014353215059675L;
	private static final long[] oldArchiveIds =
		new long[] { OLD_CLIB_ARCHIVE_ID, OLD_NTDDK_ARCHIVE_ID, OLD_WINDOWS_ARCHIVE_ID };

	private CompilerSpecID WINDOWS_CSPEC_ID = new CompilerSpecID("windows");

	private Map<UniversalID, SourceArchive> oldArchiveRemappings;

	public SourceArchiveUpgradeMap() {

		UniversalID NEW_WINDOWS_SUPER_ARCHIVE_ID = new UniversalID(2644092282468053077L);
		UniversalID NEW_DEFAULT_CLIB_ARCHIVE_ID = new UniversalID(2644097909188870631L);

		String NEW_WINDOWS_SUPER_ARCHIVE_NAME = "windows_vs12_32";
		String NEW_DEFAULT_CLIB_ARCHIVE_NAME = "generic_clib";

		SourceArchive newWindowsArchive =
			new SourceArchiveImpl(NEW_WINDOWS_SUPER_ARCHIVE_ID, NEW_WINDOWS_SUPER_ARCHIVE_NAME);
		SourceArchive newDefaultClibArchive =
			new SourceArchiveImpl(NEW_DEFAULT_CLIB_ARCHIVE_ID, NEW_DEFAULT_CLIB_ARCHIVE_NAME);

		oldArchiveRemappings = new HashMap<UniversalID, SourceArchive>();

		// create mappings for old Windows archives
		oldArchiveRemappings.put(new UniversalID(OLD_CLIB_ARCHIVE_ID), newWindowsArchive);
		oldArchiveRemappings.put(new UniversalID(OLD_WINDOWS_ARCHIVE_ID), newWindowsArchive);
		oldArchiveRemappings.put(new UniversalID(OLD_NTDDK_ARCHIVE_ID), newWindowsArchive);

		// create mappings for old default archives
		oldArchiveRemappings.put(new UniversalID(OLD_CLIB_ARCHIVE_ID), newDefaultClibArchive);

		// create mappings for old removed archives
		SourceArchive removedSourceArchive = new SourceArchiveImpl();
		oldArchiveRemappings.put(new UniversalID(OLD_WINDOWS_ARCHIVE_ID), removedSourceArchive);
		oldArchiveRemappings.put(new UniversalID(OLD_NTDDK_ARCHIVE_ID), removedSourceArchive);

	}

	public SourceArchive getMappedSourceArchive(SourceArchive sourceArchive) {
		return oldArchiveRemappings.get(sourceArchive.getSourceArchiveID());
	}

	public static boolean isReplacedSourceArchive(long id) {
		for (long oldId : oldArchiveIds) {
			if (id == oldId) {
				return true;
			}
		}
		return false;
	}

	public static String[] getTypedefReplacements() {
		return new String[] { "short", "int", "long", "longlong", "wchar_t", "bool" };
	}

	private static class SourceArchiveImpl implements SourceArchive {

		private final UniversalID id;
		private final String archiveName;

		public SourceArchiveImpl(UniversalID id, String archiveName) {
			this.id = id;
			this.archiveName = archiveName;
		}

		public SourceArchiveImpl() {
			id = DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID;
			archiveName = "";
		}

		public ArchiveType getArchiveType() {
			return ArchiveType.FILE;
		}

		public String getDomainFileID() {
			return null;
		}

		public long getLastSyncTime() {
			return 0;
		}

		public String getName() {
			return archiveName;
		}

		public UniversalID getSourceArchiveID() {
			return id;
		}

		public boolean isDirty() {
			return false;
		}

		public void setDirtyFlag(boolean dirty) {
		}

		public void setLastSyncTime(long time) {
		}

		public void setName(String name) {
		}

	}

}
