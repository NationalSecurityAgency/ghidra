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
package ghidra.app.plugin.core.datamgr.archive;

import ghidra.program.model.data.*;
import ghidra.util.UniversalID;

public class BuiltInSourceArchive implements SourceArchive {
	public static final SourceArchive INSTANCE = new BuiltInSourceArchive();

	private BuiltInSourceArchive() {
		
	}
	
	@Override
	public ArchiveType getArchiveType() {
		return ArchiveType.BUILT_IN;
	}

	@Override
	public String getDomainFileID() {
		return null;
	}

	@Override
	public long getLastSyncTime() {
		return 0;
	}

	@Override
	public String getName() {
		return DataTypeManager.BUILT_IN_DATA_TYPES_NAME;
	}

	public String getPathname() {
		return "";
	}

	@Override
	public UniversalID getSourceArchiveID() {
		return DataTypeManager.BUILT_IN_ARCHIVE_UNIVERSAL_ID;
	}

	@Override
	public boolean isDirty() {
		return false;
	}
	@Override
	public void setDirtyFlag( boolean b ) {
	}

	@Override
	public void setLastSyncTime( long time ) {
	}

	@Override
	public void setName( String name ) {
	}

	public void setPathname( String name ) {
	}

}
