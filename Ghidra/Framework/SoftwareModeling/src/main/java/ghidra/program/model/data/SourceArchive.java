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
package ghidra.program.model.data;

import ghidra.util.UniversalID;


/**
 * DataTypeSource holds information about a single data type archive which supplied a data type
 * to the program.
 */
public interface SourceArchive {
	
	/**
	 * Gets the ID that the program has associated with the data type archive.
	 * @return the data type archive ID
	 */
	public UniversalID getSourceArchiveID();

	/**
	 * Gets the ID used to uniquely identify the domain file for the data type archive.
	 * @return the domain file identifier
	 */
	public String getDomainFileID();
	
	/**
	 * Gets an indicator for the type of data type archive.
	 * (ArchiveType.BUILT_IN, ArchiveType.PROGRAM, ArchiveType.PROJECT, ArchiveType.FILE)
	 * @return the type
	 */
	public ArchiveType getArchiveType();

	/**
	 * Returns the name of the source archive
	 * @return the name of the source archive.
	 */
	public String getName();
	
	/**
	 * Returns the last time that this source archive was synchronized to the containing 
	 * DataTypeManager. 
	 * @return the last time that this source archive was synchronized to the containing 
	 * DataTypeManager.
	 */
	public long getLastSyncTime();
	
	/** 
	 * Returns true if at least one data type that originally came from this source archive has been
	 * changed.
	 * @return true if at least one data type that originally came from this source archive has been
	 * changed.
	 */
	public boolean isDirty();

	/**
	 * Sets the last time that this source archive was synchronized to the containing 
	 * DataTypeManager. 
	 * @param time the last time that this source archive was synchronized to the containing 
	 * DataTypeManager.
	 */
	public void setLastSyncTime( long time );
	
	/**
	 * Sets the name of the source archive associated with this SourceArchive object.
	 * @param name the name of the associated source archive.
	 */
	public void setName(String name);


	/**
	 * Sets the dirty flag to indicate if at least one data type that originally came from the 
	 * associated source archive has been changed since the last time the containing DataTypeManager
	 * was synchronized with it.
	 * @param dirty true means at least one data type that originally came from this source archive has been
	 * changed.
	 */
	public void setDirtyFlag( boolean dirty );
}
