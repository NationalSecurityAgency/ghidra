/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.merge;

import ghidra.app.merge.datatypes.DataTypeMergeManager;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.framework.plugintool.ModalPluginTool;
import ghidra.program.model.data.DataTypeManagerDomainObject;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.program.model.listing.DataTypeArchiveChangeSet;

/** 
 * Top level object that manages each step of the merge/resolve conflicts
 * process.
 */
public class DataTypeArchiveMergeManager extends MergeManager { 

	public DataTypeArchiveMergeManager(	DataTypeManagerDomainObject resultDtArchive, 
										DataTypeManagerDomainObject myDtArchive, 
										DataTypeManagerDomainObject originalDtArchive, 
										DataTypeManagerDomainObject latestDtArchive,
										DataTypeArchiveChangeSet latestChangeSet, 
										DataTypeArchiveChangeSet myChangeSet) {
		super(resultDtArchive, myDtArchive, originalDtArchive, latestDtArchive, latestChangeSet, myChangeSet);
	}

	@Override
	protected void createMergeResolvers() {
		// create the merge resolvers
		int idx = 0;
		mergeResolvers = new MergeResolver[1];
		
		mergeResolvers[idx++] = new DataTypeMergeManager(	this, 
															(DataTypeManagerDomainObject)resultDomainObject, 
															(DataTypeManagerDomainObject)myDomainObject, 
															(DataTypeManagerDomainObject)originalDomainObject, 
															(DataTypeManagerDomainObject)latestDomainObject, 
															(DataTypeArchiveChangeSet)latestChangeSet, 
															(DataTypeArchiveChangeSet)myChangeSet);
	}

	/**
	 * Returns one of the four programs involved in the merge as indicated by the version.
	 * 
	 * @param version
	 *            the program version to return. (LATEST, MY, ORIGINAL, or RESULT).
	 * @return the indicated program version or null if a valid version isn't specified.
	 * @see MergeConstants
	 */
	public DataTypeArchive getDataTypeArchive(int version) {
		switch (version) {
			case MergeConstants.LATEST:
				return (DataTypeArchive)latestDomainObject;
			case MergeConstants.MY:
				return (DataTypeArchive)myDomainObject;
			case MergeConstants.ORIGINAL:
				return (DataTypeArchive)originalDomainObject;
			case MergeConstants.RESULT:
				return (DataTypeArchive)resultDomainObject;
			default:
				return null;
		}
	}
	
	@Override
	protected MergeManagerPlugin createMergeManagerPlugin(ModalPluginTool mergePluginTool,
			MergeManager multiUserMergeManager, UndoableDomainObject modifiableDomainObject) {
		return new DataTypeArchiveMergeManagerPlugin(mergeTool, DataTypeArchiveMergeManager.this, 
														(DataTypeArchive)resultDomainObject);
	}

	@Override
	protected void initializeMerge() {
	}

	@Override
	protected void cleanupMerge() {
	}

}
