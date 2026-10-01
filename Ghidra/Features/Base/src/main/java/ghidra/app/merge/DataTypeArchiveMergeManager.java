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
package ghidra.app.merge;

import ghidra.app.merge.datatypes.DataTypeMergeManager;
import ghidra.framework.plugintool.ModalPluginTool;
import ghidra.program.model.dtarchive.ProjectDataTypeArchive;
import ghidra.program.model.listing.DataTypeArchiveChangeSet;

/** 
 * Top level object that manages each step of the merge/resolve conflicts
 * process.
 */
public class DataTypeArchiveMergeManager
		extends MergeManager<ProjectDataTypeArchive, DataTypeArchiveChangeSet> {

	public DataTypeArchiveMergeManager(ProjectDataTypeArchive resultDtArchive,
			ProjectDataTypeArchive myDtArchive, ProjectDataTypeArchive originalDtArchive,
			ProjectDataTypeArchive latestDtArchive, DataTypeArchiveChangeSet latestChangeSet,
			DataTypeArchiveChangeSet myChangeSet) {
		super(resultDtArchive, myDtArchive, originalDtArchive, latestDtArchive, latestChangeSet,
			myChangeSet);
	}

	@Override
	protected void createMergeResolvers() {
		// create the merge resolvers
		int idx = 0;
		mergeResolvers = new MergeResolver[1];

		mergeResolvers[idx++] =
			new DataTypeMergeManager(this, resultDomainObject, myDomainObject, originalDomainObject,
				latestDomainObject, latestChangeSet, myChangeSet);
	}

	/**
	 * Returns one of the four programs involved in the merge as indicated by the version.
	 * 
	 * @param version
	 *            the program version to return. (LATEST, MY, ORIGINAL, or RESULT).
	 * @return the indicated program version or null if a valid version isn't specified.
	 * @see MergeConstants
	 */
	public ProjectDataTypeArchive getDataTypeArchive(int version) {
		switch (version) {
			case MergeConstants.LATEST:
				return latestDomainObject;
			case MergeConstants.MY:
				return myDomainObject;
			case MergeConstants.ORIGINAL:
				return originalDomainObject;
			case MergeConstants.RESULT:
				return resultDomainObject;
			default:
				return null;
		}
	}

	@Override
	protected MergeManagerPlugin createMergeManagerPlugin(ModalPluginTool mergePluginTool,
			MergeManager<ProjectDataTypeArchive, DataTypeArchiveChangeSet> multiUserMergeManager,
			ProjectDataTypeArchive modifiableDomainObject) {
		return new DataTypeArchiveMergeManagerPlugin(mergeTool, DataTypeArchiveMergeManager.this,
			resultDomainObject);
	}

	@Override
	protected void initializeMerge() {
	}

	@Override
	protected void cleanupMerge() {
	}

}
