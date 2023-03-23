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

import ghidra.program.model.data.*;

public class CompositeViewerDataTypeManager extends StandAloneDataTypeManager {
	
	/** 
	 * The data type manager for original composite data type being edited.
	 * This is where the edited datatype will be written back to.
	 */
	private DataTypeManager originalDTM;
	private Composite originalComposite;
	private Composite viewComposite;
	private int transactionID;

	/**
	 * Creates a data type manager that the structure editor will use
	 * internally for updating the structure being edited.
	 * @param rootName the root name for this data type manager (usually the program name).
	 * @param originalComposite the original composite data type that is being edited. (cannot be null).
	 */
	public CompositeViewerDataTypeManager(String rootName, Composite originalComposite) {
		super(rootName, originalComposite.getDataTypeManager().getDataOrganization());
		this.originalComposite = originalComposite;
		transactionID = startTransaction(""); 
		originalDTM = originalComposite.getDataTypeManager();
		universalID = originalDTM.getUniversalID(); // mimic original DTM
		viewComposite = (Composite) super.resolve(originalComposite, null);
	}
	
	@Override
    public void close() {
		endTransaction(transactionID, true);
		super.close();
	}
	
	@Override
    public ArchiveType getType() {
		return originalDTM.getType();
	}

	@Override
	public boolean allowsDefaultBuiltInSettings() {
		return originalDTM.allowsDefaultBuiltInSettings();
	}

	@Override
	public DataType resolve(DataType dataType, DataTypeConflictHandler handler) {
		if (dataType == originalComposite && viewComposite != null) {
			// be sure to resolve use of original composite (e.g., pointer use)
			// from program/archive to view instance.  The viewComposite will
			// be null while resolving it during instantiation of this
			// DataTypeManager instance.
			return viewComposite;
		}
		return super.resolve(dataType, handler);
	}

}
