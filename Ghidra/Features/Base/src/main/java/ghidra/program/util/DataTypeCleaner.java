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
package ghidra.program.util;

import java.io.Closeable;
import java.util.Iterator;

import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.*;
import ghidra.program.model.data.StandAloneDataTypeManager.LanguageUpdateOption;
import ghidra.program.model.lang.ProgramArchitecture;
import ghidra.util.task.TaskMonitor;

/**
 * {@link DataTypeCleaner} provides a convenient way to clean composite definitions which may be
 * included within a complex datatype which was derived from an source unrelated to a target
 * {@link DataTypeManager}.  The cleaning process entails clearing all details associated with
 * all composites other than their description which may be present.  There is also an option
 * to retain those composites which are already defined within the target.
 * <br>
 * All datatypes and their referenced datatypes will be accumulated and possibly re-used across
 * multiple invocations of the {@link #clean(DataType)} method.  It is important that this instance 
 * be {@link #close() closed} when instance and any resulting {@link DataType} is no longer in use.
 */
public class DataTypeCleaner implements Closeable {

	private final DataTypeManager targetDtm;
	private final boolean retainExistingComposites;
	private final StandAloneDataTypeManager cleanerDtm;

	private int txId;

	/**
	 * Consruct a {@link DataTypeCleaner} instance.  The caller must ensure that this instance
	 * is {@link #close() closed} when instance and any resulting {@link DataType} is no longer in
	 * use.
	 * @param targetDtm target datatype manager
	 * @param retainExistingComposites if true all composites will be checked against the 
	 * {@code targetDtm} and retained if it already exists, otherwise all composites will be
	 * cleaned.
	 */
	public DataTypeCleaner(DataTypeManager targetDtm, boolean retainExistingComposites) {
		this.targetDtm = targetDtm;
		this.retainExistingComposites = retainExistingComposites;
		this.cleanerDtm = new StandAloneDataTypeManager("CleanerDTM");
		txId = cleanerDtm.startTransaction("CleanerTx");

		ProgramArchitecture arch = targetDtm.getProgramArchitecture();
		if (arch != null) {
			try {
				cleanerDtm.setProgramArchitecture(arch.getLanguage(),
					arch.getCompilerSpec().getCompilerSpecID(), LanguageUpdateOption.UNCHANGED,
					TaskMonitor.DUMMY);
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
	}

	/**
	 * Clean the specified datatype
	 * @param dt datatype
	 * @return clean datatype
	 */
	public DataType clean(DataType dt) {

		if (txId == -1) {
			throw new IllegalStateException("DataTypeCleaner has been closed");
		}

		DataType cleanDt = cleanerDtm.resolve(dt,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);

		Iterator<Composite> allComposites = cleanerDtm.getAllComposites();
		while (allComposites.hasNext()) {
			Composite c = allComposites.next();
			if (c.isNotYetDefined()) {
				continue;
			}
			if (retainExistingComposites && targetContainsComposite(c)) {
				continue;
			}
			Composite replacement = null;
			if (c instanceof Structure s) {
				replacement =
					new StructureDataType(c.getCategoryPath(), c.getName(), 0, cleanerDtm);
			}
			else if (c instanceof Union u) {
				replacement = new UnionDataType(c.getCategoryPath(), c.getName(), cleanerDtm);
			}
			if (replacement != null) {
				replacement.setDescription(c.getDescription());
				c.replaceWith(replacement);
			}
		}
		return cleanDt;
	}

	private boolean targetContainsComposite(Composite c) {
		Category category = targetDtm.getCategory(c.getCategoryPath());
		if (category == null) {
			return false;
		}
		String baseName = DataTypeUtilities.getNameWithoutConflict(c, false);
		for (DataType dt : category.getDataTypesByBaseName(baseName)) {
			if (dt.isEquivalent(c)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void close() {
		if (txId == -1) {
			return;
		}
		cleanerDtm.endTransaction(txId, true); // faster to commit
		cleanerDtm.close();
		txId = -1; // closed indicator
	}

}
