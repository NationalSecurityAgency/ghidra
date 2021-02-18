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
package ghidra.app.util.bin.format.dwarf4.next;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.util.bin.format.dwarf4.DWARFException;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import utility.function.Dummy;

/**
 * Performs a DWARF datatype import and a DWARF function import, under the control of the
 * {@link DWARFImportOptions}.
 */
public class DWARFParser {
	private DWARFProgram prog;
	private DWARFDataTypeManager dwarfDTM;
	private TaskMonitor monitor;
	private DWARFImportOptions importOptions;
	private DWARFImportSummary importSummary = new DWARFImportSummary();

	public DWARFParser(DWARFProgram prog, DataTypeManager builtInDTM, TaskMonitor monitor) {
		this.prog = prog;
		this.monitor = monitor;
		this.importOptions = prog.getImportOptions();
		this.dwarfDTM = new DWARFDataTypeManager(prog, prog.getGhidraProgram().getDataTypeManager(),
			builtInDTM, importSummary);
	}

	public DWARFImportOptions getImportOptions() {
		return importOptions;
	}

	/**
	 * Moves previously imported DataTypes from the /DWARF/_UNCATEGORIZED_ folder into
	 * folder /DWARF/source_code_filename.ext/...
	 * <p>
	 * When moving / renaming DataTypes, you only need to worry about named DataTypes.
	 * Pointers and Arrays, which can only exist by referring to a named DataType, get
	 * moved / renamed automagically by the DataTypeManager.
	 * <p>
	 * After moving each DataType, if the folder is empty, remove the folder.
	 *
	 * @throws CancelledException
	 */
	private void moveTypesIntoSourceFolders() throws CancelledException {

		// Sort by category to reduce the amount of thrashing the DTM does reloading
		// categories.
		List<DataTypePath> importedTypes = dwarfDTM.getImportedTypes();
		Collections.sort(importedTypes,
			(dtp1, dtp2) -> dtp1.getCategoryPath()
					.getPath()
					.compareTo(dtp2.getCategoryPath().getPath()));

		monitor.setIndeterminate(false);
		monitor.setShowProgressValue(true);
		monitor.initialize(importedTypes.size());
		monitor.setMessage("DWARF Move Types");

		CategoryPath unCatRootCp = prog.getUncategorizedRootDNI().getOrganizationalCategoryPath();
		CategoryPath rootCP = prog.getRootDNI().asCategoryPath();

		for (DataTypePath dataTypePath : importedTypes) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);

			if ( (monitor.getProgress() % 5) == 0 ) {
				/* balance between getting work done and pampering the swing thread */ 
				Swing.runNow(Dummy.runnable());
			}

			DataType dataType =
				prog.getGhidraProgram().getDataTypeManager().getDataType(dataTypePath);
			if (dataType != null && !(dataType instanceof Pointer || dataType instanceof Array)) {
				DWARFSourceInfo dsi = dwarfDTM.getSourceInfo(dataType);
				if (dsi != null && dsi.getFilename() != null) {
					CategoryPath dataTypeOrigCP = dataType.getCategoryPath();
					CategoryPath newRoot = new CategoryPath(rootCP, dsi.getFilename());
					CategoryPath newCP =
						rehomeCategoryPathSubTree(unCatRootCp, newRoot, dataTypeOrigCP);
					if (newCP != null) {
						try {
							dataType.setCategoryPath(newCP);
							if (dataType instanceof Composite) {
								fixupAnonStructMembers((Composite) dataType, dataTypeOrigCP, newCP);
							}
							deleteEmptyCategoryPaths(dataTypeOrigCP);
						}
						catch (DuplicateNameException e) {
							// if some unexpected error occurs during a move operation,
							// the datatype is left in its original location under _UNCATEGORIZED_.
							Msg.error(this,
								"Failed to move " + dataType.getDataTypePath() + " to " + newCP);
						}
					}
				}
			}
		}

		monitor.setMessage("DWARF Move Types - Done");
	}

	/*
	 * Moves DataTypes found in a Composite's fields, if they appear to be anonymous
	 * and don't have their own source code location information.
	 */
	private void fixupAnonStructMembers(Composite compositeDataType, CategoryPath origCategoryPath,
			CategoryPath newCP) throws DuplicateNameException {
		CategoryPath origCompositeNSCP =
			new CategoryPath(origCategoryPath, compositeDataType.getName());
		CategoryPath destCompositeNSCP = new CategoryPath(newCP, compositeDataType.getName());
		for (DataTypeComponent component : compositeDataType.getDefinedComponents()) {
			DataType dtcDT = component.getDataType();
			if (dtcDT instanceof Array || dtcDT instanceof Pointer) {
				dtcDT = DataTypeUtils.getNamedBaseDataType(dtcDT);
			}
			if (dtcDT.getCategoryPath().equals(origCompositeNSCP) &&
				dwarfDTM.getSourceInfo(dtcDT) == null) {
				dtcDT.setCategoryPath(destCompositeNSCP);
			}
		}
		deleteEmptyCategoryPaths(origCompositeNSCP);
	}

	private void deleteEmptyCategoryPaths(CategoryPath cp) {
		DataTypeManager dtm = prog.getGhidraProgram().getDataTypeManager();
		while (!CategoryPath.ROOT.equals(cp)) {
			Category cat = dtm.getCategory(cp);
			Category parentCat = dtm.getCategory(cp.getParent());
			if (cat == null || parentCat == null) {
				break;
			}

			if (cat.getDataTypes().length != 0 || cat.getCategories().length != 0) {
				break;
			}

			if (!parentCat.removeEmptyCategory(cat.getName(), monitor)) {
				Msg.error(this, "Failed to delete empty category " + cp);
				break;
			}
			cp = parentCat.getCategoryPath();
		}
	}

	private CategoryPath rehomeCategoryPathSubTree(CategoryPath origRoot, CategoryPath newRoot,
			CategoryPath cp) {
		if (origRoot.equals(cp)) {
			return newRoot;
		}

		String origRootPath = origRoot.getPath();
		if (!CategoryPath.ROOT.equals(origRoot)) {
			origRootPath += "/";
		}
		String newRootPath = newRoot.getPath();
		if (!CategoryPath.ROOT.equals(newRoot)) {
			newRootPath += "/";
		}
		String cpPath = cp.getPath();
		if (cpPath.startsWith(origRootPath)) {
			String newPath = newRootPath + cpPath.substring(origRootPath.length());
			return new CategoryPath(newPath);
		}
		return null;
	}

	/**
	 * Imports DWARF information according to the {@link DWARFImportOptions} set.
	 * <p>
	 * {@link DWARFProgram#checkPreconditions(TaskMonitor)} must be called before this.
	 * <p>
	 * @return
	 * @throws IOException
	 * @throws DWARFException
	 * @throws CancelledException
	 */
	public DWARFImportSummary parse() throws IOException, DWARFException, CancelledException {
		monitor.setIndeterminate(false);
		monitor.setShowProgressValue(true);

		long start_ts = System.currentTimeMillis();

		if (importOptions.isImportDataTypes()) {
			dwarfDTM.importAllDataTypes(monitor);
			prog.getGhidraProgram().flushEvents();
			importSummary.dataTypeElapsedMS = System.currentTimeMillis() - start_ts;
		}

		if (importOptions.isImportFuncs()) {
			long funcstart_ts = System.currentTimeMillis();
			DWARFFunctionImporter dfi =
				new DWARFFunctionImporter(prog, dwarfDTM, importOptions, importSummary, monitor);
			dfi.importFunctions();
			importSummary.funcsElapsedMS = System.currentTimeMillis() - funcstart_ts;
		}

		if (importOptions.isOrganizeTypesBySourceFile()) {
			moveTypesIntoSourceFolders();
		}

		importSummary.totalElapsedMS = System.currentTimeMillis() - start_ts;

		return importSummary;
	}
}
