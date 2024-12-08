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
//
// Synchronize the category path name case from the first archive into the second
// archive.
//
//@category Data Types

import java.io.File;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.StandAloneDataTypeManager.ArchiveWarning;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

public class SynchronizeGDTCategoryPaths extends GhidraScript {

	@Override
	protected void run() throws Exception {

		File firstFile = askFile("Select First GDT File", "Select 1st");
		try (FileDataTypeManager firstArchive =
			FileDataTypeManager.openFileArchive(firstFile, false)) {
			if (hasWarning(firstArchive, firstFile)) {
				return;
			}

			File secondFile = askFile("Select Second GDT File", "Select 2nd");
			try (FileDataTypeManager secondArchive =
				FileDataTypeManager.openFileArchive(secondFile, true)) {
				if (hasWarning(secondArchive, secondFile)) {
					return;
				}

				int transactionID =
					secondArchive.startTransaction("Synchronize Category Path Names");
				try {
					Category firstCategory = firstArchive.getRootCategory();
					Category secondCategory = secondArchive.getRootCategory();
					synchronizeCategory(firstCategory, secondCategory);
				}
				finally {
					secondArchive.endTransaction(transactionID, true);
					secondArchive.save();
					secondArchive.close();
				}
			}
		}
	}

	private boolean hasWarning(FileDataTypeManager archive, File file) {
		ArchiveWarning warning = archive.getWarning();
		if (warning == ArchiveWarning.NONE) {
			return false;
		}
		if (warning == ArchiveWarning.UPGRADED_LANGUAGE_VERSION) {
			return !askYesNo("Archive Upgrade Confirmation",
				"A language upgrade has been performed on archive " + file.getName() +
					"\nIs it OK to proceed?");
		}
		popup(
			"An architecture language error occured while opening archive (see log for details)\n" +
				file.getPath());
		return true;
	}

	private void synchronizeCategory(Category firstCategory, Category secondCategory) {
		Category[] firstCategories = firstCategory.getCategories();
		for (Category categoryA : firstCategories) {

			// loop through categories looking for a case agnostic path match
			Category[] secondCategories = secondCategory.getCategories();
			boolean foundIt = false;
			for (Category categoryB : secondCategories) {
				if (categoryA.getName().equalsIgnoreCase(categoryB.getName())) {
					// if not the exact same name, rename it
					if (!categoryA.getName().equals(categoryB.getName())) {
						try {
							println(
								"Renamed " + categoryB.getName() + " to " + categoryA.getName());
							categoryB.setName(categoryA.getName());
							foundIt = true;
						}
						catch (DuplicateNameException | InvalidNameException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					else {
						foundIt = true;
					}
					synchronizeCategory(categoryA, categoryB);
				}
			}
			if (!foundIt) {
				println("Couldn't find matching category for " + categoryA.getName());
			}
		}
	}
}
