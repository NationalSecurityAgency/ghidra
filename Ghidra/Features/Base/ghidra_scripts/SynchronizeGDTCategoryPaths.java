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
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

public class SynchronizeGDTCategoryPaths extends GhidraScript {

	private File firstFile;
	private File secondFile;
	private FileDataTypeManager firstArchive;
	private FileDataTypeManager secondArchive;

	@Override
	protected void run() throws Exception {
		firstFile = askFile("Select First GDT File", "Select 1st");
		secondFile = askFile("Select Second GDT File", "Select 2nd");

		try {
			firstArchive = FileDataTypeManager.openFileArchive(firstFile, false);
			secondArchive = FileDataTypeManager.openFileArchive(secondFile, true);

			int transactionID = secondArchive.startTransaction("Synchronize Category Path Names");
			Category firstCategory = firstArchive.getRootCategory();
			Category secondCategory = secondArchive.getRootCategory();

			synchronizeCategory(firstCategory, secondCategory);
			secondArchive.endTransaction(transactionID, true);
		}
		finally {
			if (firstArchive != null) {
				firstArchive.close();
			}
			secondArchive.save();
			if (secondArchive != null) {
				secondArchive.close();
			}
		}
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
