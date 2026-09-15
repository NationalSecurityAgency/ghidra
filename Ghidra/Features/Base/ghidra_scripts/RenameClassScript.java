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

// Rename a class and the struct that it is mapped to, if one exists.
//
// This script differs from the "Rename" action in the symbol tree in that it
// also renames the struct associated with the class, if one exists.
//
// When run from the GUI, the script presents a choice of all current Classes,
// defaulting to the class of the current function if found. A confirmation
// dialog will show the items that will be renamed before any actions are taken.
//
// When run in headless mode, the first argument must be the full path to the
// class to rename, for example "namespace::Class", and the second must be the
// new name, for example "NewClass". These two examples would result in the
// class being renamed to "namespace::NewClass".
//
// @category C++

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * A GhidraScript to rename a class and structure.
 */
public class RenameClassScript extends GhidraScript {

	/**
	 * A container for GhidraClass with a more user-friendly toString method. This
	 * is especially useful for running this script in headless mode, so that the
	 * path to the class is all that is needed, without the the " (GhidraClass)"
	 * suffix added by the default toString method.
	 */
	private class ClassChoice {
		public GhidraClass cls;

		public ClassChoice(GhidraClass cls) {
			this.cls = cls;
		}

		/**
		 * The full path of the GhidraClass for this choice.
		 */
		public String toString() {
			return cls.getName(true);
		}
	}

	/**
	 * Renames a GhidraClass and matching struct, if present.
	 *
	 * @param classToRename  The Ghidra class to rename.
	 * @param structToRename The struct matching the class to also rename. If this
	 *                       is null, then only the class is renamed.
	 * @param newName        The new name for the class, without any parent
	 *                       namespaces.
	 * @throws DuplicateNameException A GhidraClass or Structure with the new name
	 *                                already exists.
	 * @throws InvalidInputException  The new name is not a valid symbol name.
	 * @throws InvalidNameException   The new name is not a structure name.
	 */
	public static void renameClass(GhidraClass classToRename, Structure structToRename, String newName)
			throws DuplicateNameException, InvalidInputException, InvalidNameException {
		String oldName = classToRename.getName(true);
		Symbol symbol = classToRename.getSymbol();
		Program program = symbol.getProgram();

		// this class rename implementation is a simplified version of
		// SymbolNode#valueChanged in Ghidra release 11.1.2
		// this script doesn't allow parent namespace renames, so is a bit simpler
		String actionDescription = "rename " + oldName + " to " + newName;
		int transaction = program.startTransaction(actionDescription);
		try {
			symbol.setName(newName, SourceType.USER_DEFINED);

			if (structToRename != null) {
				structToRename.setName(newName);
			}
		} catch (DuplicateNameException | InvalidInputException | InvalidNameException e) {
			program.endTransaction(transaction, false);
			throw e;
		}

		program.endTransaction(transaction, true);
	}

	/**
	 * Prompt the user for confirmation of the changes that will be performed as
	 * part of the rename.
	 *
	 * @param chosenClass The class that will be renamed.
	 * @param struct      The structure that will be renamed.
	 * @param newName     The new name of the class and structure.
	 * @throws CancelledException If the user declines the confirmation, then the
	 *                            script is treated as if it was cancelled.
	 */
	private void confirmRename(GhidraClass chosenClass, Structure struct, String newName) throws CancelledException {
		StringBuilder actionSummary = new StringBuilder("The following actions will be performed:\n\nClass ");
		actionSummary.append(chosenClass);
		actionSummary.append(" will be renamed to ");
		actionSummary.append(newName);
		actionSummary.append('\n');

		if (struct == null) {
			actionSummary.append("no structure matching the class to rename");
		} else {
			actionSummary.append("Structure ");
			actionSummary.append(struct.getPathName());
			actionSummary.append(" will be renamed to ");
			actionSummary.append(newName);
		}

		actionSummary.append("\n\nIs this correct?");

		boolean confirmed = askYesNo("Confirm Rename", actionSummary.toString());
		if (!confirmed) {
			throw new CancelledException();
		}
	}

	/**
	 * Gets the class of the current function, if one exists.
	 *
	 * @param classList A list of classes in the current program.
	 * @return The class from the list that is equal to one of the current
	 *         function's parent namespaces, or null if such a match is not found.
	 */
	private ClassChoice currentClass(List<ClassChoice> classList) {
		FunctionManager fm = currentProgram.getFunctionManager();
		Namespace currentNamespace = fm.getFunctionContaining(currentAddress);

		while (currentNamespace != null) {
			Iterator<ClassChoice> it = classList.iterator();
			while (it.hasNext()) {
				ClassChoice classChoice = it.next();
				if (classChoice.cls.equals(currentNamespace)) {
					return classChoice;
				}
			}

			currentNamespace = currentNamespace.getParentNamespace();
		}

		return null;
	}

	@Override
	public void run() throws CancelledException, InvalidInputException, InvalidNameException, DuplicateNameException {
		Iterator<GhidraClass> namespaces = currentProgram.getSymbolTable().getClassNamespaces();
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		List<ClassChoice> classes = new ArrayList<ClassChoice>();

		while (namespaces.hasNext()) {
			classes.add(new ClassChoice(namespaces.next()));
		}

		if (classes.size() == 0) {
			printerr("no classes found to rename!");
			return;
		}

		ClassChoice defaultChoice = currentClass(classes);
		ClassChoice chosenClass = askChoice("Choose Class", "choose the class to rename", classes, defaultChoice);
		String newName = askString("New Class Name", "enter the new name for the class");
		Structure struct = VariableUtilities.findExistingClassStruct(chosenClass.cls, dtm);

		if (!isRunningHeadless()) {
			// if this is an interactive session, request confirmation to avoid surprises
			confirmRename(chosenClass.cls, struct, newName);
		}

		renameClass(chosenClass.cls, struct, newName);
	}
}
