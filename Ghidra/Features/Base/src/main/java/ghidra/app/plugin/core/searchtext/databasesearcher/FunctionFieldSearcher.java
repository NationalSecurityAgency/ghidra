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
package ghidra.app.plugin.core.searchtext.databasesearcher;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.plugin.core.navigation.FunctionUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.StringUtilities;

public class FunctionFieldSearcher extends ProgramDatabaseFieldSearcher {
	private FunctionIterator iterator;
	private Program program;

	public FunctionFieldSearcher(Program program, ProgramLocation startLoc, AddressSetView set,
			boolean forward, Pattern pattern) {

		super(pattern, forward, startLoc, set);
		this.program = program;

		if (set != null) {
			iterator = program.getListing().getFunctions(set, forward);
		}
		else {
			iterator = program.getListing().getFunctions(startLoc.getAddress(), forward);
		}
	}

	@Override
	protected Address advance(List<ProgramLocation> currentMatches) {
		if (iterator.hasNext()) {
			Function function = iterator.next();
			Address nextAddress = null;
			// TODO: don't search EXTERNAL functions for now since they will 
			// cause issues for ProgramLocation
			if (function != null && !function.isExternal()) {
				nextAddress = function.getEntryPoint();
				findMatchesForCurrentFunction(function, currentMatches);
			}
			return nextAddress;
		}
		return null;
	}

	private void findMatchesForCurrentFunction(Function function,
			List<ProgramLocation> currentMatches) {
		findCommentMatches(function, currentMatches);
		findSignatureMatches(function, currentMatches);
		findVariableMatches(function, currentMatches);
	}

	private void findVariableMatches(Function function, List<ProgramLocation> currentMatches) {
		Parameter[] parameters = function.getParameters();
		for (int i = 0; i < parameters.length; i++) {
			checkTypeString(parameters[i], currentMatches);
			checkName(parameters[i], currentMatches);
			checkStorage(parameters[i], currentMatches);
			checkComment(parameters[i], currentMatches);
		}
		Variable[] localVariables = function.getLocalVariables();
		for (int i = 0; i < localVariables.length; i++) {
			checkTypeString(localVariables[i], currentMatches);
			checkName(localVariables[i], currentMatches);
			checkStorage(localVariables[i], currentMatches);
			checkComment(localVariables[i], currentMatches);
		}

	}

	private void checkTypeString(Variable variable, List<ProgramLocation> currentMatches) {
		DataType dt;
		if (variable instanceof Parameter) {
			dt = ((Parameter)variable).getFormalDataType();
		}
		else {
			dt = variable.getDataType();
		}

		if (dt == null) {
			return;
		}
		String searchString = dt.getDisplayName();
		Matcher matcher = pattern.matcher(searchString);
		while (matcher.find()) {
			int index = matcher.start();
			currentMatches.add(new VariableTypeFieldLocation(program, variable, index));
		}
	}

	private void checkName(Variable variable, List<ProgramLocation> currentMatches) {
		String searchString = variable.getName();
		Matcher matcher = pattern.matcher(searchString);
		while (matcher.find()) {
			int index = matcher.start();
			currentMatches.add(new VariableNameFieldLocation(program, variable, index));
		}
	}

	private void checkStorage(Variable var, List<ProgramLocation> currentMatches) {
		String searchString = var.getVariableStorage().toString();
		Matcher matcher = pattern.matcher(searchString);
		while (matcher.find()) {
			int index = matcher.start();
			currentMatches.add(new VariableLocFieldLocation(program, var, index));
		}
	}

	private void checkComment(Variable variable, List<ProgramLocation> currentMatches) {
		String searchString = variable.getComment();
		if (searchString == null) {
			return;
		}
		Matcher matcher = pattern.matcher(searchString);
		while (matcher.find()) {
			int index = matcher.start();
			currentMatches.add(new VariableCommentFieldLocation(program, variable, index));
		}
	}

	private void findSignatureMatches(Function function, List<ProgramLocation> currentMatches) {
		String signature = function.getPrototypeString(false, false);
		Matcher matcher = pattern.matcher(signature);
		Address address = function.getEntryPoint();
		int callingConventionOffset = FunctionUtils.getCallingConventionSignatureOffset(function);
		while (matcher.find()) {
			int index = matcher.start();
			currentMatches.add(new FunctionSignatureFieldLocation(program, address, null, index +
				callingConventionOffset, signature));
		}
	}

	private void findCommentMatches(Function function, List<ProgramLocation> currentMatches) {
		String functionComment = function.getRepeatableComment();

		if (functionComment == null) {
			return;
		}
		String cleanedUpComment = functionComment.replace('\n', ' ');
		Matcher matcher = pattern.matcher(cleanedUpComment);
		Address address = function.getEntryPoint();
		while (matcher.find()) {
			int index = matcher.start();
			currentMatches.add(getFunctionCommentLocation(functionComment, index, address));
		}
	}

	private ProgramLocation getFunctionCommentLocation(String comment, int index, Address address) {
		String[] comments = StringUtilities.toLines(comment);
		int rowIndex = findRowIndex(comments, index);
		int charOffset = findCharOffset(index, rowIndex, comments);
		return new FunctionRepeatableCommentFieldLocation(program, address, comments,
			rowIndex, charOffset);

	}

	private int findCharOffset(int index, int rowIndex, String[] opStrings) {
		int totalBeforeOpIndex = 0;
		for (int i = 0; i < rowIndex; i++) {
			totalBeforeOpIndex += opStrings[i].length();
		}
		return index - totalBeforeOpIndex;
	}

	private int findRowIndex(String[] commentStrings, int index) {
		int totalSoFar = 0;
		for (int i = 0; i < commentStrings.length; i++) {
			if (index < totalSoFar + commentStrings[i].length()) {
				return i;
			}
		}
		return commentStrings.length - 1;
	}

}
