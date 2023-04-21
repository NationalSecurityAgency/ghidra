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
import ghidra.app.plugin.core.searchtext.Searcher.TextSearchResult;
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
	protected Address advance(List<TextSearchResult> currentMatches) {
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
			List<TextSearchResult> currentMatches) {
		findCommentMatches(function, currentMatches);
		findSignatureMatches(function, currentMatches);
		findVariableMatches(function, currentMatches);
	}

	private void findVariableMatches(Function function, List<TextSearchResult> currentMatches) {
		Parameter[] parameters = function.getParameters();
		for (Parameter parameter : parameters) {
			checkTypeString(parameter, currentMatches);
			checkName(parameter, currentMatches);
			checkStorage(parameter, currentMatches);
			checkComment(parameter, currentMatches);
		}
		Variable[] localVariables = function.getLocalVariables();
		for (Variable localVariable : localVariables) {
			checkTypeString(localVariable, currentMatches);
			checkName(localVariable, currentMatches);
			checkStorage(localVariable, currentMatches);
			checkComment(localVariable, currentMatches);
		}

	}

	private void checkTypeString(Variable variable, List<TextSearchResult> currentMatches) {
		DataType dt;
		if (variable instanceof Parameter) {
			dt = ((Parameter) variable).getFormalDataType();
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
			currentMatches.add(new TextSearchResult(
				new VariableTypeFieldLocation(program, variable, index), index));
		}
	}

	private void checkName(Variable variable, List<TextSearchResult> currentMatches) {
		String searchString = variable.getName();
		Matcher matcher = pattern.matcher(searchString);
		while (matcher.find()) {
			int index = matcher.start();
			currentMatches.add(new TextSearchResult(
				new VariableNameFieldLocation(program, variable, index), index));
		}
	}

	private void checkStorage(Variable var, List<TextSearchResult> currentMatches) {
		String searchString = var.getVariableStorage().toString();
		Matcher matcher = pattern.matcher(searchString);
		while (matcher.find()) {
			int index = matcher.start();
			currentMatches.add(
				new TextSearchResult(new VariableLocFieldLocation(program, var, index), index));
		}
	}

	private void checkComment(Variable variable, List<TextSearchResult> currentMatches) {
		String searchString = variable.getComment();
		if (searchString == null) {
			return;
		}
		Matcher matcher = pattern.matcher(searchString);
		while (matcher.find()) {
			int index = matcher.start();
			currentMatches.add(
				new TextSearchResult(new VariableCommentFieldLocation(program, variable, index),
					index));
		}
	}

	private void findSignatureMatches(Function function, List<TextSearchResult> currentMatches) {
		String signature = function.getPrototypeString(false, false);
		Matcher matcher = pattern.matcher(signature);
		Address address = function.getEntryPoint();
		int callingConventionOffset = FunctionUtils.getCallingConventionSignatureOffset(function);
		while (matcher.find()) {
			int index = matcher.start();
			currentMatches.add(new TextSearchResult(
				new FunctionSignatureFieldLocation(program, address, null, index +
					callingConventionOffset, signature),
				index));
		}
	}

	private void findCommentMatches(Function function, List<TextSearchResult> currentMatches) {
		String functionComment = function.getRepeatableComment();

		if (functionComment == null) {
			return;
		}
		String cleanedUpComment = functionComment.replace('\n', ' ');
		Matcher matcher = pattern.matcher(cleanedUpComment);
		Address address = function.getEntryPoint();
		while (matcher.find()) {
			int index = matcher.start();
			currentMatches.add(new TextSearchResult(
				getFunctionCommentLocation(functionComment, index, address), index));
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
