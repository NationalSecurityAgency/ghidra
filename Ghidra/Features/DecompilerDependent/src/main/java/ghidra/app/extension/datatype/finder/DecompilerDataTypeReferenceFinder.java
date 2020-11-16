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
package ghidra.app.extension.datatype.finder;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Predicate;

import org.apache.commons.collections4.IterableUtils;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReference;
import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.app.services.DataTypeReference;
import ghidra.app.services.DataTypeReferenceFinder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.datastruct.SetAccumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Implementation of {@link DataTypeReferenceFinder} that uses the Decompiler's output 
 * to find data type and composite field usage.
 */
public class DecompilerDataTypeReferenceFinder implements DataTypeReferenceFinder {

	public DecompilerDataTypeReferenceFinder() {
		// for Extension Point loading
	}

	@Override
	public void findReferences(Program program, DataType dataType,
			Consumer<DataTypeReference> callback, TaskMonitor monitor) throws CancelledException {

		DecompilerDataTypeFinderQCallback qCallback =
			new DecompilerDataTypeFinderQCallback(program, dataType, callback);

		Set<Function> functions = filterFunctions(program, dataType, monitor);

		try {
			ParallelDecompiler.decompileFunctions(qCallback, functions, monitor);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt(); // reset the flag
			Msg.trace(this, "Interrupted while decompiling functions");
		}
		catch (Exception e) {
			Msg.error(this, "Encountered an exception decompiling functions", e);
		}
		finally {
			qCallback.dispose();
		}
	}

	@Override
	public void findReferences(Program program, Composite dataType, String fieldName,
			Consumer<DataTypeReference> callback, TaskMonitor monitor) throws CancelledException {

		DecompilerDataTypeFinderQCallback qCallback =
			new DecompilerDataTypeFinderQCallback(program, dataType, fieldName, callback);

		Set<Function> functions = filterFunctions(program, dataType, monitor);

		try {
			ParallelDecompiler.decompileFunctions(qCallback, functions, monitor);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt(); // reset the flag
			Msg.debug(this, "Interrupted while decompiling functions");
		}
		catch (Exception e) {
			Msg.error(this, "Encountered an exception decompiling functions", e);
		}
		finally {
			qCallback.dispose();
		}
	}

	private Set<Function> filterFunctions(Program program, DataType dt, TaskMonitor monitor)
			throws CancelledException {

		Set<DataType> types = new HashSet<>();
		buildTypeLineage(dt, types);

		Set<Function> results = new HashSet<>();
		accumulateFunctionCallsToDefinedData(program, types, results, monitor);

		Listing listing = program.getListing();
		FunctionIterator it = listing.getFunctions(true);
		for (Function f : it) {
			monitor.checkCanceled();
			if (results.contains(f)) {
				continue;
			}

			if (usesAnyType(f, types)) {
				results.add(f);
			}
		}

		// note: do this here, so that don't cause the code above to skip processing these functions
		Set<Function> callers = new HashSet<>();
		for (Function f : results) {
			monitor.checkCanceled();
			Set<Function> callingFunctions = f.getCallingFunctions(monitor);
			callers.addAll(callingFunctions);
		}

		results.addAll(callers);

		return results;
	}

	private void accumulateFunctionCallsToDefinedData(Program program, Set<DataType> potentialTypes,
			Set<Function> results, TaskMonitor monitor) throws CancelledException {

		Listing listing = program.getListing();
		AtomicInteger counter = new AtomicInteger();
		SetAccumulator<LocationReference> accumulator = new SetAccumulator<>();
		Predicate<Data> dataMatcher = data -> {
			counter.incrementAndGet();
			DataType dataType = data.getDataType();
			boolean matches = potentialTypes.contains(dataType);
			return matches;
		};

		ReferenceUtils.findDataTypeMatchesInDefinedData(accumulator, program, dataMatcher, null,
			monitor);

		for (LocationReference ref : accumulator) {
			Address address = ref.getLocationOfUse();
			Function f = listing.getFunctionContaining(address);
			if (f != null) {
				results.add(f);
			}
		}
	}

	/* Gets all types that are in the lineage of the given type */
	private void buildTypeLineage(DataType sourceType, Set<DataType> types) {

		if (types.contains(sourceType)) {
			return; // already processed
		}

		// First, get this type, which could be a pointer, typedef or array...
		gatherRelatedTypes(sourceType, types);

		// Then, check the base type
		DataType baseType = DataTypeUtils.getBaseDataType(sourceType);
		if (types.contains(baseType)) {
			return;
		}

		// We have a different type, should we search for it?
		if (baseType instanceof BuiltInDataType) {
			// When given a wrapper type (e.g., typedef) , ignore 
			// built-ins (e.g., int, byte, etc), as 
			// they will be of little value due to their volume in the program and the
			// user *probably* did not intend to search for them.  (Below we do not do 
			// this check, which allows the user to search directly for a 
			// built-in type, if they wish.)			
			return;
		}

		gatherRelatedTypes(baseType, types);
	}

	private void gatherRelatedTypes(DataType dt, Set<DataType> types) {

		types.add(dt);

		DataType[] parents = dt.getParents();
		for (DataType parent : parents) {
			buildTypeLineage(parent, types);
		}
	}

	private boolean usesAnyType(Function f, Set<DataType> types) {

		DataType returnType = f.getReturnType();
		if (types.contains(returnType)) {
			return true;
		}

		Variable[] variables = f.getAllVariables();
		for (Variable v : variables) {
			DataType paramType = v.getDataType();
			if (types.contains(paramType) ||
				types.contains(ReferenceUtils.getBaseDataType(paramType))) {
				return true;
			}
		}

		return false;
	}

//==================================================================================================
// Classes
//==================================================================================================

	private static class DecompilerDataTypeFinderQCallback
			extends DecompilerCallback<List<DataTypeReference>> {

		private Consumer<DataTypeReference> callback;
		private DataType dataType;
		private String fieldName;

		/* Search for Data Type access only--no field usage */
		DecompilerDataTypeFinderQCallback(Program program, DataType dataType,
				Consumer<DataTypeReference> callback) {
			this(program, dataType, null, callback);
		}

		/* Search for composite field access */
		DecompilerDataTypeFinderQCallback(Program program, DataType dataType, String fieldName,
				Consumer<DataTypeReference> callback) {

			super(program, new DecompilerConfigurer());

			this.dataType = dataType;
			this.fieldName = fieldName;
			this.callback = callback;
		}

		@Override
		public List<DataTypeReference> process(DecompileResults results, TaskMonitor monitor)
				throws Exception {

			Function function = results.getFunction();
			if (function.isThunk()) {
				return null;
			}

			DecompilerDataTypeFinder finder =
				new DecompilerDataTypeFinder(results, function, dataType, fieldName);
			List<DataTypeReference> refs = finder.findUsage();

			refs.forEach(r -> callback.accept(r));

			return refs;
		}

	}

	private static class DecompilerConfigurer implements DecompileConfigurer {

		@Override
		public void configure(DecompInterface decompiler) {
			decompiler.toggleCCode(true);
			decompiler.toggleSyntaxTree(true);
			decompiler.setSimplificationStyle("decompile");

			DecompileOptions xmlOptions = new DecompileOptions();
			xmlOptions.setDefaultTimeout(60);
			decompiler.setOptions(xmlOptions);
		}
	}

	/**
	 * Class to do the work of searching through the Decompiler's results for the desired 
	 * data type access.
	 */
	private static class DecompilerDataTypeFinder {

		private DecompileResults decompilation;
		private Function function;
		private DataType dataType;
		private String fieldName;

		DecompilerDataTypeFinder(DecompileResults results, Function function, DataType dataType,
				String fieldName) {
			this.decompilation = results;
			this.function = function;
			this.dataType = dataType;
			this.fieldName = fieldName;
		}

		List<DataTypeReference> findUsage() {

			List<DataTypeReference> refs = new ArrayList<>();
			searchDecompilation(refs);
			return refs;
		}

		private void searchDecompilation(List<DataTypeReference> results) {

			ClangTokenGroup tokens = decompilation.getCCodeMarkup();

// TODO delete this when the ticket settles down			
//			dumpTokens(tokens, 0);
//			dumpTokenNames(tokens, 0);

			if (tokens == null) {
				// assume a bad function or the user cancelled the decompilation
				Msg.trace(this, "Unable to get decompilation tokens for " + function.getName());
				return;
			}

			List<DecompilerReference> variables = findVariableReferences(tokens);
			variables.forEach(v -> matchUsage(v, results));
		}

		/** Finds any search input match in the given reference */
		private void matchUsage(DecompilerReference reference, List<DataTypeReference> results) {
			reference.accumulateMatches(dataType, fieldName, results);
		}

		private List<DecompilerReference> findVariableReferences(ClangTokenGroup tokens) {

			List<ClangLine> lines = DecompilerUtils.toLines(tokens);
			List<DecompilerReference> result = new ArrayList<>();
			for (ClangLine line : lines) {
				findVariablesInLine(line, result);
			}

			return result;
		}

		/**
		 * Uses the given line to find variables (also parameters and return types) and any 
		 * accesses to them in that line.   A given variable may be used directly or, as in 
		 * the case with Composite types, may have one of its fields accessed.  Each result
		 * found by this method will be at least a variable access and may also itself have
		 * field accesses.
		 * 
		 * <p>Sometimes a line is structured such that there are anonymous variable accesses.  This
		 * is the case where a Composite is being accessed, but the Composite itself is
		 * not a variable in the current function.  See {@link AnonymousVariableAccessDR} for 
		 * more details.
		 * 
		 * @param line the current line being processed from the Decompiler
		 * @param results the accumulator into which matches will be placed
		 */
		private void findVariablesInLine(ClangLine line, List<DecompilerReference> results) {

			List<ClangToken> allTokens = line.getAllTokens();
			Iterable<ClangToken> filteredTokens = IterableUtils.filteredIterable(allTokens,
				token -> {
					// Only include desirable tokens (this is really just for easier debugging).
					// Update this filter if the loop below ever needs other types of tokens.
					return (token instanceof ClangTypeToken) ||
						(token instanceof ClangVariableToken) || (token instanceof ClangFieldToken);
				});

			// gather any casts until we can use them (the type they modify will follow)
			List<DecompilerVariable> castsSoFar = new ArrayList<>();

			VariableDR declaration = null;
			VariableAccessDR access = null;
			for (ClangToken token : filteredTokens) {

				if (token instanceof ClangTypeToken) {

					if (token.Parent() instanceof ClangReturnType) {
						results.add(new ReturnTypeDR(line, (ClangTypeToken) token));
					}
					else if (token.isVariableRef()) {
						// Note: variable refs will get their variable in an upcoming token
						if (isFunctionPrototype(token.Parent())) {
							declaration = new ParameterDR(line, (ClangTypeToken) token);
						}
						else {
							declaration = new LocalVariableDR(line, (ClangTypeToken) token);
						}

						results.add(declaration);
					}
					else {
						// Assumption: this is a cast inside of a ClangStatement
						// Assumption: there can be multiple casts concatenated
						castsSoFar.add(new DecompilerVariableType(token));
					}
				}
				else if (token instanceof ClangVariableToken) {

					//
					// Observations: 
					// 1) 'access' will be null if we are on a C statement that 
					//    is a declaration (parameter or variable).  In this case, 
					//    'declaration' will be an instance of VariableDR.
					// 2) 'access' will be null the first time a variable is used in
					//    a statement.
					// 3) if 'access' is non-null, but already has a variable assigned, 
					//    then this means the current ClangVariableToken represents a new 
					//    variable access/usage.
					//
					if (declaration != null) {
						declaration.setVariable((ClangVariableToken) token);
						declaration = null;
					}
					else {
						if (access == null || access.getVariable() != null) {
							access = new VariableAccessDR(line);
							results.add(access);
						}

						List<DecompilerVariable> casts = new ArrayList<>(castsSoFar);
						access.setVariable((ClangVariableToken) token, casts);
						castsSoFar.clear();
					}
				}
				else if (token instanceof ClangFieldToken) {

					List<DecompilerVariable> casts = new ArrayList<>(castsSoFar);

					if (access == null) {
						// Uh-oh.  I've only seen this when line-wrapping is happening.  In that
						// case, try to get the last variable that we've seen and assume that 
						// is the variable to which this field belongs.
						access = getLastAccess(results);
						if (access == null) {
							Msg.debug(this,
								"Found a field access without a preceding " +
									"variable for\n\tline: " + line + "\n\tfield: " + token +
									"\n\tfunction: " + function);

							continue;
						}
					}

					ClangFieldToken field = (ClangFieldToken) token;
					if (typesDoNotMatch(access, field)) {
						// this can happen when a field is used anonymously, such as directly 
						// after a nested array index operation
						results.add(new AnonymousVariableAccessDR(line, field));
						continue;
					}

					access.addField(field, casts);
					castsSoFar.clear();
				}
			}
		}

		private boolean typesDoNotMatch(VariableAccessDR access, ClangFieldToken field) {

			DecompilerVariable variable = access.getVariable();
			if (variable == null) {
				return false; // should not happen
			}

			// Note: the field's type is that of the parent structure, not the field.  We want the
			//       field's type, so we must retrieve that.
			DataType fieldDt = DecompilerReference.getFieldDataType(field);

			// unusual code: getDataType() on the variable may return the type of the field being
			//               accessed.  Contrastingly, getDataType() on the field may return the
			//               type of the parent structure.
			DataType variableDt = variable.getDataType();
			return !DecompilerReference.isEqual(variableDt, fieldDt);
		}

		private VariableAccessDR getLastAccess(List<DecompilerReference> variables) {
			// for now, assume that the last access will be the last item we added
			if (variables.isEmpty()) {
				return null; // shouldn't happen
			}

			DecompilerReference last = variables.get(variables.size() - 1);
			if (last instanceof VariableAccessDR) {
				return (VariableAccessDR) last;
			}
			return null; // shouldn't happen
		}

		private boolean isFunctionPrototype(ClangNode node) {

			while (!(node instanceof ClangFuncProto) && node != null) {
				node = node.Parent();
			}

			return node instanceof ClangFuncProto;
		}

		private void dumpTokens(ClangTokenGroup tokens, int depth) {
			int n = tokens.numChildren();
			for (int i = 0; i < n; i++) {
				ClangNode child = tokens.Child(i);
				doDumpTokens(child, depth);
			}
		}

		private void doDumpTokens(ClangNode node, int depth) {

			if (node instanceof ClangTokenGroup) {
				dumpTokens((ClangTokenGroup) node, depth + 1);
				return;
			}

			if (node instanceof ClangBreak) {
				System.err.print("\n");
				int tabs = depth * 4;
				String asString = StringUtilities.pad("", ' ', tabs);
				System.err.print(asString);
			}
			else {
				String text = node.toString();
				System.err.print(" '" + text + "' ");
			}

			ClangToken token = (ClangToken) node;
			int n = node.numChildren();
			for (int i = 0; i < n; i++) {
				ClangNode child = token.Child(i);

				doDumpTokens(child, depth + 1);
			}
		}

		private void dumpTokenNames(ClangTokenGroup tokens, int depth) {
			System.err.print(" '" + tokens.getClass().getSimpleName());

			int n = tokens.numChildren();
			for (int i = 0; i < n; i++) {
				ClangNode child = tokens.Child(i);
				doDumpTokenNames(child, depth);
			}
		}

		private void doDumpTokenNames(ClangNode node, int depth) {

			if (node instanceof ClangTokenGroup) {
				dumpTokenNames((ClangTokenGroup) node, depth + 1);
				return;
			}

			if (node instanceof ClangBreak) {
				System.err.print("\n");
				int tabs = depth * 4;
				String asString = StringUtilities.pad("", ' ', tabs);
				System.err.print(asString);
			}
			else {
				System.err.print(
					" '" + node.getClass().getSimpleName() + "' ['" + node.toString() + "'] ");
			}

			ClangToken token = (ClangToken) node;
			int n = node.numChildren();
			for (int i = 0; i < n; i++) {
				ClangNode child = token.Child(i);

				doDumpTokenNames(child, depth + 1);
			}
		}
	}
}
