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
package ghidra.features.bsim.gui.search.results.apply;

import java.util.List;

import ghidra.features.bsim.gui.search.results.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.util.FunctionUtility;

/**
 * Task for applying names and namespaces from a match function to the queried function
 */
public class NameAndNamespaceBSimApplyTask extends AbstractBSimApplyTask {

	public NameAndNamespaceBSimApplyTask(Program program, List<BSimMatchResult> results,
		ServiceProvider serviceProvider) {
		super(program, "Function Name", results, serviceProvider);
	}

	@Override
	protected boolean hasSameApplyData(List<Function> functions) {
		String name = functions.get(0).getName(true);
		for (int i = 1; i < functions.size(); i++) {
			if (!functions.get(i).getName(true).equals(name)) {
				return false;
			}
		}
		return true;
	}

	@Override
	protected BSimApplyResult apply(Function target, Function source) {
		String defaultFunctionName = SymbolUtilities.getDefaultFunctionName(source.getEntryPoint());
		if (defaultFunctionName.equals(source.getName())) {
			return new BSimApplyResult(target, source, BSimResultStatus.ERROR,
				"Can't apply default function names");
		}
		String targetFullName = target.getName(true);
		String sourceFullName = source.getName(true);

		if (targetFullName.equals(sourceFullName)) {
			return new BSimApplyResult(target, source, BSimResultStatus.IGNORED,
				"Functions already have the same name");
		}

		try {
			FunctionUtility.applyNameAndNamespace(target, source);
		}
		catch (Exception e) {
			return new BSimApplyResult(target, source, BSimResultStatus.ERROR,
				"Rename failed (" + e.getMessage() + ")");
		}

		return new BSimApplyResult(target, source, BSimResultStatus.NAME_APPLIED, "");
	}

}
