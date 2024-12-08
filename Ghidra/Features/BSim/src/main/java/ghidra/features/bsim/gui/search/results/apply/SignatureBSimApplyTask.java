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
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.util.FunctionUtility;

/**
 * Task for applying names, namespaces, and signatures from a match function to the queried function
 */
public class SignatureBSimApplyTask extends AbstractBSimApplyTask {

	private boolean applyEmptyStructures;

	public SignatureBSimApplyTask(Program program, List<BSimMatchResult> results,
			boolean applyEmptyStructures, ServiceProvider serviceProvider) {
		super(program, "Function Signature", results, serviceProvider);
		this.applyEmptyStructures = applyEmptyStructures;
	}

	@Override
	protected boolean hasSameApplyData(List<Function> functions) {
		FunctionSignature firstSignature = functions.get(0).getSignature(false);
		for (int i = 1; i < functions.size(); i++) {
			FunctionSignature signature = functions.get(i).getSignature(false);
			if (!firstSignature.isEquivalentSignature(signature)) {
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
		try {
			FunctionUtility.applySignature(target, source, applyEmptyStructures,
				DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
			return new BSimApplyResult(target, source, BSimResultStatus.SIGNATURE_APPLIED, "");
		}
		catch (Exception e) {
			return new BSimApplyResult(target, source, BSimResultStatus.ERROR,
				"Apply signature failed (" + e.getMessage() + ")");
		}
	}
}
