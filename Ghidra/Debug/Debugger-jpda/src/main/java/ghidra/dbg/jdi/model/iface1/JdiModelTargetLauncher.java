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
package ghidra.dbg.jdi.model.iface1;

import java.util.Map;
import java.util.stream.Collectors;

import com.sun.jdi.connect.Connector.*;

import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.TargetLauncher;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.ParameterDescription;

/**
 * An interface which indicates this object is capable of launching targets.
 * 
 * The targets this launcher creates ought to appear in its successors.
 * 
 * @param <T> type for this
 */
public interface JdiModelTargetLauncher extends JdiModelTargetObject, TargetLauncher {

	static ParameterDescription<Boolean> createBooleanParameter(BooleanArgument arg) {
		return ParameterDescription.create(Boolean.class, arg.name(), arg.mustSpecify(),
			arg.booleanValue(), arg.label(), arg.description());
	}

	static ParameterDescription<Integer> createIntegerParameter(IntegerArgument arg) {
		return ParameterDescription.create(Integer.class, arg.name(), arg.mustSpecify(),
			arg.intValue(), arg.label(), arg.description());
	}

	static ParameterDescription<String> createStringParameter(StringArgument arg) {
		return createGenericParameter(arg);
	}

	static ParameterDescription<String> createSelectedParameter(SelectedArgument arg) {
		return ParameterDescription.choices(String.class, arg.name(), arg.choices(),
			arg.label(), arg.description());
	}

	static ParameterDescription<String> createGenericParameter(Argument arg) {
		return ParameterDescription.create(String.class, arg.name(), arg.mustSpecify(),
			arg.value(), arg.label(), arg.description());
	}

	static ParameterDescription<?> createParameter(Argument arg) {
		if (arg instanceof BooleanArgument) {
			return createBooleanParameter((BooleanArgument) arg);
		}
		if (arg instanceof IntegerArgument) {
			return createIntegerParameter((IntegerArgument) arg);
		}
		if (arg instanceof StringArgument) {
			return createStringParameter((StringArgument) arg);
		}
		if (arg instanceof SelectedArgument) {
			return createSelectedParameter((SelectedArgument) arg);
		}
		return createGenericParameter(arg);
	}

	static Map<String, ParameterDescription<?>> getParameters(
			Map<String, Argument> defaultArguments) {
		return defaultArguments.entrySet()
				.stream()
				.collect(Collectors.toMap(Map.Entry::getKey, e -> createParameter(e.getValue())));
	}

	static Map<String, Argument> getArguments(Map<String, Argument> defaultArguments,
			Map<String, ParameterDescription<?>> parameters, Map<String, ?> arguments) {
		Map<String, ?> validated = TargetMethod.validateArguments(parameters, arguments, false);
		for (Argument arg : defaultArguments.values()) {
			Object val = parameters.get(arg.name()).get(validated);
			// Eh, we could probably avoid the round-trip string conversion. Is it needed? No.
			arg.setValue(val == null ? null : val.toString());
		}
		return defaultArguments;
	}
}
