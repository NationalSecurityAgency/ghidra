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
package ghidra.dbg.jdi.model;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import com.sun.jdi.LocalVariable;

import ghidra.async.AsyncFence;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "LocalVariableContainer",
	elements = {
		@TargetElementType(type = JdiModelTargetLocalVariable.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetLocalVariableContainer extends JdiModelTargetObjectImpl {

	private List<LocalVariable> vars;

	// TODO: Is it possible to load the same object twice?
	protected final Map<String, JdiModelTargetLocalVariable> variablesByName = new HashMap<>();

	public JdiModelTargetLocalVariableContainer(JdiModelTargetObject parent, String name,
			List<LocalVariable> vars) {
		super(parent, name);
		this.vars = vars;
	}

	protected CompletableFuture<Void> updateUsingVariables(Map<String, LocalVariable> byName) {
		List<JdiModelTargetLocalVariable> locations;
		synchronized (this) {
			locations =
				byName.values().stream().map(this::getTargetVariable).collect(Collectors.toList());
		}
		AsyncFence fence = new AsyncFence();
		for (JdiModelTargetLocalVariable loc : locations) {
			fence.include(loc.init());
		}
		return fence.ready().thenAccept(__ -> {
			changeElements(List.of(), locations, Map.of(), "Refreshed");
		});
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		Map<String, LocalVariable> map = new HashMap<>();
		try {
			for (LocalVariable var : vars) {
				map.put(var.name(), var);
			}
			variablesByName.keySet().retainAll(map.keySet());
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return updateUsingVariables(map);
	}

	protected synchronized JdiModelTargetLocalVariable getTargetVariable(LocalVariable var) {
		return variablesByName.computeIfAbsent(var.name(),
			n -> new JdiModelTargetLocalVariable(this, var, true));
	}

	public synchronized JdiModelTargetLocalVariable getTargetVariableIfPresent(String name) {
		return variablesByName.get(name);
	}
}
