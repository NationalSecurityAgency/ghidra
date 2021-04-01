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

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import com.sun.jdi.ThreadGroupReference;

import ghidra.dbg.jdi.manager.JdiEventsListenerAdapter;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "ThreadGroupContainer",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = JdiModelTargetThreadGroupContainer.class)
	},
	canonicalContainer = true)
public class JdiModelTargetThreadGroupContainer extends JdiModelTargetObjectImpl
		implements JdiEventsListenerAdapter {

	protected static String keyGroup(ThreadGroupReference group) {
		return PathUtils.makeKey(group.name());
	}

	protected final ThreadGroupReference baseGroup;

	protected final Map<String, JdiModelTargetThreadGroupContainer> threadGroupsById =
		new WeakValueHashMap<>();

	public JdiModelTargetThreadGroupContainer(JdiModelTargetVM parent) {
		super(parent, "Thread Groups");
		this.baseGroup = null;
	}

	public JdiModelTargetThreadGroupContainer(JdiModelTargetObject parent,
			ThreadGroupReference group, boolean isElement) {
		super(parent, isElement ? keyGroup(group) : group.name());
		this.baseGroup = group;
	}

	@Override
	protected CompletableFuture<Void> requestElements(boolean refresh) {
		List<ThreadGroupReference> groups;
		if (parent instanceof JdiModelTargetVM) {
			JdiModelTargetVM vm = (JdiModelTargetVM) parent;
			groups = vm.vm.topLevelThreadGroups();
		}
		else {
			groups = baseGroup.threadGroups();
			if (!baseGroup.threads().isEmpty()) {
				JdiModelTargetThreadContainer c =
					new JdiModelTargetThreadContainer(this, "Threads", baseGroup.threads());
				this.changeAttributes(List.of(), List.of( //
					c //
				), Map.of(), "Refreshed");
			}
		}
		updateUsingThreadGroups(groups);
		return CompletableFuture.completedFuture(null);
	}

	protected void updateUsingThreadGroups(List<ThreadGroupReference> refs) {
		List<JdiModelTargetThreadGroupContainer> threadGroups;
		synchronized (this) {
			threadGroups =
				refs.stream().map(this::getTargetThreadGroup).collect(Collectors.toList());
		}
		setElements(threadGroups, Map.of(), "Refreshed");
	}

	public synchronized JdiModelTargetThreadGroupContainer getTargetThreadGroup(
			ThreadGroupReference group) {
		return threadGroupsById.computeIfAbsent(group.name(),
			i -> new JdiModelTargetThreadGroupContainer(this, group, true));
	}

}
