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

import com.sun.jdi.*;

import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "ObjectReference",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(name = "UID", type = Long.class, required = true, fixed = true),
		@TargetAttributeType(type = Object.class)
	})
public class JdiModelTargetObjectReference extends JdiModelTargetValue {

	private static final long MAX_REFERRERS = 100;

	protected final ObjectReference objref;

	protected JdiModelTargetThread owner;
	private JdiModelTargetReferenceType referenceType;

	public JdiModelTargetObjectReference(JdiModelTargetObject object, ObjectReference objref,
			boolean isElement) {
		this(object, Long.toString(objref.uniqueID()), objref, isElement);
	}

	public JdiModelTargetObjectReference(JdiModelTargetObject object, String id,
			ObjectReference objref, boolean isElement) {
		super(object, id, objref, isElement);
		this.objref = objref;

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			"UID", objref.uniqueID() //
		), "Initialized");

	}

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {

		this.referenceType = (JdiModelTargetReferenceType) getInstance(objref.referenceType());

		changeAttributes(List.of(), List.of(), Map.of( //
			referenceType.getName(), referenceType //
		), "Initialized");

		try {
			ThreadReference owningThread = objref.owningThread();
			if (owningThread != null) {
				owner = (JdiModelTargetThread) getInstance(owningThread);
				changeAttributes(List.of(), List.of(), Map.of( //
					"Owner", owner //
				), "Initialized");
			}
		}
		catch (IncompatibleThreadStateException e) {
			// Ignore
		}
		try {
			List<ThreadReference> waitingThreads = objref.waitingThreads();
			if (waitingThreads != null) {
				JdiModelTargetThreadContainer targetWaitingThreads =
					new JdiModelTargetThreadContainer(this, "Waiting Threads", waitingThreads);
				changeAttributes(List.of(), List.of( //
					targetWaitingThreads //
				), Map.of(), "Initialized");
			}
		}
		catch (IncompatibleThreadStateException e) {
			// Ignore
		}
		try {
			JdiModelTargetObjectReferenceContainer referringObjects =
				new JdiModelTargetObjectReferenceContainer(this, "Referring Objects",
					objref.referringObjects(MAX_REFERRERS));
			changeAttributes(List.of(), List.of( //
				referringObjects //
			), Map.of(), "Initialized");
		}
		catch (UnsupportedOperationException e) {
			// Ignore
		}
		catch (IllegalArgumentException e) {
			// Ignore
		}
		try {
			int entryCount = objref.entryCount();
			changeAttributes(List.of(), List.of(), Map.of( //
				"Entry Count", entryCount //
			), "Initialized");
		}
		catch (IncompatibleThreadStateException e) {
			// Ignore
		}
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> init() {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public String getDisplay() {
		return objref == null ? super.getDisplay() : objref.toString();
	}

}
