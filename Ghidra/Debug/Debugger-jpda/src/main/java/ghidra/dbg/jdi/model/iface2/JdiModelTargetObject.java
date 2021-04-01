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
package ghidra.dbg.jdi.model.iface2;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import com.sun.jdi.*;

import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.agent.InvalidatableTargetObjectIf;
import ghidra.dbg.jdi.manager.JdiManager;
import ghidra.dbg.jdi.model.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.EnumerableTargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.util.datastruct.ListenerSet;

public interface JdiModelTargetObject extends TargetObject, InvalidatableTargetObjectIf {

	String THREAD_ATTRIBUTE_NAME = "Thread";
	String THIS_OBJECT_ATTRIBUTE_NAME = "This";
	String LOCATION_ATTRIBUTE_NAME = "Location";

	public JdiModelImpl getModelImpl();

	public default JdiManager getManager() {
		return getModelImpl().getManager();
	}

	public default CompletableFuture<Void> init(Map<String, Object> map) {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<? extends Map<String, ? extends TargetObject>> fetchElements();

	@Override
	public CompletableFuture<? extends Map<String, ?>> fetchAttributes();

	public Delta<?, ?> changeAttributes(List<String> remove, Map<String, ?> add, String reason);

	public ListenerSet<DebuggerModelListener> getListeners();

	public default JdiModelTargetObject getInstance(Mirror object) {
		JdiModelTargetObject targetObject = getTargetObject(object);
		if (targetObject == null) {
			if (object instanceof ThreadReference) {
				ThreadReference thread = (ThreadReference) object;
				targetObject = new JdiModelTargetThread(this, thread, acceptsElement("Thread"));
			}
			else if (object instanceof ObjectReference) {
				ObjectReference ref = (ObjectReference) object;
				targetObject =
					new JdiModelTargetObjectReference(this, ref, acceptsElement("ObjectReference"));
			}
			else if (object instanceof ReferenceType) {
				ReferenceType reftype = (ReferenceType) object;
				targetObject =
					new JdiModelTargetReferenceType(this, reftype, acceptsElement("ReferenceType"));
			}
			else if (object instanceof Field) {
				Field field = (Field) object;
				targetObject = new JdiModelTargetField(this, field, acceptsElement("Field"));
			}
			else if (object instanceof Method) {
				Method method = (Method) object;
				targetObject = new JdiModelTargetMethod(this, method, acceptsElement("Method"));
			}
			else if (object instanceof Type) {
				Type type = (Type) object;
				targetObject = new JdiModelTargetType(this, type, acceptsElement("Type"));
			}
			else {
				throw new RuntimeException();
			}
		}
		return targetObject;
	}

	public default boolean acceptsElement(String schemaName) {
		TargetObjectSchema schema = this.getSchema();
		if (schema.equals(EnumerableTargetObjectSchema.ANY)) {
			return true;
		}
		SchemaName s = schema.getElementSchema(schemaName);
		return s.toString().equals(schemaName);
	}

	public JdiModelTargetObject getTargetObject(Object object);

	public Object getObject();

}
