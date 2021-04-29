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
package ghidra.app.plugin.core.debug.gui.objects.components;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.StringUtils;

import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;

public class DummyTargetObject implements TargetObject {
	private static final String PATH_SEPARATOR_STRING = ".";

	private final DebuggerObjectModel model;
	private final String joinedPath;
	final List<String> path;
	final int hash;

	private final Map<String, Object> attributes = new LinkedHashMap<>();
	private final Map<String, TargetObject> elements = new LinkedHashMap<>();

	private TargetObject parent;

	private final String kind;
	private final Object value;
	private final String type;
	private final String key;

	public DummyTargetObject(DebuggerObjectModel model, String root, List<String> path) {
		this(model, path, "", "", "");
	}

	public DummyTargetObject(DebuggerObjectModel model, List<String> path, String kind,
			Object value, String type) {
		this.model = model;
		this.joinedPath = StringUtils.join(path, PATH_SEPARATOR_STRING);
		this.path = path;
		this.kind = kind;
		this.value = value;
		this.type = type;
		this.key = path.size() > 0 ? path.get(path.size() - 1) : "";
		this.hash = computeHashCode();
	}

	public DummyTargetObject(String key, List<String> path, String kind, Object value, String type,
			List<TargetObject> objects) {
		this.model = null;
		this.joinedPath = StringUtils.join(path, PATH_SEPARATOR_STRING);
		this.path = path;
		this.kind = kind;
		this.value = value;
		this.type = type;
		this.key = path.size() > 0 ? path.get(path.size() - 1) : "";
		this.hash = computeHashCode();
		if (objects != null) {
			for (TargetObject obj : objects) {
				addObject(obj);
			}
		}
	}

	public DummyTargetObject(TargetObject parent, List<String> path, String kind, Object value,
			String type) {
		this.parent = parent;
		this.model = parent.getModel();
		this.joinedPath = StringUtils.join(path, PATH_SEPARATOR_STRING);
		this.path = path;
		this.kind = kind;
		this.value = value;
		this.type = type;
		this.key = path.size() > 0 ? path.get(path.size() - 1) : "";
		this.hash = computeHashCode();
		if (!(parent instanceof DummyTargetObject)) {
			fetchAttributes();
		}
	}

	@Override
	public boolean equals(Object obj) {
		return doEquals(obj);
	}

	@Override
	public int hashCode() {
		return hash;
	}

	@Override
	public TargetObject getParent() {
		return parent;
	}

	public void addObject(TargetObject obj) {
		String name = obj.getName();
		if (name.contains("[")) {
			elements.put(name, obj);
		}
		else {
			attributes.put(name, obj);
		}
	}

	public void addAttribute(String name, Object val) {
		attributes.put(name, val);
	}

	public void setParent(TargetObject parent) {
		this.parent = parent;
	}

	@Override
	public DebuggerObjectModel getModel() {
		return model;
	}

	@Override
	public String getName() {
		if (path == null) {
			return "";
		}
		String ret = path.get(path.size() - 1);
		if (ret.endsWith("]")) {
			ret = ret.substring(ret.indexOf("["));
		}
		return ret;
	}

	@Override
	public Object getProtocolID() {
		return path;
	}

	@Override
	public List<String> getPath() {
		return path;
	}

	@Override
	public String getTypeHint() {
		return kind;
	}

	@Override
	public CompletableFuture<Void> resync(boolean attributes, boolean elements) {
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<? extends Map<String, ? extends TargetObject>> fetchElements() {
		// Why not completedFuture(elements)?
		return CompletableFuture.supplyAsync(() -> elements);
	}

	@Override
	public Map<String, ? extends TargetObject> getCachedElements() {
		return elements;
	}

	@Override
	public Map<String, ? extends TargetObject> getCallbackElements() {
		return elements;
	}

	@Override
	public CompletableFuture<? extends Map<String, ?>> fetchAttributes() {
		if (!key.equals(TargetObject.DISPLAY_ATTRIBUTE_NAME)) {
			if (value != null) {
				String display = getName() + " : " + value;
				addAttribute(TargetObject.DISPLAY_ATTRIBUTE_NAME, display);
			}
			if (kind != null && !kind.equals("")) {
				addAttribute(TargetObject.KIND_ATTRIBUTE_NAME, kind);
			}
			else {
				addAttribute(TargetObject.KIND_ATTRIBUTE_NAME, "OBJECT_INTRINSIC");
			}
			if (value != null) {
				addAttribute(TargetObject.VALUE_ATTRIBUTE_NAME, value);
			}
			if (type != null) {
				addAttribute(TargetObject.TYPE_ATTRIBUTE_NAME, type);
			}
		}
		// Why not completedFuture(attributes)?
		return CompletableFuture.supplyAsync(() -> attributes);
	}

	@Override
	public Map<String, ?> getCachedAttributes() {
		return attributes;
	}

	@Override
	public Map<String, ?> getCallbackAttributes() {
		return attributes;
	}

	@Override
	public void addListener(DebuggerModelListener l) {
	}

	@Override
	public void removeListener(DebuggerModelListener l) {
	}

	public String getJoinedPath() {
		return joinedPath;
	}

	@Override
	public boolean isValid() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public String toString() {
		return getName();
	}
}
