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
package ghidra.app.plugin.core.debug.gui.objects;

import static ghidra.async.AsyncUtils.*;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import org.jdom.Element;

import ghidra.async.AsyncFence;
import ghidra.async.TypeSpec;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.util.PathUtils;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.xml.XmlUtilities;

public class ObjectContainer implements Comparable {

	private DebuggerObjectsProvider provider;
	protected TargetObject targetObject;
	protected TargetObjectRef targetObjectRef;
	private final Map<String, TargetObjectRef> elementMap = new LinkedHashMap<>();
	private final Map<String, Object> attributeMap = new LinkedHashMap<>();
	private Set<ObjectContainer> currentChildren = new TreeSet<>();

	public final ListenerSet<ObjectContainerListener> listeners =
		new ListenerSet<>(ObjectContainerListener.class);

	private boolean immutable;
	private boolean visible = true;
	private boolean isSubscribed = false;
	private boolean isLink = false;
	private boolean useSort = true;
	private String treePath;
	public String linkKey;

	public ObjectContainer(TargetObjectRef ref, String linkKey) {
		this.linkKey = linkKey;
		this.isLink = linkKey != null;
		if (ref != null) {
			this.targetObjectRef = ref;
			if (targetObjectRef instanceof TargetObject) {
				targetObject = (TargetObject) targetObjectRef;
				if (!isLink) {
					rebuildContainers(targetObject.getCachedElements(),
						targetObject.getCachedAttributes());
				}
			}
			else {
				targetObject = null;
				targetObjectRef.fetch().thenAccept(obj -> {
					targetObject = obj;
					if (obj != null && !isLink) {
						rebuildContainers(targetObject.getCachedElements(),
							targetObject.getCachedAttributes());
					}
				});
			}
			visible = visibleByDefault(getName());
		}
	}

	public static boolean visibleByDefault(String key) {
		return key == null || !PathUtils.isHidden(key);
	}

	public static ObjectContainer clone(ObjectContainer container) {
		ObjectContainer nc = new ObjectContainer(container.getTargetObject(), container.linkKey);
		nc.rebuildContainers(container.getElementMap(), container.getAttributeMap());
		nc.propagateProvider(container.getProvider());
		return nc;
	}

	public boolean hasElements() {
		return !elementMap.isEmpty();
	}

	public String getName() {
		if (targetObjectRef == null) {
			return "Objects";
		}
		if (isLink) {
			return linkKey;
		}
		boolean noTarget = targetObject == null;
		String name = noTarget ? targetObjectRef.getName() : targetObject.getName();
		String hint = noTarget ? null : targetObject.getTypeHint();
		if (name == null) {
			return hint;
		}
		return name;
	}

	public String getDecoratedName() {
		if (targetObjectRef == null) {
			return "Objects";
		}
		if (isLink) {
			String refname = targetObjectRef.getName();
			if (linkKey.equals(refname)) {
				return "->" + linkKey;
			}
			return linkKey + ":" + refname;
		}
		String name = targetObject.getName();
		if (targetObject.getCachedAttributes().containsKey(TargetObject.DISPLAY_ATTRIBUTE_NAME)) {
			if (name != null) {
				return targetObject.getDisplay();
			}
		}
		String hint = targetObject.getTypeHint();
		return (name == null) ? hint : name;
	}

	public String getPrefixedName() {
		if (targetObjectRef == null) {
			return "Objects";
		}
		List<String> path = targetObjectRef.getPath();
		int index = path.size() - 1;
		if (index < 0) {
			return targetObject.getName();
		}
		String parent = path.get(index);
		if (parent.contains("(")) {
			while (parent.contains("(")) {
				parent = path.get(--index);
			}
			String initVal = path.get(path.size() - 1);
			return parent + initVal.substring(initVal.indexOf(")") + 1);
		}
		return parent;
	}

	public String getShortName() {
		if (targetObjectRef == null) {
			return "Objects";
		}
		return targetObject == null ? targetObjectRef.getName() : targetObject.getName();
	}

	public ObjectContainer getParent() {
		return provider.getParent(this);
	}

	/* 
	 * For all of what follow, you want to preserve the following pattern:
	 * 		rebuildContainers
	 * 		propagateProvider(p)
	 * 		p.update
	 */

	public CompletableFuture<ObjectContainer> getOffspring() {
		if (targetObjectRef == null) {
			return null;
		}
		AtomicReference<TargetObject> to = new AtomicReference<>();
		AtomicReference<Map<String, ? extends TargetObject>> elements = new AtomicReference<>();
		AtomicReference<Map<String, ?>> attributes = new AtomicReference<>();
		return sequence(TypeSpec.cls(ObjectContainer.class)).then(seq -> {
			targetObjectRef.fetch().handle(seq::next);
		}, to).then(seq -> {
			targetObject = to.get();
			AsyncFence fence = new AsyncFence();
			fence.include(targetObject.fetchElements(true)
					.thenCompose(DebugModelConventions::fetchAll)
					.thenAccept(elements::set));
			fence.include(targetObject.fetchAttributes(true)
					.thenCompose(attrs -> DebugModelConventions.fetchObjAttrs(targetObject, attrs))
					.thenAccept(attributes::set));
			fence.ready().handle(seq::next);
		}).then(seq -> {
			rebuildContainers(elements.get(), attributes.get());
			propagateProvider(provider);
			seq.exit(this);
		}).finish();
	}

	protected void checkAutoRecord() {
		if (targetObject != null && provider.isAutorecord()) {
			TargetProcess<?> proc = DebugModelConventions.liveProcessOrNull(targetObject);
			if (proc != null) {
				provider.startRecording(proc, false).exceptionally(ex -> {
					Msg.error("Could not record and/or open target: " + targetObject, ex);
					return null;
				});
			}
			// Note that the recorder seeds its own listener with its target
		}
	}

	public void augmentElements(Collection<String> elementsRemoved,
			Map<String, ? extends TargetObject> elementsAdded) {
		Set<ObjectContainer> result = new TreeSet<ObjectContainer>();
		synchronized (elementMap) {
			for (ObjectContainer child : currentChildren) {
				String name = child.getName();
				if (elementsRemoved.contains(name) && !elementsAdded.containsKey(name)) {
					elementMap.remove(name);
					continue;
				}
				result.add(child);
			}
			for (String key : elementsAdded.keySet()) {
				TargetObject val = elementsAdded.get(key);
				ObjectContainer child =
					DebuggerObjectsProvider.buildContainerFromObject(targetObject, key, val, true);
				elementMap.put(key, val);
				result.add(child);
			}
		}
		currentChildren = result;
		provider.fireObjectUpdated(this);
		//provider.update(this);
	}

	public void augmentAttributes(Collection<String> attributesRemoved,
			Map<String, ?> attributesAdded) {
		Set<ObjectContainer> result = new TreeSet<ObjectContainer>();
		synchronized (attributeMap) {
			for (ObjectContainer child : currentChildren) {
				String name = child.getName();
				if (attributesRemoved.contains(name) && !attributesAdded.containsKey(name)) {
					attributeMap.remove(name);
					continue;
				}
				result.add(child);
			}
			for (String key : attributesAdded.keySet()) {
				Object val = attributesAdded.get(key);
				ObjectContainer child =
					DebuggerObjectsProvider.buildContainerFromObject(targetObject, key, val, true);
				if (child == null) {
					Msg.error(this, "Null container for " + key);
				}
				else {
					attributeMap.put(key, val);
					result.add(child);
				}
			}
		}
		currentChildren = result;
		provider.fireObjectUpdated(this);
		//provider.update(this);
	}

	public void rebuildContainers(Map<String, ? extends TargetObjectRef> elements,
			Map<String, ?> attributes) {
		synchronized (elementMap) {
			elementMap.clear();
			if (elements != null) {
				elementMap.putAll(elements);
			}
		}
		synchronized (attributeMap) {
			attributeMap.clear();
			if (attributes != null) {
				attributeMap.putAll(attributes);
			}
		}

		Set<ObjectContainer> result = new TreeSet<ObjectContainer>();
		List<ObjectContainer> nodeFromElements =
			DebuggerObjectsProvider.getContainersFromObjects(elementMap, targetObject, false);
		result.addAll(nodeFromElements);

		List<ObjectContainer> nodeFromAttributes =
			DebuggerObjectsProvider.getContainersFromObjects(attributeMap, targetObject, true);
		result.addAll(nodeFromAttributes);

		currentChildren = result;
	}

	public Set<ObjectContainer> getCurrentChildren() {
		return currentChildren;
	}

	public void setCurrentChildren(Set<ObjectContainer> children) {
		currentChildren = children;
	}

	public Map<String, Object> updateMap(Map<String, Object> map, List<String> removed,
			Map<String, ?> added) {
		if (removed != null) {
			for (String key : removed) {
				map.remove(key);
			}
		}
		if (added != null) {
			for (String key : added.keySet()) {
				Object object = added.get(key);
				map.put(key, object);
			}
		}
		return map;
	}

	public Map<String, Object> getAttributeMap() {
		return attributeMap;
	}

	public Map<String, TargetObjectRef> getElementMap() {
		return elementMap;
	}

	public TargetObject getTargetObject() {
		return targetObject;
	}

	public ObjectContainer getSubContainer(TargetObject object) {
		for (ObjectContainer c1 : currentChildren) {
			if (c1.getTargetObject().equals(object)) {
				return c1;
			}
			for (ObjectContainer c2 : c1.getCurrentChildren()) {
				if (c2.getTargetObject().equals(object)) {
					return c2;
				}
			}
		}
		return null;
	}

	public DebuggerObjectsProvider getProvider() {
		return provider;
	}

	public void propagateProvider(DebuggerObjectsProvider newProvider) {
		if (newProvider == null) {
			throw new RuntimeException("Provider reset to null");
		}
		if (!newProvider.equals(provider)) {
			this.provider = newProvider;
			provider.addTargetToMap(this);
		}
		this.addListener(provider);
		//if (targetObject != null && !currentChildren.isEmpty()) {
		//	targetObject.addListener(provider);
		//}
		for (ObjectContainer c : currentChildren) {
			c.propagateProvider(provider);
		}
		provider.fireObjectUpdated(this);
		checkAutoRecord();
	}

	// This should only be called once when the connection is activated
	public void setTargetObject(TargetObject rootObject) {
		this.targetObject = rootObject;
		this.targetObjectRef = rootObject;
		if (provider != null) {
			provider.addTargetToMap(this);
			provider.update(this);
		}
	}

	/**
	 * Converts this object into XML
	 * 
	 * @return new jdom {@link Element}
	 */
	public Element toXml() {
		String name = getPrefixedName();
		name = name.replaceAll(" ", "_");
		if (name.contains("[")) {
			name = name.replaceAll("\\[", "_");
			name = name.replaceAll("\\]", "");
			name = name.replaceAll("/", "_");
		}
		Element result = new Element(name);
		for (ObjectContainer child : getCurrentChildren()) {
			String key = child.getShortName();
			if (elementMap.containsKey(key)) {
				result.addContent(child.toXml());
			}
			else {
				result.addContent(child.toXml());
			}
		}
		if (targetObject != null) {
			if (!targetObject.getTypeHint().equals("")) {
				XmlUtilities.setStringAttr(result, "Type", targetObject.getTypeHint());
			}
			if (!targetObject.getDisplay().equals("")) {
				XmlUtilities.setStringAttr(result, "Value", targetObject.getDisplay());
			}
		}

		return result;
	}

	public boolean isImmutable() {
		return immutable;
	}

	public void setImmutable(boolean immutable) {
		this.immutable = immutable;
	}

	public void addListener(ObjectContainerListener listener) {
		listeners.add(listener);
	}

	public void removeListener(ObjectContainerListener listener) {
		listeners.remove(listener);
	}

	public boolean isVisible() {
		return visible;
	}

	public void setVisible(boolean visible) {
		this.visible = visible;
	}

	@Override
	public String toString() {
		return targetObject == null ? super.toString() : targetObject.toString();
	}

	public boolean isSubscribed() {
		return isSubscribed;
	}

	public void subscribe() {
		isSubscribed = true;
		if (targetObject != null && provider != null) {
			targetObject.addListener(provider);
			provider.addListener(targetObject);
		}
	}

	public void unsubscribe() {
		isSubscribed = false;
		targetObject.removeListener(provider);
		if (provider.isAutorecord()) {
			//provider.stopRecording(targetObject);
		}
	}

	public boolean isModified() {
		Object object = targetObject == null ? null
				: targetObject.getCachedAttributes().get(TargetObject.MODIFIED_ATTRIBUTE_NAME);
		return object != null && ((Boolean) object);
	}

	public boolean isLink() {
		return isLink;
	}

	public String getOrder() {
		Integer order = (Integer) attributeMap.get(TargetObject.ORDER_ATTRIBUTE_NAME);
		return order == null ? getName() : Integer.toString(order);
	}

	public boolean useSort() {
		return useSort;
	}

	public void setUseSort(boolean useSort) {
		this.useSort = useSort;
	}

	// NB: WOuld be nice if we could use the real treePath but our use case
	//  precede the node's actual placement in the tree

	public String getTreePath() {
		return treePath;
	}

	public void setTreePath(String treePath) {
		this.treePath = treePath;
	}

	@Override
	public int compareTo(Object obj) {
		ObjectContainer that = (ObjectContainer) obj;
		String thisTreePath = this.toString();
		String thatTreePath = that.toString();
		if (thisTreePath != null && thatTreePath != null) {
			return thisTreePath.compareTo(thatTreePath);
		}
		return this.hashCode() - that.hashCode();
	}
}
