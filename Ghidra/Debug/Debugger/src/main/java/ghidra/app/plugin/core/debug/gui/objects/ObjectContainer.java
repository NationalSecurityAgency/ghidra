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

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;

import org.jdom.Element;

import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;
import ghidra.util.xml.XmlUtilities;

public class ObjectContainer implements Comparable<ObjectContainer> {

	private DebuggerObjectsProvider provider;
	protected TargetObject targetObject;
	private final Map<String, TargetObject> elementMap = new LinkedHashMap<>();
	private final Map<String, Object> attributeMap = new LinkedHashMap<>();
	private Set<ObjectContainer> currentChildren = new TreeSet<>();

	private boolean immutable;
	private boolean visible = true;
	private boolean isSubscribed = false;
	private boolean isLink = false;
	private boolean useSort = true;
	private String treePath;
	public String linkKey;

	public ObjectContainer(TargetObject to, String linkKey) {
		this.linkKey = linkKey;
		this.isLink = linkKey != null;
		if (to != null) {
			targetObject = to;
			if (!isLink) {
				rebuildContainers(targetObject.getCachedElements(),
					targetObject.getCachedAttributes());
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

	public void updateUsing(ObjectContainer container) {
		attributeMap.clear();
		attributeMap.putAll(container.getAttributeMap());
		elementMap.clear();
		elementMap.putAll(container.getElementMap());
		targetObject = container.targetObject;
	}

	public boolean hasElements() {
		return !elementMap.isEmpty();
	}

	public String getName() {
		if (targetObject == null) {
			return "Objects";
		}
		if (isLink) {
			return linkKey;
		}
		boolean noTarget = targetObject == null;
		String name = noTarget ? targetObject.getName() : targetObject.getName();
		String hint = noTarget ? null : targetObject.getTypeHint();
		if (name == null) {
			return hint;
		}
		return name;
	}

	public String getDecoratedName() {
		if (targetObject == null) {
			return "Objects";
		}
		if (isLink) {
			String refname = targetObject.getName();
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
		if (targetObject == null) {
			return "Objects";
		}
		List<String> path = targetObject.getPath();
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
		if (targetObject == null) {
			return "Objects";
		}
		return targetObject == null ? targetObject.getName() : targetObject.getName();
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
		if (targetObject == null) {
			return CompletableFuture.completedFuture(null);
		}
		return targetObject.resync(true, true).thenApplyAsync(__ -> {
			rebuildContainers(targetObject.getCachedElements(), targetObject.getCachedAttributes());
			propagateProvider(provider);
			return this;
		});
	}

	/*
	protected void checkAutoRecord() {
		if (targetObject != null && provider.isAutorecord()) {
			TargetProcess proc = DebugModelConventions.liveProcessOrNull(targetObject);
			if (proc != null) {
				provider.startRecording(proc, false);
			}
		}
	}
	*/

	public void augmentElements(Collection<String> elementsRemoved,
			Map<String, ? extends TargetObject> elementsAdded) {
		Set<ObjectContainer> result = new TreeSet<ObjectContainer>();
		Map<String, Object> newAdds = new HashMap<>();
		for (Entry<String, ? extends TargetObject> entry : elementsAdded.entrySet()) {
			newAdds.put(entry.getKey(), entry.getValue());
		}
		boolean structureChanged = false;
		synchronized (elementMap) {
			for (ObjectContainer child : currentChildren) {
				String key = child.getName();
				if (key.startsWith("[")) {
					key = key.substring(1, key.length() - 1);
				}
				if (elementsRemoved.contains(key) && !elementsAdded.containsKey(key)) {
					elementMap.remove(key);
					structureChanged = true;
					continue;
				}
				if (elementsAdded.containsKey(key)) {
					Object val = elementsAdded.get(key);
					ObjectContainer newChild =
						DebuggerObjectsProvider.buildContainerFromObject(targetObject, key, val,
							true);
					child.updateUsing(newChild);
					newAdds.remove(key);
					provider.signalDataChanged(child);
				}
				result.add(child);
			}
			for (String key : elementsAdded.keySet()) {
				TargetObject val = elementsAdded.get(key);
				ObjectContainer child =
					DebuggerObjectsProvider.buildContainerFromObject(targetObject, key, val, false);
				elementMap.put(key, val);
				result.add(child);
				structureChanged = true;
			}
		}
		currentChildren = result;
		if (structureChanged) {
			provider.signalContentsChanged(this);
		}
		provider.fireObjectUpdated(this);
		//provider.update(this);
	}

	public void augmentAttributes(Collection<String> attributesRemoved,
			Map<String, ?> attributesAdded) {
		Set<ObjectContainer> result = new TreeSet<ObjectContainer>();
		Map<String, Object> newAdds = new HashMap<>();
		for (Entry<String, ?> entry : attributesAdded.entrySet()) {
			newAdds.put(entry.getKey(), entry.getValue());
		}
		boolean structureChanged = false;
		synchronized (attributeMap) {
			for (ObjectContainer child : currentChildren) {
				String key = child.getName();
				if (attributesRemoved.contains(key) && !attributesAdded.containsKey(key)) {
					attributeMap.remove(key);
					structureChanged = true;
					continue;
				}
				if (attributesAdded.containsKey(key)) {
					Object val = attributesAdded.get(key);
					ObjectContainer newChild =
						DebuggerObjectsProvider.buildContainerFromObject(targetObject, key, val,
							true);
					child.updateUsing(newChild);
					newAdds.remove(key);
					provider.signalDataChanged(child);
				}
				result.add(child);
			}
			for (String key : newAdds.keySet()) {
				Object val = newAdds.get(key);
				ObjectContainer child =
					DebuggerObjectsProvider.buildContainerFromObject(targetObject, key, val, true);
				if (child != null) {
					attributeMap.put(key, val);
					result.add(child);
					structureChanged = true;
				}
			}
		}
		currentChildren = result;
		if (structureChanged) {
			provider.signalContentsChanged(this);
		}
		provider.fireObjectUpdated(this);
		//provider.update(this);
	}

	public void rebuildContainers(Map<String, ? extends TargetObject> elements,
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

	public Map<String, TargetObject> getElementMap() {
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
		for (ObjectContainer c : currentChildren) {
			c.propagateProvider(provider);
		}
		provider.fireObjectUpdated(this);
		//checkAutoRecord();
	}

	// This should only be called once when the connection is activated
	public void setTargetObject(TargetObject rootObject) {
		this.targetObject = rootObject;
		rebuildContainers(rootObject.getCachedElements(), rootObject.getCachedAttributes());
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

	/*
	public void toXmlSchema(Element root) {
		Element element = this.toXmlSchema();
		root.addContent(element);
	
		for (ObjectContainer child : getCurrentChildren()) {
			String key = child.getShortName();
			if (attributeMap.containsKey(key)) {
				if (!(child.targetObject instanceof DummyTargetObject)) {
					child.toXmlSchema(root);
				}
			}
		}
		for (ObjectContainer child : getCurrentChildren()) {
			if (elementMap.containsValue(child.targetObject)) {
				child.toXmlSchema(root);
				break;
			}
		}
	}
	
	public Element toXmlSchema() {
		String name = getPrefixedName();
		if (name == null) {
			name = provider.getRoot().getName();
		}
		name = sanitize(name);
		Element result = new Element("schema");
		XmlUtilities.setStringAttr(result, "name", name);
		for (ObjectContainer child : getCurrentChildren()) {
			String key = child.getShortName();
			if (attributeMap.containsKey(key)) {
				Element n = new Element("attribute");
				String typeHint = null;
				if (child.targetObject != null) {
					typeHint = child.targetObject.getTypeHint();
				}
				XmlUtilities.setStringAttr(n, "name", key);
				if (typeHint != null) {
					XmlUtilities.setStringAttr(n, "schema", typeHint);
				}
				if (key.startsWith("_")) {
					XmlUtilities.setStringAttr(n, "hidden", "yes");
				}
				result.addContent(n);
			}
		}
		if (elementMap.isEmpty()) {
			Element n = new Element("element");
			XmlUtilities.setStringAttr(n, "schema", "VOID");
			result.addContent(n);
		}
		else {
			for (ObjectContainer child : getCurrentChildren()) {
				if (elementMap.containsValue(child.targetObject)) {
					Element n = new Element("element");
					String typeHint = null;
					if (child.targetObject != null) {
						typeHint = child.targetObject.getTypeHint();
					}
					XmlUtilities.setStringAttr(n, "name", child.getName());
					if (typeHint != null) {
						Element ifc = new Element("interface");
						try {
							XmlUtilities.setStringAttr(n, "name", sanitize(typeHint));
						}
						catch (Exception e) {
							//do nothing
						}
						result.addContent(ifc);
					}
					result.addContent(n);
					break;
				}
			}
		}
		Element n = new Element("attribute");
		XmlUtilities.setStringAttr(n, "schema", "VOID");
		result.addContent(n);
		return result;
	}
	
	private String sanitize(String name) {
		name = name.replaceAll(" ", "_");
		name = name.replaceAll("/", "_");
		if (name.contains("[")) {
			name = name.replaceAll("\\[", "_");
			name = name.replaceAll("\\]", "");
			name = name.replaceAll("/", "_");
		}
		return name;
	}
	*/

	public boolean isImmutable() {
		return immutable;
	}

	public void setImmutable(boolean immutable) {
		this.immutable = immutable;
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
	}

	public void unsubscribe() {
		isSubscribed = false;
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
	public int compareTo(ObjectContainer that) {
		String thisTreePath = this.toString();
		String thatTreePath = that.toString();
		if (thisTreePath != null && thatTreePath != null) {
			return thisTreePath.compareTo(thatTreePath);
		}
		return this.hashCode() - that.hashCode();
	}

}
