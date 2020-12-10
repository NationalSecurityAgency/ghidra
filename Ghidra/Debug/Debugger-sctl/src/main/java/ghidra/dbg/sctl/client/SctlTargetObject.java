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
package ghidra.dbg.sctl.client;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.StringUtils;

import ghidra.async.AsyncLazyValue;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.sctl.protocol.common.AbstractSctlObjectEntry;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.dbg.util.PathUtils;
import ghidra.dbg.util.PathUtils.TargetObjectKeyComparator;
import ghidra.util.datastruct.ListenerSet;

/**
 * A target thread on the SCTL server
 */
public class SctlTargetObject implements TargetObject {
	public static final String PATH_SEPARATOR_STRING = "|";
	public static final String PATH_SEPARATOR_REGEX = "\\|";

	private final SctlClient client;
	private final String joinedPath;
	private final List<String> path;
	private final int hash;
	boolean valid = true;

	final AsyncLazyValue<Map<String, TargetObject>> lazyAttributes =
		new AsyncLazyValue<>(this::doGetAttributes);
	final AsyncLazyValue<Map<String, TargetObject>> lazyElements =
		new AsyncLazyValue<>(this::doGetChildren);
	private String kind;
	private String value;
	private String type;
	// NOTE: 'key' is last element of the path. The method getName() retrieves it.

	// TODO: Create one of these per object proxy, and ensure users act accordingly
	// For now, aliasing to client.listenersObject
	protected final ListenerSet<TargetObjectListener> listeners;

	public SctlTargetObject(SctlClient client, SctlTargetObjectsContainer objects,
			List<String> path, String kind, String value, String type) {
		this.client = client;
		this.joinedPath = StringUtils.join(path, PATH_SEPARATOR_STRING);
		this.path = PathUtils.extend(objects.getPath(), path);
		this.hash = computeHashCode();
		this.kind = kind;
		this.value = value;
		this.type = type;

		this.listeners = client.listenersObject;
	}

	public SctlTargetObject(SctlClient client, AbstractSctlObjectEntry entry) {
		this.client = client;
		this.joinedPath = entry.getPath().str;
		this.path = List.of(joinedPath.split(PATH_SEPARATOR_REGEX));
		this.hash = computeHashCode();
		this.kind = entry.getKind().str;
		this.value = entry.getValue().str;
		this.type = entry.getType().str;

		this.listeners = client.listenersObject;
	}

	@Override
	public boolean equals(Object obj) {
		return doEquals(obj);
	}

	@Override
	public int hashCode() {
		return hash;
	}

	protected void checkValid() {
		if (!valid) {
			throw new IllegalStateException(
				"This thread handle is no longer valid, i.e., the thread has been destroyed.");
		}
	}

	protected CompletableFuture<Map<String, TargetObject>> doGetAttributes() {
		return lazyAttributes.request();
	}

	protected CompletableFuture<Map<String, TargetObject>> doGetChildren() {
		return lazyElements.request();
	}

	@Override
	public SctlClient getModel() {
		return client;
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
	public String getDisplay() {
		if (value != null && !value.equals("")) {
			if (type != null && !type.equals("")) {
				return value + ":" + type;
			}
			return value;
		}
		return "";
		//return getName() + "   " + kind + "   " + value + "   " + type;
	}

	@Override
	public String getTypeHint() {
		return kind;
	}

	@Override
	public boolean isValid() {
		return valid;
	}

	@Override
	public CompletableFuture<? extends Map<String, ? extends TargetObject>> fetchElements() {
		return getModel().getElements(path);
	}

	@Override
	public CompletableFuture<? extends Map<String, ?>> fetchAttributes() {
		return getModel().getAttributes(path);
	}

	@Override
	public void addListener(TargetObjectListener l) {
		listeners.add(l);
	}

	@Override
	public void removeListener(TargetObjectListener l) {
		listeners.remove(l);
	}

	public String getJoinedPath() {
		return joinedPath;
	}

	@Override
	public synchronized Map<String, ? extends TargetObjectRef> getCachedElements() {
		if (lazyElements.isDone()) {
			return lazyElements.request().getNow(null);
		}
		return Map.of();
	}

	@Override
	public synchronized Map<String, ?> getCachedAttributes() {
		if (lazyAttributes.isDone()) {
			return lazyAttributes.request().getNow(null);
		}
		return Map.of();
	}

	protected void notifyAttributes(Map<String, TargetObject> map) {
		Delta<TargetObject, TargetObject> delta;
		synchronized (this) {
			CompletableFuture<Map<String, TargetObject>> future = lazyAttributes.provide();
			if (!future.isDone()) {
				future.complete(new TreeMap<>(TargetObjectKeyComparator.ATTRIBUTE));
			}
			Map<String, TargetObject> attrs = future.getNow(null);
			delta = Delta.computeAndSet(attrs, map, Delta.EQUAL);
		}
		listeners.fire.attributesChanged(this, delta.getKeysRemoved(), delta.added);
	}

	protected void notifyElements(Map<String, TargetObject> map) {
		Delta<TargetObject, TargetObject> delta;
		synchronized (this) {
			CompletableFuture<Map<String, TargetObject>> future = lazyElements.provide();
			if (!future.isDone()) {
				future.complete(new TreeMap<>(TargetObjectKeyComparator.ELEMENT));
			}
			Map<String, TargetObject> elems = future.getNow(null);
			delta = Delta.computeAndSet(elems, map, Delta.SAME);
		}
		listeners.fire.elementsChanged(this, delta.getKeysRemoved(), delta.added);
	}
}
