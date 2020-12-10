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
package ghidra.dbg.agent;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.error.DebuggerModelTypeException;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;

public interface SpiDebuggerObjectModel extends DebuggerObjectModel {

	@Override
	default boolean isAlive() {
		return true;
	}

	@Override
	default CompletableFuture<Void> ping(String content) {
		return AsyncUtils.NIL;
	}

	@Override
	default TargetObjectRef createRef(List<String> path) {
		return new DefaultTargetObjectRef(this, path);
	}

	public default CompletableFuture<Object> fetchFreshChild(TargetObject obj, String key) {
		if (PathUtils.isIndex(key)) {
			return obj.fetchElements(true).thenApply(elements -> {
				return elements.get(PathUtils.parseIndex(key));
			});
		}
		return obj.fetchAttributes(true).thenApply(attributes -> {
			return attributes.get(key);
		});
	}

	public default CompletableFuture<Object> fetchSuccessorValue(TargetObject obj,
			List<String> path, boolean refresh, boolean followLinks) {
		if (path.isEmpty()) {
			return CompletableFuture.completedFuture(obj);
		}
		String key = path.get(0);
		CompletableFuture<?> futureChild;
		if (refresh) {
			futureChild = fetchFreshChild(obj, key);
		}
		else {
			futureChild = obj.fetchChild(key);
		}
		return futureChild.thenCompose(c -> {
			if (c == null) {
				return AsyncUtils.nil();
			}
			if (!(c instanceof TargetObjectRef)) {
				if (path.size() == 1) {
					return CompletableFuture.completedFuture(c);
				}
				else {
					List<String> p = PathUtils.extend(obj.getPath(), key);
					throw DebuggerModelTypeException.typeRequired(c, p, TargetObjectRef.class);
				}
			}
			TargetObjectRef childRef = (TargetObjectRef) c;
			if (PathUtils.isLink(obj.getPath(), key, childRef.getPath()) && !followLinks) {
				if (path.size() == 1) {
					return CompletableFuture.completedFuture(c);
				}
				else {
					List<String> p = PathUtils.extend(obj.getPath(), key);
					throw DebuggerModelTypeException.linkForbidden(childRef, p);
				}
			}
			return childRef.fetch().thenCompose(childObj -> {
				List<String> remains = path.subList(1, path.size());
				return fetchSuccessorValue(childObj, remains, refresh, followLinks);
			});
		});
	}

	@Override
	public default CompletableFuture<?> fetchModelValue(List<String> path, boolean refresh) {
		return fetchModelRoot().thenCompose(root -> {
			return fetchSuccessorValue(root, path, refresh, true);
		});
	}

	@Override
	public default CompletableFuture<?> fetchModelValue(List<String> path) {
		return fetchModelValue(path, false);
	}

	@Override
	public default CompletableFuture<? extends Map<String, ? extends TargetObjectRef>> fetchObjectElements(
			List<String> path, boolean refresh) {
		return fetchModelObject(path).thenCompose(obj -> {
			if (obj == null) {
				return AsyncUtils.nil();
			}
			return obj.fetchElements(refresh);
		});
	}

	@Override
	default CompletableFuture<? extends Map<String, ?>> fetchObjectAttributes(List<String> path,
			boolean refresh) {
		return fetchModelObject(path).thenCompose(obj -> {
			if (obj == null) {
				return AsyncUtils.nil();
			}
			return obj.fetchAttributes(refresh);
		});
	}

	@Override
	default void invalidateAllLocalCaches() {
		// Do nothing
	}
}
