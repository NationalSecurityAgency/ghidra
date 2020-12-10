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

import java.io.InvalidObjectException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;

public class SctlTargetObjectsContainer
		extends DefaultTargetObject<SctlTargetObject, SctlTargetSession> {

	protected final Map<String, SctlTargetObject> objectsByJoined = new LinkedHashMap<>();
	protected final SctlClient client;

	public SctlTargetObjectsContainer(SctlTargetSession session) {
		super(session.client, session, "Objects", "ObjectsContainer");
		this.client = session.client;
	}

	/**
	 * Create an object
	 * 
	 * This is preferred to calling
	 * {@link SctlTargetObject#SctlTargetObject(SctlClient, String, String, String, String, String)}
	 * directly, since this will add the object to the client container.
	 * 
	 * Note this does not check if another object already exists at the given path
	 * 
	 * @param key the id for the object
	 * @param sub the path used to identify the object terminating in the key
	 * @param kind the generic container type
	 * @params value the value of the object if it exists
	 * @params type the type of the object if it exists
	 * @return the new object proxy
	 * @throws InvalidObjectException
	 */
	protected SctlTargetObject create(String key, List<String> sub, String kind,
			String value, String type) throws InvalidObjectException {
		assert key.equals(PathUtils.getKey(sub));
		if (sub == null || sub.isEmpty()) {
			throw new IllegalArgumentException("sub cannot be null or empty");
		}
		List<String> fullPath = PathUtils.extend(getPath(), sub);
		List<String> parentPath = PathUtils.parent(fullPath);
		String joinedParent = StringUtils.join(parentPath, SctlTargetObject.PATH_SEPARATOR_STRING);
		TargetObject newParent =
			parentPath.equals(getPath()) ? this : objectsByJoined.get(joinedParent);
		if (newParent == null) {
			throw new IllegalArgumentException(
				"parent of newPath=" + newParent + ", which does not exist");
		}

		SctlTargetObject object = new SctlTargetObject(client, this, sub, kind, value, type);
		if (object.getTypeHint().equals("OBJECT_ERROR")) {
			throw new InvalidObjectException(object.getDisplay());
		}
		objectsByJoined.put(StringUtils.join(sub, SctlTargetObject.PATH_SEPARATOR_STRING), object);
		return object;
	}

	protected List<TargetObject> findObjectByKey(String key) {
		return objectsByJoined.values()
				.stream()
				.filter(o -> key.equals(o.getName()))
				.collect(Collectors.toList());
	}

	@Override
	public CompletableFuture<? extends TargetObject> fetchSuccessor(List<String> sub) {
		if (sub.isEmpty()) {
			return CompletableFuture.completedFuture(this);
		}
		String joinedSub = StringUtils.join(sub, SctlTargetObject.PATH_SEPARATOR_STRING);
		return CompletableFuture.completedFuture(getObject(joinedSub));
	}

	protected SctlTargetObject getObject(String sub) {
		return objectsByJoined.get(sub);
	}

	protected SctlTargetObject require(String sub) {
		SctlTargetObject object = objectsByJoined.get(sub);
		if (object == null) {
			throw new IllegalArgumentException("No such object: path=" + path);
		}
		return object;
	}

	protected void notifyAttributes(String sub, Map<String, TargetObject> map) {
		SctlTargetObject obj = require(sub);
		obj.notifyAttributes(map);
	}

	protected void notifyElements(String sub, Map<String, TargetObject> map) {
		SctlTargetObject obj = require(sub);
		obj.notifyElements(map);
	}
}
