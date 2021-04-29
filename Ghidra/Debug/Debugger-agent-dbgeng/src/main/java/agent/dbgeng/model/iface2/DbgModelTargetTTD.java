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
package agent.dbgeng.model.iface2;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

public interface DbgModelTargetTTD extends DbgModelTargetObject {

	@Override
	public default CompletableFuture<Void> init(Map<String, Object> map) {
		return requestNativeAttributes().thenCompose(attrs -> {
			if (attrs == null) {
				return CompletableFuture.completedFuture(null);
			}
			map.putAll(attrs);
			DbgModelTargetObject attributes = (DbgModelTargetObject) attrs.get("Position");
			if (attributes == null) {
				return CompletableFuture.completedFuture(null);
			}
			return attributes.requestAugmentedAttributes().thenCompose(ax -> {
				Map<String, ?> subattrs = attributes.getCachedAttributes();
				if (subattrs == null) {
					return CompletableFuture.completedFuture(null);
				}
				DbgModelTargetObject seq = (DbgModelTargetObject) subattrs.get("Sequence");
				return seq.requestAugmentedAttributes().thenCompose(bx -> {
					Object sqval = seq.getCachedAttribute(VALUE_ATTRIBUTE_NAME);
					String sqstr = sqval.toString();
					DbgModelTargetObject steps = (DbgModelTargetObject) subattrs.get("Steps");
					return steps.requestAugmentedAttributes().thenAccept(cx -> {
						Object stval = steps.getCachedAttribute(VALUE_ATTRIBUTE_NAME);
						String oldval = (String) getCachedAttribute(DISPLAY_ATTRIBUTE_NAME);
						String ststr = stval.toString();
						String display = String.format("TTD %s:%s", sqstr, ststr);
						map.put(DISPLAY_ATTRIBUTE_NAME, display);
						setModified(map, !display.equals(oldval));
					});
				});
			});
		});
	}
}
