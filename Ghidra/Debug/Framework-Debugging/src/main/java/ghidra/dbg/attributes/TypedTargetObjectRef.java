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
package ghidra.dbg.attributes;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TypedTargetObject;

/**
 * A reference having a known or expected type
 * 
 * @param <T> the type
 * @deprecated I don't think this adds any real value.
 */
@Deprecated(forRemoval = true)
public interface TypedTargetObjectRef<T extends TargetObject> extends TargetObjectRef {
	public class CastingTargetObjectRef<T extends TypedTargetObject<T>>
			implements TypedTargetObjectRef<T> {

		private final Class<T> cls;
		private final TargetObjectRef ref;

		public CastingTargetObjectRef(Class<T> cls, TargetObjectRef ref) {
			this.cls = cls;
			this.ref = ref;
		}

		@Override
		public boolean equals(Object obj) {
			return ref.equals(obj);
		}

		@Override
		public int hashCode() {
			return ref.hashCode();
		}

		@Override
		public DebuggerObjectModel getModel() {
			return ref.getModel();
		}

		@Override
		public List<String> getPath() {
			return ref.getPath();
		}

		@Override
		public CompletableFuture<? extends T> fetch() {
			return ref.fetch().thenApply(o -> o.as(cls));
		}
	}

	public static <T extends TypedTargetObject<T>> TypedTargetObjectRef<T> casting(Class<T> cls,
			TargetObjectRef ref) {
		if (ref instanceof CastingTargetObjectRef) {
			CastingTargetObjectRef<?> casting = (CastingTargetObjectRef<?>) ref;
			return new CastingTargetObjectRef<>(cls, casting.ref);
		}
		return new CastingTargetObjectRef<>(cls, ref);
	}

	@Override
	CompletableFuture<? extends T> fetch();
}
