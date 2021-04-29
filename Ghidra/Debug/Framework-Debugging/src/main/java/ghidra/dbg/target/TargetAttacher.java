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
package ghidra.dbg.target;

import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.util.CollectionUtils;
import ghidra.dbg.util.CollectionUtils.AbstractEmptySet;

/**
 * An object which is capable of attaching to a {@link TargetAttachable}
 */
@DebuggerTargetObjectIface("Attacher")
public interface TargetAttacher extends TargetObject {

	public interface TargetAttachKindSet extends Set<TargetAttachKind> {

		public static class EmptyTargetAttachKindSet extends AbstractEmptySet<TargetAttachKind>
				implements TargetAttachKindSet {
			// Nothing
		}

		public static class ImmutableTargetAttachKindSet extends
				CollectionUtils.AbstractNSet<TargetAttachKind> implements TargetAttachKindSet {

			public ImmutableTargetAttachKindSet(TargetAttachKind... kinds) {
				super(kinds);
			}

			public ImmutableTargetAttachKindSet(Set<TargetAttachKind> set) {
				super(set);
			}
		}

		TargetAttachKindSet EMPTY = new EmptyTargetAttachKindSet();

		public static TargetAttachKindSet of() {
			return EMPTY;
		}

		public static TargetAttachKindSet of(TargetAttachKind... kinds) {
			return new ImmutableTargetAttachKindSet(kinds);
		}

		public static TargetAttachKindSet copyOf(Set<TargetAttachKind> set) {
			return new ImmutableTargetAttachKindSet(set);
		}
	}

	enum TargetAttachKind {
		/**
		 * Use a {@link TargetAttachable} object
		 */
		BY_OBJECT_REF,
		/**
		 * Use the id of some object
		 */
		BY_ID,
	}

	String SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "supported_attach_kinds";

	/**
	 * Get the kinds of multi-stepping implemented by the debugger
	 * 
	 * <p>
	 * Different debuggers provide varying methods of attaching. This attribute describes which are
	 * supported. NOTE: This should be replaced by generic method invocation.
	 * 
	 * @return the set of supported attach operations
	 */
	@TargetAttributeType(
		name = SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME,
		required = true,
		hidden = true)
	public default TargetAttachKindSet getSupportedAttachKinds() {
		return getTypedAttributeNowByName(SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME,
			TargetAttachKindSet.class, TargetAttachKindSet.of());
	}

	/**
	 * Attach to the given {@link TargetAttachable}
	 * 
	 * <p>
	 * This is mostly applicable to user-space contexts, in which case, this usually means to attach
	 * to a process.
	 * 
	 * @param attachable the object or reference to attach to
	 * @return a future which completes when the command is confirmed
	 */
	public CompletableFuture<Void> attach(TargetAttachable attachable);

	/**
	 * Attach to the given id
	 * 
	 * <p>
	 * This is mostly applicable to user-space contexts, in which case, this usually means to attach
	 * to a process using its OS-assigned process id.
	 * 
	 * @param pid the identifier for and object to attach to
	 * @return a future which completes when the command is confirmed
	 */
	public CompletableFuture<Void> attach(long pid);
}
