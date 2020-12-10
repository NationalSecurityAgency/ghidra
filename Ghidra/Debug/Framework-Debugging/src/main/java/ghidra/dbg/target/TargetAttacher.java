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
import ghidra.dbg.attributes.TypedTargetObjectRef;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.dbg.target.TargetSteppable.TargetStepKindSet;
import ghidra.dbg.target.TargetSteppable.TargetStepKindSet.ImmutableTargetStepKindSet;
import ghidra.dbg.util.CollectionUtils;
import ghidra.dbg.util.CollectionUtils.AbstractEmptySet;

@DebuggerTargetObjectIface("Attacher")
public interface TargetAttacher<T extends TargetAttacher<T>> extends TypedTargetObject<T> {
	enum Private {
		;
		private abstract class Cls implements TargetAttacher<Cls> {
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	Class<Private.Cls> tclass = (Class) TargetAttacher.class;

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

		public static TargetStepKindSet of(TargetStepKind... kinds) {
			return new ImmutableTargetStepKindSet(kinds);
		}

		public static TargetStepKindSet copyOf(Set<TargetStepKind> set) {
			return new ImmutableTargetStepKindSet(set);
		}
	}

	enum TargetAttachKind {
		/**
		 * Use an "attachable" object
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
	 * Different debuggers may provide similar, but slightly different vocabularies of stepping.
	 * This method queries the connected debugger for its supported step kinds.
	 * 
	 * @return the set of supported multi-step operations
	 */
	public default TargetAttachKindSet getSupportedAttachKinds() {
		return getTypedAttributeNowByName(SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME,
			TargetAttachKindSet.class, TargetAttachKindSet.of());
	}

	/**
	 * Attach to the given {@link TargetAttachable} or reference
	 * 
	 * This is mostly applicable to user-space contexts, in which case, this usually means to attach
	 * to a process.
	 * 
	 * @param attachable the object or reference to attach to
	 * @return a future which completes when the command is confirmed
	 */
	public CompletableFuture<Void> attach(TypedTargetObjectRef<? extends TargetAttachable<?>> ref);

	/**
	 * Attach to the given id
	 * 
	 * This is mostly applicable to user-space contexts, in which case, this usually means to attach
	 * to a process using its pid.
	 * 
	 * @param id the identifier for and object to attach to
	 * @return a future which completes when the command is confirmed
	 */
	public CompletableFuture<Void> attach(long id);

}
