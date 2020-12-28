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

import org.apache.commons.lang3.reflect.TypeLiteral;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.util.ValueUtils;
import ghidra.lifecycle.Internal;

/**
 * A target object which may not be accessible
 * 
 * <p>
 * Depending on the state of the debugger, it may not be able to process commands for certain target
 * objects. Objects which may not be accessible should support this interface. Note, that the
 * granularity of accessibility is the entire object, including its children (excluding links). If,
 * e.g., an object can process memory commands but not control commands, it should be separated into
 * two objects.
 */
@DebuggerTargetObjectIface("Access")
public interface TargetAccessConditioned<T extends TargetAccessConditioned<T>>
		extends TypedTargetObject<T> {
	enum Private {
		;
		private abstract class Cls implements TargetAccessConditioned<Cls> {
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	Class<Private.Cls> tclass = (Class) TargetAccessConditioned.class;

	TypeLiteral<TargetAccessConditioned<?>> type = new TypeLiteral<>() {};
	String ACCESSIBLE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "accessible";

	/**
	 * TODO: I'm seriously considering removing this
	 */
	public enum TargetAccessibility {
		ACCESSIBLE, INACCESSIBLE;

		public static TargetAccessibility fromBool(boolean accessible) {
			return accessible ? TargetAccessibility.ACCESSIBLE : TargetAccessibility.INACCESSIBLE;
		}
	}

	@Internal
	default TargetAccessibility fromObj(Object obj) {
		if (obj == null) {
			return TargetAccessibility.ACCESSIBLE;
		}
		return TargetAccessibility
				.fromBool(
					ValueUtils.expectBoolean(obj, this, ACCESSIBLE_ATTRIBUTE_NAME, true, true));
	}

	@TargetAttributeType(name = ACCESSIBLE_ATTRIBUTE_NAME, required = true, hidden = true)
	public default Boolean isAccessible() {
		return getTypedAttributeNowByName(ACCESSIBLE_ATTRIBUTE_NAME, Boolean.class, true);
	}

	public default TargetAccessibility getAccessibility() {
		return fromObj(getCachedAttributes().get(ACCESSIBLE_ATTRIBUTE_NAME));
	}

	public interface TargetAccessibilityListener extends TargetObjectListener {
		default void accessibilityChanged(TargetAccessConditioned<?> object,
				TargetAccessibility accessibility) {
		}
	}
}
