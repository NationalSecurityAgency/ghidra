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
package ghidra.trace.model.target.annot;

import java.util.Collection;
import java.util.List;

import com.google.common.collect.Range;

import ghidra.dbg.target.TargetObject;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.util.LockHold;
import ghidra.util.exception.DuplicateNameException;

public enum TraceObjectInterfaceUtils {
	;

	public static TraceObjectInfo requireAnnotation(Class<? extends TraceObjectInterface> traceIf) {
		TraceObjectInfo annot = traceIf.getAnnotation(TraceObjectInfo.class);
		if (annot == null) {
			throw new IllegalArgumentException(
				traceIf + " is missing @" + TraceObjectInfo.class + " annotation");
		}
		return annot;
	}

	public static Class<? extends TargetObject> toTargetIf(
			Class<? extends TraceObjectInterface> traceIf) {
		return requireAnnotation(traceIf).targetIf();
	}

	public static String getShortName(Class<? extends TraceObjectInterface> traceIf) {
		return requireAnnotation(traceIf).shortName();
	}

	public static Collection<String> getFixedKeys(
			Class<? extends TraceObjectInterface> traceIf) {
		return List.of(requireAnnotation(traceIf).fixedKeys());
	}

	public static void setLifespan(Class<? extends TraceObjectInterface> traceIf,
			TraceObject object, Range<Long> lifespan) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			for (TraceObjectValue val : object.getParents()) {
				if (val.isCanonical() && !val.isDeleted()) {
					val.setLifespan(lifespan, ConflictResolution.DENY);
				}
			}
		}
		catch (DuplicateKeyException e) {
			throw new DuplicateNameException(
				"Duplicate " + getShortName(traceIf) + ": " + e.getMessage());
		}
		object.insert(lifespan, ConflictResolution.TRUNCATE);
		long lower = DBTraceUtils.lowerEndpoint(lifespan);
		for (String key : getFixedKeys(traceIf)) {
			TraceObjectValue val = object.getValue(lower, key);
			if (val != null) {
				val.setLifespan(lifespan, ConflictResolution.TRUNCATE);
			}
		}
	}

	public static <T> T getValue(TraceObject object, long snap, String key, Class<T> cls, T def) {
		TraceObjectValue value = object.getValue(snap, key);
		if (value == null) {
			return def;
		}
		return cls.cast(value.getValue());
	}
}
