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
package ghidra.app.plugin.core.analysis;

import java.io.Closeable;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Supplier;

import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectClosedListener;
import ghidra.program.model.listing.Program;

/**
 * Mechanism to associate values with a currently open program.  Values will be released when
 * the program is closed, or when the current analysis session is finished.
 * <p>
 * Values that are linked to things in a Program that are subject to be reverted during a
 * transaction roll-back should probably not be stored in a PROGRAM scoped property.  (example:
 * DataTypes, CodeUnits, etc)  ANALYSIS_SESSION scoped properties are protected from rollback
 * by the active transaction that is held during the session.
 * 
 */
public class TransientProgramProperties {

	private static final Map<Program, PerProgramProperties> properties = new HashMap<>();

	public enum SCOPE {
		PROGRAM, // value will be released when the program is closed 
		ANALYSIS_SESSION // value will be released when the current analysis session is finished
	}

	/**
	 * A checked {@link Supplier}
	 *  
	 * @param <T> type of result
	 * @param <E> type of exception thrown
	 */
	public interface PropertyValueSupplier<T, E extends Throwable> {
		T get() throws E;
	}

	/**
	 * Returns true if the specified property is present.
	 *  
	 * @param program {@link Program}
	 * @param key property key
	 * @return boolean true if property is present.
	 */
	public static synchronized boolean hasProperty(Program program, Object key) {
		PerProgramProperties perProgramProps = properties.get(program);
		return perProgramProps != null ? perProgramProps.props.containsKey(key) : false;
	}

	/**
	 * Returns a property value that has been associated with the specified program.
	 * <p>
	 * If the property wasn't present, the {@link PropertyValueSupplier} will be used to 
	 * create the value and associate it with the program.
	 * 
	 * @param <T> type of the property value.  If the property value is {@link Closeable}, it
	 * will be {@link Closeable#close() closed} when released.
	 * @param <E> type of the exception the supplier throws
	 * @param program {@link Program}
	 * @param key property key
	 * @param scope {@link SCOPE} lifetime of property.  If an analysis session is NOT active,
	 * requesting {@link SCOPE#ANALYSIS_SESSION} will throw an IllegalArgumentException.  If the
	 * requested scope does not match the scope of the already existing value, an 
	 * IllegalArgumentException will be thrown.
	 * @param clazz type of the property value
	 * @param supplier {@link PropertyValueSupplier} callback that will create the property 
	 * value if it is not present
	 * @return property value
	 * @throws IllegalArgumentException if scope == ANALYSIS_SESSION and there is no active analysis
	 * session, OR, if the requested scope does not match the scope used to an earlier call for
	 * the same property
	 * @throws E same exception type that the supplier throws
	 */
	public static synchronized <T, E extends Throwable> T getProperty(Program program, Object key,
			SCOPE scope, Class<? extends T> clazz, PropertyValueSupplier<T, E> supplier) throws E {
		if (scope == SCOPE.ANALYSIS_SESSION &&
			(!AutoAnalysisManager.hasAutoAnalysisManager(program) ||
				!AutoAnalysisManager.getAnalysisManager(program).isAnalyzing())) {
			throw new IllegalArgumentException("No active analysis session");
		}

		PerProgramProperties perProgramProps =
			properties.computeIfAbsent(program, PerProgramProperties::new);

		Property property = perProgramProps.props.get(key);
		if (property == null) {
			T supplierVal = supplier.get();
			if (supplierVal == null) {
				return null;
			}
			property = perProgramProps.addProperty(key, supplierVal, scope);
		}
		if (property.scope != scope) {
			throw new IllegalArgumentException("Mismatched Program property scope");
		}
		return clazz.isInstance(property.value) ? clazz.cast(property.value) : null;
	}

	/**
	 * Release all properties for the specified program.
	 * 
	 * @param program {@link Program}
	 */
	public static synchronized void removeProgramProperties(Program program) {
		PerProgramProperties removedProps = properties.remove(program);
		if (removedProps != null) {
			removedProps.close();
		}
	}

	//---------------------------------------------------------------------------------------------
	private record Property(Object key, Object value, SCOPE scope) implements Closeable {
		@Override
		public void close() {
			if (value instanceof Closeable c) {
				FSUtilities.uncheckedClose(c, null);
			}
		}
	}

	private static class PerProgramProperties
			implements DomainObjectClosedListener, AutoAnalysisManagerListener, Closeable {
		final Program program;
		final Map<Object, Property> props;
		boolean aamListenerAdded;

		PerProgramProperties(Program program) {
			this.program = program;
			this.props = new HashMap<>();
			program.addCloseListener(this);
		}

		@Override
		public void domainObjectClosed(DomainObject dobj) {
			removeProgramProperties(program);
		}

		@Override
		public void analysisEnded(AutoAnalysisManager manager, boolean isCancelled) {
			for (Iterator<Entry<Object, Property>> it = props.entrySet().iterator(); it
					.hasNext();) {
				Entry<Object, Property> entry = it.next();
				Property prop = entry.getValue();
				if (prop.scope == SCOPE.ANALYSIS_SESSION) {
					it.remove();
					prop.close();
				}
			}
		}

		@Override
		public void close() {
			props.forEach((key, prop) -> prop.close());
			props.clear();
			program.removeCloseListener(this);
			if (aamListenerAdded) {
				AutoAnalysisManager.getAnalysisManager(program).removeListener(this);
			}
		}

		private Property addProperty(Object key, Object value, SCOPE scope) {
			if (scope == SCOPE.ANALYSIS_SESSION) {
				if (!aamListenerAdded) {
					AutoAnalysisManager.getAnalysisManager(program).addListener(this);
					aamListenerAdded = true;
				}
			}
			Property newProperty = new Property(key, value, scope);
			props.put(key, newProperty);
			return newProperty;
		}

	}

}
