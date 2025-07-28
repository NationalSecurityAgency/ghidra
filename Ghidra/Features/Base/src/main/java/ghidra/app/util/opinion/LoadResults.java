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
package ghidra.app.util.opinion;

import java.io.IOException;
import java.util.*;
import java.util.function.Predicate;

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The result of a 
 * {@link Loader#load(ghidra.app.util.bin.ByteProvider, String, Project, String, LoadSpec, List, MessageLog, Object, TaskMonitor) load}.
 * A {@link LoadResults} object provides convenient access to and operations on the underlying 
 * {@link Loaded} {@link DomainObject}s that got loaded.
 * 
 * @param <T> The type of {@link DomainObject}s that were loaded
 */
public class LoadResults<T extends DomainObject> implements Iterable<Loaded<T>>, AutoCloseable {

	private final List<Loaded<T>> loadedList;

	/**
	 * Creates a new {@link LoadResults} that contains the given non-empty {@link List} of 
	 * {@link Loaded} {@link DomainObject}s.  The first entry in the {@link List} is assumed to be
	 * the {@link #getPrimary() primary} {@link Loaded} {@link DomainObject}.
	 * <p>
	 * This object needs to be {@link #close() closed} when done with it.
	 * 
	 * @param loadedList A {@link List} of {@link Loaded} {@link DomainObject}s
	 * @throws IllegalArgumentException if the provided {@link List} is null or empty
	 */
	public LoadResults(List<Loaded<T>> loadedList) throws IllegalArgumentException {
		if (loadedList == null || loadedList.isEmpty()) {
			throw new IllegalArgumentException("The loaded list must not be empty");
		}
		this.loadedList = new ArrayList<>(loadedList);
	}
	
	/**
	 * Creates a new {@link LoadResults} that contains a new {@link Loaded} 
	 * {@link DomainObject} created from the given parameters.  This new {@link Loaded} 
	 * {@link DomainObject} is assumed to be the {@link #getPrimary() primary} {@link Loaded} 
	 * {@link DomainObject}.
	 * 
	 * @param domainObject The loaded {@link DomainObject}
	 * @param name The name of the loaded {@link DomainObject}.  If a 
	 *   {@link #save(TaskMonitor) save} occurs, this will attempted to be used for the resulting 
	 *   {@link DomainFile}'s name.
	 * @param project If not null, the project this will get saved to during a 
	 *   {@link #save(TaskMonitor)} operation
	 * @param projectFolderPath The project folder path this will get saved to during a 
	 *   {@link #save(TaskMonitor) save} operation.  If null or empty, the root project folder will
	 *   be used.
	 * @param consumer A reference to the object "consuming" the returned this 
	 *   {@link LoadResults}, used to ensure the underlying {@link DomainObject}s are only closed 
	 *   when every consumer is done with it (see {@link #close()}). NOTE:  Wrapping a 
	 *   {@link DomainObject} in a {@link LoadResults} transfers responsibility of releasing the 
	 *   given {@link DomainObject} to this {@link LoadResults}'s {@link #close()} method. 
	 */
	public LoadResults(T domainObject, String name, Project project, String projectFolderPath,
			Object consumer) {
		this(List.of(new Loaded<T>(domainObject, name, project, projectFolderPath, consumer)));
	}

	/**
	 * Gets the "primary" {@link Loaded} {@link DomainObject}, whose meaning is defined by each 
	 * {@link Loader} implementation
	 * 
	 * @return The "primary" {@link Loaded} {@link DomainObject}
	 */
	public Loaded<T> getPrimary() {
		return loadedList.getFirst();
	}

	/**
	 * Gets the "non-primary" {@link Loaded} {@link DomainObject}s, whose meaning is defined by each
	 * {@link Loader} implementation
	 * 
	 * @return The "non-primary" {@link Loaded} {@link DomainObject}s
	 */
	public List<Loaded<T>> getNonPrimary() {
		return loadedList.stream().skip(1).toList();
	}

	/**
	 * Gets the "primary" {@link DomainObject}, whose meaning is defined by each {@link Loader} 
	 * implementation.
	 * <p>
	 * NOTE: It is the responsibility of the caller to properly 
	 * {@link DomainObject#release(Object) release} it when done. This
	 * {@link DomainObject#release(Object)} does not replace the requirement to 
	 * {@link #close()} the {@link LoadResults} object when done.
	 * 
	 * @param consumer A new reference to the object "consuming" the returned {@link DomainObject},
	 *   used to ensure the underlying {@link DomainObject} is only released when every consumer is
	 *   done with it (see {@link DomainObject#release(Object)}). NOTE: This method adds the given
	 *   consumer to the returned {@link DomainObject}, requiring an explicit 
	 *   {@link DomainObject#release(Object)} to be called on the return value (this entire
	 *   {@link LoadResults} must also still be {@link #close() closed}).
	 * @return The "primary" {@link DomainObject}
	 */
	public T getPrimaryDomainObject(Object consumer) {
		return loadedList.getFirst().getDomainObject(consumer);
	}

	/**
	 * Gets the "primary" loaded {@link DomainObject}, whose meaning is defined by each 
	 * {@link Loader} implementation. Unsafe resource management is used. Temporarily exists to 
	 * provide backwards compatibility.
	 * 
	 * @return The "primary" {@link DomainObject}
	 * @deprecated This class's internal {@link DomainObject}s are now cleaned up with the 
	 *   {@link #close()} method.  If the primary {@link DomainObject} needs to be retrieved from 
	 *   this class, instead use {@link #getPrimaryDomainObject(Object)} and independently clean up
	 *   the new reference with a separate call to {@link DomainObject#release(Object)}.
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public T getPrimaryDomainObject() {
		return loadedList.get(0).getDomainObject();
	}

	/**
	 * Gets the number of {@link Loaded} {@link DomainObject}s in this {@link LoadResults}.  The
	 * size will always be greater than 0.
	 * 
	 * @return The number of {@link Loaded} {@link DomainObject}s in this {@link LoadResults}
	 */
	public int size() {
		return loadedList.size();
	}

	/**
	 * {@link Loaded#save(TaskMonitor) Saves} each {@link Loaded} {@link DomainObject} to the given 
	 * {@link Project}.
	 * 
	 * @param monitor A cancelable task monitor
	 * @throws CancelledException if the operation was cancelled
	 * @throws IOException If there was a problem saving. A thrown exception may result in only some
	 *   of the {@link Loaded} elements being saved. It is the responsibility of the caller to clean
	 *   things up appropriately.
	 * @see Loaded#save(TaskMonitor)
	 */
	public void save(TaskMonitor monitor) throws CancelledException, IOException {
		for (Loaded<T> loaded : loadedList) {
			loaded.save(monitor);
		}
	}

	/**
	 * Unsafely notifies all of the {@link Loaded} {@link DomainObject}s that the specified consumer
	 * is no longer using them. Temporarily exists to provide backwards compatibility.
	 * 
	 * @param consumer the consumer
	 * @deprecated Use {@link #close()} instead
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public void release(Object consumer) {
		loadedList.forEach(loaded -> loaded.release(consumer));
	}

	/**
	 * Unsafely notifies the filtered {@link Loaded} {@link DomainObject}s that the specified 
	 * consumer is no longer using them. Temporarily exists to provide backwards compatibility.
	 * 
	 * @param consumer the consumer
	 * @param filter a filter to apply to the {@link Loaded} {@link DomainObject}s prior to the
	 *   release
	 * @deprecated Use {@link #close()} instead
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public void release(Object consumer, Predicate<? super Loaded<T>> filter) {
		loadedList.stream().filter(filter).forEach(loaded -> loaded.release(consumer));
	}

	/**
	 * Notify the non-primary {@link Loaded} {@link DomainObject}s that the specified consumer is no 
	 * longer using them. When the last consumer invokes this method, the non-primary {@link Loaded} 
	 * {@link DomainObject}s will be closed and will become invalid.
	 * 
	 * @param consumer the consumer
	 * @deprecated Use {@link #getNonPrimary()} and {@link Loaded#close()} on the {@link List} 
	 *   elements instead
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public void releaseNonPrimary(Object consumer) {
		for (int i = 0; i < loadedList.size(); i++) {
			if (i > 0) {
				loadedList.get(i).release(consumer);
			}
		}
	}

	/**
	 * Closes this {@link LoadResults} and releases the reference on the object consuming it.
	 * <p>
	 * NOTE: Any {@link DomainObject}s obtained via {@link #getPrimaryDomainObject(Object)} must
	 * still be explicitly {@link DomainObject#release(Object) released} after calling this method,
	 * since they were obtained with their own consumers.
	 */
	@Override
	public void close() {
		loadedList.forEach(Loaded::close);
	}

	@Override
	public Iterator<Loaded<T>> iterator() {
		return loadedList.iterator();
	}
}
