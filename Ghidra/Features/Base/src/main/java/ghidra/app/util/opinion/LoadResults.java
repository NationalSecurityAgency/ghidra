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
import ghidra.util.Msg;
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
public class LoadResults<T extends DomainObject> implements Iterable<Loaded<T>> {

	private final List<Loaded<T>> loadedList;

	/**
	 * Creates a new {@link LoadResults} that contains the given non-empty {@link List} of 
	 * {@link Loaded} {@link DomainObject}s.  The first entry in the {@link List} is assumed to be
	 * the {@link #getPrimary() primary} {@link Loaded} {@link DomainObject}.
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
	 * Creates a a new {@link LoadResults} that contains a new {@link Loaded} 
	 * {@link DomainObject} created from the given parameters.  This new {@link Loaded} 
	 * {@link DomainObject} is assumed to be the {@link #getPrimary() primary} {@link Loaded} 
	 * {@link DomainObject}.
	 * 
	 * @param domainObject The loaded {@link DomainObject}
	 * @param name The name of the loaded {@link DomainObject}.  If a 
	 *   {@link #save(Project, Object, MessageLog, TaskMonitor) save} occurs, this will attempted to
	 *   be used for the resulting {@link DomainFile}'s name.
	 * @param projectFolderPath The project folder path this will get saved to during a 
	 *   {@link #save(Project, Object, MessageLog, TaskMonitor) save} operation.  If null or empty, 
	 *   the root project folder will be used.
	 */
	public LoadResults(T domainObject, String name, String projectFolderPath) {
		this(List.of(new Loaded<T>(domainObject, name, projectFolderPath)));
	}

	/**
	 * Gets the "primary" {@link Loaded} {@link DomainObject}, who's meaning is defined by each 
	 * {@link Loader} implementation
	 * 
	 * @return The "primary" {@link Loaded} {@link DomainObject}
	 */
	public Loaded<T> getPrimary() {
		return loadedList.get(0);
	}

	/**
	 * Gets the "primary" {@link DomainObject}, who's meaning is defined by each {@link Loader} 
	 * implementation
	 * 
	 * @return The "primary" {@link DomainObject}
	 */
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
	 * {@link Loaded#save(Project, MessageLog, TaskMonitor) Saves} each {@link Loaded} 
	 * {@link DomainObject} to the given {@link Project}.
	 * <p>
	 * NOTE: If any fail to save, none will be saved (already saved {@link DomainFile}s will be
	 * cleaned up/deleted), and all {@link Loaded} {@link DomainObject}s will have been
	 * {@link #release(Object) released}.
	 * 
	 * @param project The {@link Project} to save to
	 * @param consumer the consumer
	 * @param messageLog The log
	 * @param monitor A cancelable task monitor
	 * @throws CancelledException if the operation was cancelled
	 * @throws IOException If there was a problem saving
	 * @see Loaded#save(Project, MessageLog, TaskMonitor)
	 */
	public void save(Project project, Object consumer, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, IOException {
		boolean success = false;
		try {
			for (Loaded<T> loaded : loadedList) {
				loaded.save(project, messageLog, monitor);
			}
			success = true;
		}
		finally {
			if (!success) {
				for (Loaded<T> loaded : this) {
					try {
						loaded.release(consumer);
						loaded.deleteSavedDomainFile(consumer);
					}
					catch (IOException e1) {
						Msg.error(getClass(), "Failed to delete: " + loaded);
					}
				}
			}
		}
	}

	/**
	 * Notify all of the {@link Loaded} {@link DomainObject}s that the specified consumer is no 
	 * longer using them. When the last consumer invokes this method, the {@link Loaded} 
	 * {@link DomainObject}s will be closed and will become invalid.
	 * 
	 * @param consumer the consumer
	 */
	public void release(Object consumer) {
		loadedList.forEach(loaded -> loaded.release(consumer));
	}

	/**
	 * Notify the filtered {@link Loaded} {@link DomainObject}s that the specified consumer is no 
	 * longer using them. When the last consumer invokes this method, the filtered {@link Loaded} 
	 * {@link DomainObject}s will be closed and will become invalid.
	 * 
	 * @param consumer the consumer
	 * @param filter a filter to apply to the {@link Loaded} {@link DomainObject}s prior to the
	 *   release
	 */
	public void release(Object consumer, Predicate<? super Loaded<T>> filter) {
		loadedList.stream().filter(filter).forEach(loaded -> loaded.release(consumer));
	}

	/**
	 * Notify the non-primary {@link Loaded} {@link DomainObject}s that the specified consumer is no 
	 * longer using them. When the last consumer invokes this method, the non-primary {@link Loaded} 
	 * {@link DomainObject}s will be closed and will become invalid.
	 * 
	 * @param consumer the consumer
	 */
	public void releaseNonPrimary(Object consumer) {
		for (int i = 0; i < loadedList.size(); i++) {
			if (i > 0) {
				loadedList.get(i).release(consumer);
			}
		}
	}

	@Override
	public Iterator<Loaded<T>> iterator() {
		return loadedList.iterator();
	}
}
