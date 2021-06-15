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
package ghidra.app.plugin.core.osgi;

import java.util.*;
import java.util.concurrent.locks.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import generic.jar.ResourceFile;

/**
 * A thread-safe container that maps {@link GhidraBundle}s by file and bundle location.
 */
public class BundleMap {
	private final ReadWriteLock lock = new ReentrantReadWriteLock();
	private final Lock readLock = lock.readLock();
	private final Lock writeLock = lock.writeLock();

	private final Map<ResourceFile, GhidraBundle> bundlesByFile = new HashMap<>();
	private final Map<String, GhidraBundle> bundlesByLocation = new HashMap<>();

	/**
	 * Maps associations between a bundle, its file, and its bundle location.
	 * 
	 * @param bundle a GhidraBundle object
	 */
	public void add(GhidraBundle bundle) {
		writeLock.lock();
		try {
			bundlesByFile.put(bundle.getFile(), bundle);
			bundlesByLocation.put(bundle.getLocationIdentifier(), bundle);
		}
		finally {
			lock.writeLock().unlock();
		}
	}

	/**
	 * Maps bundles in a collection.
	 * 
	 * <p>This is the same as calling {@link BundleMap#add(GhidraBundle)} for each bundle in {@code bundles}.
	 * 
	 * @param bundles a collection of GhidraBundle objects
	 */
	public void addAll(Collection<GhidraBundle> bundles) {
		writeLock.lock();
		try {
			for (GhidraBundle bundle : bundles) {
				bundlesByFile.put(bundle.getFile(), bundle);
				bundlesByLocation.put(bundle.getLocationIdentifier(), bundle);
			}
		}
		finally {
			writeLock.unlock();
		}
	}

	/**
	 * Removes the mappings of a bundle. 
	 * 
	 * @param bundle a GhidraBundle object
	 */
	public void remove(GhidraBundle bundle) {
		writeLock.lock();
		try {
			bundlesByFile.remove(bundle.getFile());
			bundlesByLocation.remove(bundle.getLocationIdentifier());
		}
		finally {
			writeLock.unlock();
		}
	}

	/**
	 * Removes all mappings of each bundle from a collection.
	 * 
	 * This is the same as calling {@link #remove(GhidraBundle)} for each bundle in {@code bundles}.
	 * 
	 * @param bundles a collection of GhidraBundle objects
	 */
	public void removeAll(Collection<GhidraBundle> bundles) {
		writeLock.lock();
		try {
			for (GhidraBundle bundle : bundles) {
				bundlesByFile.remove(bundle.getFile());
				bundlesByLocation.remove(bundle.getLocationIdentifier());
			}
		}
		finally {
			writeLock.unlock();
		}
	}

	/**
	 * Removes the mapping for a bundle with a given bundle location.
	 * 
	 * @param bundleLocation a bundle location
	 * @return the bundle removed
	 */
	public GhidraBundle remove(String bundleLocation) {
		writeLock.lock();
		try {
			GhidraBundle bundle = bundlesByLocation.remove(bundleLocation);
			bundlesByFile.remove(bundle.getFile());
			return bundle;
		}
		finally {
			writeLock.unlock();
		}
	}

	/**
	 * Removes the mapping for a bundle with a given file.
	
	 * @param bundleFile a bundle file
	 * @return the bundle removed
	 */
	public GhidraBundle remove(ResourceFile bundleFile) {
		writeLock.lock();
		try {
			GhidraBundle bundle = bundlesByFile.remove(bundleFile);
			bundlesByLocation.remove(bundle.getLocationIdentifier());
			return bundle;
		}
		finally {
			writeLock.unlock();
		}
	}

	/**
	 * Creates and maps bundles from files in a collection that aren't already mapped.
	 * 
	 * @param bundleFiles a collection of bundle files
	 * @param ctor a constructor for a GhidraBundle given a bundle file
	 * @return the newly created GhidraBundle objects
	 */
	public Collection<GhidraBundle> computeAllIfAbsent(Collection<ResourceFile> bundleFiles,
			Function<ResourceFile, GhidraBundle> ctor) {
		writeLock.lock();
		try {
			Set<ResourceFile> newBundleFiles = new HashSet<>(bundleFiles);
			newBundleFiles.removeAll(bundlesByFile.keySet());
			List<GhidraBundle> newBundles =
				newBundleFiles.stream().map(ctor).collect(Collectors.toList());
			addAll(newBundles);
			return newBundles;
		}
		finally {
			writeLock.unlock();
		}
	}

	/**
	 * Returns the bundle with the given location.
	 * 
	 * @param location a bundle location
	 * @return the bundle found or null
	 */
	public GhidraBundle getBundleAtLocation(String location) {
		readLock.lock();
		try {
			return bundlesByLocation.get(location);
		}
		finally {
			readLock.unlock();
		}
	}

	/**
	 * Returns the bundle with the given file.
	 * 
	 * @param bundleFile a bundle file
	 * @return the bundle found or null
	 */
	public GhidraBundle get(ResourceFile bundleFile) {
		readLock.lock();
		try {
			return bundlesByFile.get(bundleFile);
		}
		finally {
			readLock.unlock();
		}
	}

	/**
	 * @return the currently mapped bundles
	 */
	public Collection<GhidraBundle> getGhidraBundles() {
		readLock.lock();
		try {
			return new ArrayList<>(bundlesByFile.values());
		}
		finally {
			readLock.unlock();
		}
	}

	/**
	 * @return the currently mapped bundle files
	 */
	public Collection<ResourceFile> getBundleFiles() {
		readLock.lock();
		try {
			return new ArrayList<>(bundlesByFile.keySet());
		}
		finally {
			readLock.unlock();
		}
	}

}
