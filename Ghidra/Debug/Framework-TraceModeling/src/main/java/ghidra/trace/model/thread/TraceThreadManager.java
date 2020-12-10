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
package ghidra.trace.model.thread;

import java.util.Collection;

import com.google.common.collect.Range;

import ghidra.util.exception.DuplicateNameException;

/**
 * A store for observed threads over time in a trace
 * 
 * <p>
 * Note that the methods returning collections of threads order them eldest first. "Eldest" means
 * lowest database key, which does not necessarily correlate to earliest creation snap.
 */
public interface TraceThreadManager {

	/**
	 * Add a thread with the given lifespan
	 * 
	 * @param path the "full name" of the thread
	 * @param lifespan the lifespan of the thread
	 * @return the new thread
	 * @throws DuplicateNameException if a thread with the given full name already exists within an
	 *             overlapping snap
	 */
	TraceThread addThread(String path, Range<Long> lifespan) throws DuplicateNameException;

	/**
	 * Add a thread with the given lifespan
	 * 
	 * @param path the "full name" of the thread
	 * @param name "short name" of the thread
	 * @param lifespan the lifespan of the thread
	 * @return the new thread
	 * @throws DuplicateNameException if a thread with the given full name already exists within an
	 *             overlapping snap
	 */
	TraceThread addThread(String path, String display, Range<Long> lifespan)
			throws DuplicateNameException;

	/**
	 * Add a thread with the given creation snap
	 * 
	 * @see #addThread(String, Range)
	 */
	default TraceThread createThread(String path, long creationSnap) throws DuplicateNameException {
		return addThread(path, Range.atLeast(creationSnap));
	}

	/**
	 * Add a thread with the given creation snap
	 * 
	 * @see #addThread(String, String, Range)
	 */
	default TraceThread createThread(String path, String display, long creationSnap)
			throws DuplicateNameException {
		return addThread(path, display, Range.atLeast(creationSnap));
	}

	/**
	 * Get all threads ordered eldest first
	 * 
	 * @return the collection
	 */
	Collection<? extends TraceThread> getAllThreads();

	/**
	 * Get all threads with the given name, ordered eldest first
	 * 
	 * @param name the name
	 * @return the collection
	 */
	Collection<? extends TraceThread> getThreadsByPath(String name);

	/**
	 * Get the live thread at the given snap by the given path
	 * 
	 * @param snap the snap which the thread's lifespan must contain
	 * @param path the path of the thread
	 * @return the thread, or {@code null} if no thread matches
	 */
	TraceThread getLiveThreadByPath(long snap, String path);

	/**
	 * Get the thread with the given key
	 * 
	 * @param key the database key
	 * @return the thread
	 */
	TraceThread getThread(long key);

	/**
	 * Get live threads at the given snap, ordered eldest first
	 * 
	 * @param snap the snap
	 * @return the collection
	 */
	Collection<? extends TraceThread> getLiveThreads(long snap);
}
