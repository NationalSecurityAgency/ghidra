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
package ghidra.framework.model;

import java.io.File;
import java.io.IOException;
import java.util.*;

import ghidra.framework.options.Options;
import ghidra.util.ReadOnlyException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <CODE>DomainObject</CODE> is the interface that must be supported by
 * data objects that are persistent. <CODE>DomainObject</CODE>s maintain an
 * association with a <CODE>DomainFile</CODE>. A <CODE>DomainObject</CODE> that
 * has never been saved will have a null <CODE>DomainFile</CODE>.
 */
public interface DomainObject {

	/**
	 * Object to synchronize on for undo/redo operations.
	 */
	public final static Object undoLock = new Object();
	/**
	 * Event type generated when the domain object is saved.
	 */
	public final static int DO_OBJECT_SAVED = 1;

	/**
	 * Event type generated when the domain file associated with
	 * the domain object changes.
	 */
	public final static int DO_DOMAIN_FILE_CHANGED = 2;

	/**
	 * Event type generated when the object name changes.
	 */
	public final static int DO_OBJECT_RENAMED = 3;

	/**
	 * Event type generated when domain object is restored.
	 */
	public static final int DO_OBJECT_RESTORED = 4;

	/**
	 * Event type generated when a property on this DomainObject is changed.
	 */
	public static final int DO_PROPERTY_CHANGED = 5;

	/**
	 * Event type generated when this domain object is closed.
	 */
	public static final int DO_OBJECT_CLOSED = 6;

	/**
	 * Event type generated when a fatal error occurs which renders the domain object invalid.
	 */
	public static final int DO_OBJECT_ERROR = 8;

	/**
	 * Returns whether the object has changed.
	 */
	public boolean isChanged();

	/**
	 * Set the temporary state of this object.
	 * If this object is temporary, the isChanged() method will
	 * always return false.  The default temporary state is false.
	 * @param state if true object is marked as temporary
	 */
	public void setTemporary(boolean state);

	/**
	 * Returns true if this object has been marked as Temporary.
	 */
	public boolean isTemporary();

	/**
	 * Returns true if changes are permitted.
	 */
	public boolean isChangeable();

	/**
	 * Returns true if this object can be saved; a read-only file
	 * cannot be saved.
	 */
	public boolean canSave();

	/**
	 * Saves changes to the DomainFile.
	 * @param comment comment used for new version
	 * @param monitor monitor that shows the progress of the save
	 * @throws IOException thrown if there was an error accessing this
	 * domain object
	 * @throws ReadOnlyException thrown if this DomainObject is read only
	 * and cannot be saved
	 * @throws CancelledException thrown if the user canceled the save
	 * operation
	 */
	public void save(String comment, TaskMonitor monitor) throws IOException, CancelledException;

	/**
	 * Saves (i.e., serializes) the current content to a packed file.
	 * @param outputFile packed output file
	 * @param monitor progress monitor
	 * @throws IOException
	 * @throws CancelledException
	 * @throws UnsupportedOperationException if not supported by object implementation
	 */
	public void saveToPackedFile(File outputFile, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Notify the domain object that the specified consumer is no longer using it.
	 * When the last consumer invokes this method, the domain object will be closed 
	 * and will become invalid.
	 * @param consumer the consumer (e.g., tool, plugin, etc) of the domain object 
	 * previously established with the addConsumer method.
	 */
	public void release(Object consumer);

	/**
	 * Adds a listener for this object.
	 * @param dol listener notified when any change occurs to this domain object
	 */
	public void addListener(DomainObjectListener dol);

	/**
	 * Remove the listener for this object.
	 * @param dol listener
	 */
	public void removeListener(DomainObjectListener dol);

	/**
	 * Adds a listener that will be notified when this DomainObject is closed.  This is meant
	 * for clients to have a chance to cleanup, such as reference removal.
	 * 
	 * @param listener the reference to add
	 */
	public void addCloseListener(DomainObjectClosedListener listener);

	/**
	 * Removes the given close listener.
	 * 
	 * @param listener the listener to remove.
	 */
	public void removeCloseListener(DomainObjectClosedListener listener);

	/**
	 * Creates a private event queue that can be flushed independently from the main event queue.
	 * @param listener the listener to be notified of domain object events.
	 * @param maxDelay the time interval (in milliseconds) used to buffer events.
	 * @return a unique identifier for this private queue.
	 */
	public EventQueueID createPrivateEventQueue(DomainObjectListener listener, int maxDelay);

	/**
	 * Removes the specified private event queue
	 * @param id the id of the queue to remove.
	 * @return true if the id represents a valid queue that was removed.
	 */
	public boolean removePrivateEventQueue(EventQueueID id);

	/**
	 * Returns a word or short phrase that best describes or categorizes
	 * the object in terms that a user will understand.
	 */
	public String getDescription();

	/**
	 * Get the name of this domain object.
	 */
	public String getName();

	/**
	 * Set the name for this domain object.
	 * @param name object name
	 */
	public void setName(String name);

	/**
	 * Get the domain file for this domain object.
	 * @return the associated domain file 
	 */
	public DomainFile getDomainFile();

	/**
	 * Adds the given object as a consumer.  The release method must be invoked
	 * with this same consumer instance when this domain object is no longer in-use.
	 * @param consumer domain object consumer
	 * @return false if this domain object has already been closed
	 */
	public boolean addConsumer(Object consumer);

	/** 
	 * Returns the list of consumers on this domainObject
	 * @return the list of consumers.
	 */
	public ArrayList<Object> getConsumerList();

	/** 
	 * Returns true if the given consumer is using (has open) this domain object.
	 * @param consumer the object to test to see if it is a consumer of this domain object.
	 * @return true if the given consumer is using (has open) this domain object;
	 */
	public boolean isUsedBy(Object consumer);

	/**
	 * If true, domain object change events are sent. If false, no events are sent.
	 * <p>
	 * <b>
	 * NOTE: disabling events could cause plugins to be out of sync!
	 * </b>
	 * <p>
	 * NOTE: when re-enabling events, an event will be sent to the system to signal that
	 *       every listener should update.
	 * 
	 * 
	 * @param enabled true means to enable events
	 */
	public void setEventsEnabled(boolean enabled);

	/**
	 * Returns true if this object is sending out events as it is changed.  The default is
	 * true.  You can change this value by calling {@link #setEventsEnabled(boolean)}.
	 * 
	 * @see #setEventsEnabled(boolean)
	 */
	public boolean isSendingEvents();

	/**
	 * Makes sure all pending domainEvents have been sent.
	 */
	public void flushEvents();

	/**
	 * Flush events from the specified event queue.
	 * @param id the id specifying the event queue to be flushed.
	 */
	public void flushPrivateEventQueue(EventQueueID id);

	/**
	 * Returns true if a modification lock can be obtained on this
	 * domain object.  Care should be taken with using this method since
	 * this will not prevent another thread from modifying the domain object.
	 */
	public boolean canLock();

	/**
	 * Returns true if the domain object currenly has a modification lock enabled.
	 */
	public boolean isLocked();

	/**
	 * Attempt to obtain a modification lock on the domain object.  Multiple locks
	 * may be granted on this domain object, although all lock owners must release their
	 * lock in a timely fashion.
	 * @param reason very short reason for requesting lock
	 * @return true if lock obtained successfully, else false which indicates that a
	 * modification is in process.
	 */
	public boolean lock(String reason);

	/**
	 * Cancels any previous lock and aquires it.
	 * @param rollback if true, any changes in made with the previous lock should be discarded.
	 * @param reason very short reason for requesting lock
	 */
	public void forceLock(boolean rollback, String reason);

	/**
	 * Release a modification lock previously granted with the lock method.
	 */
	public void unlock();

	/**
	 * Returns all properties lists contained by this domain object.
	 * 
	 * @return all property lists contained by this domain object.
	 */
	public List<String> getOptionsNames();

	/**
	 * Get the property list for the given name.
	 * @param propertyListName name of property list
	 */
	public Options getOptions(String propertyListName);

	/**
	 * Returns true if this domain object has been closed as a result of the last release
	 */
	public boolean isClosed();

	/**
	 * Returns true if the user has exclusive access to the domain object.  Exclusive access means
	 * either the object is not shared or the user has an exclusive checkout on the object.
	 */
	public boolean hasExclusiveAccess();

	/**
	 * Returns a map containing all the stored metadata associated with this domain object.  The map
	 * contains key,value pairs and are ordered by their insertion order.
	 * @return a map containing all the stored metadata associated with this domain object.
	 */
	public Map<String, String> getMetadata();

	/**
	 * Returns a long value that gets incremented every time a change, undo, or redo takes place.
	 * Useful for implementing a lazy caching system.
	 * @return a long value that is incremented for every change to the program.
	 */
	public long getModificationNumber();
}
