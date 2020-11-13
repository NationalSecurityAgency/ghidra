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
package ghidra.framework.data;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import ghidra.framework.model.*;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.LockException;
import ghidra.util.Lock;
import ghidra.util.classfinder.ClassSearcher;

/**
 * An abstract class that provides default behavior for
 * DomainObject(s), specifically it handles listeners and
 * change status; the derived class must provide the
 * getDescription() method.
 */
public abstract class DomainObjectAdapter implements DomainObject {

	protected final static String DEFAULT_NAME = "untitled";

	private static Class<?> defaultDomainObjClass; // Domain object implementation mapped to unknown content type
	private static HashMap<String, ContentHandler> contentHandlerTypeMap; // maps content-type string to handler
	private static HashMap<Class<?>, ContentHandler> contentHandlerClassMap; // maps domain object class to handler
	private static ChangeListener contentHandlerUpdateListener = new ChangeListener() {
		@Override
		public void stateChanged(ChangeEvent e) {
			getContentHandlers();
		}
	};

	protected String name;
	private DomainFile domainFile;

	private DomainObjectChangeSupport docs;
	protected Map<EventQueueID, DomainObjectChangeSupport> changeSupportMap =
		new ConcurrentHashMap<EventQueueID, DomainObjectChangeSupport>();
	private volatile boolean eventsEnabled = true;
	private Set<DomainObjectClosedListener> closeListeners =
		new HashSet<DomainObjectClosedListener>();

	private ArrayList<Object> consumers;
	protected Map<String, String> metadata = new LinkedHashMap<String, String>();

	// a flag indicating whether the domain object has changed
	// any methods of this domain object which cause its state to
	// to change must set this flag to true
	protected boolean changed = false;

	// a flag indicating that this object is temporary
	protected boolean temporary = false;
	protected Lock lock = new Lock("Domain Object");
	private long modificationNumber = 1;

	/**
	 * Construct a new DomainObjectAdapter. 
	 * If construction of this object fails, be sure to release with consumer.
	 * @param name name of the object
	 * @param timeInterval the time (in milliseconds) to wait before the
	 * event queue is flushed.  If a new event comes in before the time expires,
	 * the timer is reset.
	 * @param bufsize initial size of event buffer
	 * @param consumer the object that created this domain object
	 */
	protected DomainObjectAdapter(String name, int timeInterval, int bufsize, Object consumer) {
		if (consumer == null) {
			throw new IllegalArgumentException("Consumer must not be null");
		}
		this.name = name;
		docs = new DomainObjectChangeSupport(this, timeInterval, bufsize, lock);
		consumers = new ArrayList<Object>();
		consumers.add(consumer);
		if (!UserData.class.isAssignableFrom(getClass())) {
			// UserData instances do not utilize DomainFile storage
			domainFile = new DomainFileProxy(name, this);
		}
	}

	/**
	 * @see ghidra.framework.model.DomainObject#release(java.lang.Object)
	 */
	@Override
	public void release(Object consumer) {
		synchronized (consumers) {
			if (!consumers.remove(consumer)) {
				throw new IllegalArgumentException(
					"Attempted to release domain object with unknown consumer: " + consumer);
			}
			if (consumers.size() != 0) {
				return;
			}
		}
		close();
	}

	public Lock getLock() {
		return lock;
	}

	/**
	 * @see ghidra.framework.model.DomainObject#getDomainFile()
	 */
	@Override
	public DomainFile getDomainFile() {
		return domainFile;
	}

	/**
	 * Returns the hidden user-filesystem associated with 
	 * this objects domain file, or null if unknown.
	 * @return user data file system
	 */
	protected FileSystem getAssociatedUserFilesystem() {
		if (domainFile instanceof GhidraFile) {
			return ((GhidraFile) domainFile).getUserFileSystem();
		}
		return null;
	}

	/**
	 * @see ghidra.framework.model.DomainObject#getName()
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		String classname = getClass().getName();
		classname = classname.substring(classname.lastIndexOf('.'));
		return name + " - " + classname;
	}

	/**
	 * @see ghidra.framework.model.DomainObject#setName(java.lang.String)
	 */
	@Override
	public void setName(String newName) {
		synchronized (this) {
			if (name.equals(newName)) {
				return;
			}
			name = newName;
			changed = true;
		}
		fireEvent(new DomainObjectChangeRecord(DO_OBJECT_RENAMED));
	}

	private void clearDomainObj() {
		if (domainFile instanceof GhidraFile) {
			GhidraFile file = (GhidraFile) domainFile;
			file.clearDomainObj();
		}
		else if (domainFile instanceof DomainFileProxy) {
			DomainFileProxy df = (DomainFileProxy) domainFile;
			df.clearDomainObj();
		}
	}

	/**
	 * @see ghidra.framework.model.DomainObject#isChanged()
	 */
	@Override
	public boolean isChanged() {
		return changed && !temporary;
	}

	/**
	 * @see ghidra.framework.model.DomainObject#setTemporary(boolean)
	 */
	@Override
	public void setTemporary(boolean state) {
		temporary = state;
	}

	/**
	 * @see ghidra.framework.model.DomainObject#isTemporary()
	 */
	@Override
	public boolean isTemporary() {
		return temporary;
	}

	protected void setDomainFile(DomainFile df) {
		if (df == null) {
			throw new IllegalArgumentException("DomainFile must not be null");
		}
		clearDomainObj();
		DomainFile oldDf = domainFile;
		domainFile = df;
		fireEvent(new DomainObjectChangeRecord(DO_DOMAIN_FILE_CHANGED, oldDf, df));
	}

	protected void close() {
		synchronized (this) {
			clearDomainObj();
		}

// TODO: This does not work since change manager is disposed before event ever gets sent out
//		fireEvent(new DomainObjectChangeRecord(DO_OBJECT_CLOSED));

		docs.dispose(); // clear out any unsent events to prevent listeners from trying
		for (DomainObjectChangeSupport queue : changeSupportMap.values()) {
			queue.dispose();
		}

		notifyCloseListeners();
	}

	private void notifyCloseListeners() {
		for (DomainObjectClosedListener listener : closeListeners) {
			listener.domainObjectClosed();
		}
		closeListeners.clear();
	}

	/**
	 * @see ghidra.framework.model.DomainObject#flushEvents()
	 */
	@Override
	public void flushEvents() {
		docs.flush();
		for (DomainObjectChangeSupport queue : changeSupportMap.values()) {
			queue.flush();
		}
	}

	/**
	 * Return "changed" status
	 * @return true if this object has changed
	 */
	public boolean getChangeStatus() {
		return changed;
	}

	/**
	 * @see ghidra.framework.model.DomainObject#addListener(ghidra.framework.model.DomainObjectListener)
	 */
	@Override
	public synchronized void addListener(DomainObjectListener l) {
		docs.addListener(l);
	}

	/**
	 * @see ghidra.framework.model.DomainObject#removeListener(ghidra.framework.model.DomainObjectListener)
	 */
	@Override
	public synchronized void removeListener(DomainObjectListener l) {
		docs.removeListener(l);
	}

	@Override
	public void addCloseListener(DomainObjectClosedListener listener) {
		closeListeners.add(listener);
	}

	@Override
	public void removeCloseListener(DomainObjectClosedListener listener) {
		closeListeners.remove(listener);
	}

	@Override
	public EventQueueID createPrivateEventQueue(DomainObjectListener listener, int maxDelay) {
		EventQueueID eventQueueID = new EventQueueID();
		DomainObjectChangeSupport queue = new DomainObjectChangeSupport(this, maxDelay, 1000, lock);
		queue.addListener(listener);
		changeSupportMap.put(eventQueueID, queue);
		return eventQueueID;
	}

	@Override
	public boolean removePrivateEventQueue(EventQueueID id) {
		DomainObjectChangeSupport queue = changeSupportMap.remove(id);
		if (queue == null) {
			return false;
		}
		queue.dispose();
		return true;
	}

	@Override
	public void flushPrivateEventQueue(EventQueueID id) {
		DomainObjectChangeSupport queue = changeSupportMap.get(id);
		if (queue != null) {
			queue.flush();
		}
	}

	/**
	 * @see ghidra.framework.model.DomainObject#getDescription()
	 */
	@Override
	public abstract String getDescription();

	/**
	  * Fires the specified event.
	  * @param ev event to fire
	  */
	public void fireEvent(DomainObjectChangeRecord ev) {
		modificationNumber++;
		if (eventsEnabled) {
			docs.fireEvent(ev);
			for (DomainObjectChangeSupport queue : changeSupportMap.values()) {
				queue.fireEvent(ev);
			}
		}
	}

	/**
	 * @see ghidra.framework.model.DomainObject#setEventsEnabled(boolean)
	 */
	@Override
	public void setEventsEnabled(boolean v) {
		if (eventsEnabled != v) {
			eventsEnabled = v;
			if (eventsEnabled) {
				DomainObjectChangeRecord docr = new DomainObjectChangeRecord(DO_OBJECT_RESTORED);
				docs.fireEvent(docr);
				for (DomainObjectChangeSupport queue : changeSupportMap.values()) {
					queue.fireEvent(docr);
				}
			}
		}
	}

	@Override
	public boolean isSendingEvents() {
		return eventsEnabled;
	}

	/**
	 * @see ghidra.framework.model.DomainObject#hasExclusiveAccess()
	 */
	@Override
	public boolean hasExclusiveAccess() {
		return domainFile == null || !domainFile.isCheckedOut() ||
			domainFile.isCheckedOutExclusive();
	}

	public void checkExclusiveAccess() throws LockException {
		if (!hasExclusiveAccess()) {
			throw new LockException();
		}
	}

	protected void setChanged(boolean state) {
		changed = state;
	}

	/**
	 * @see ghidra.framework.model.DomainObject#addConsumer(java.lang.Object)
	 */
	@Override
	public boolean addConsumer(Object consumer) {
		if (consumer == null) {
			throw new IllegalArgumentException("Consumer must not be null");
		}

		synchronized (consumers) {
			if (isClosed()) {
				return false;
			}

			if (consumers.contains(consumer)) {
				throw new IllegalArgumentException("Attempted to acquire the " +
					"domain object more than once by the same consumer: " + consumer);
			}
			consumers.add(consumer);
		}

		return true;
	}

	boolean hasConsumers() {
		synchronized (consumers) {
			return consumers.size() > 0;
		}
	}

	/**
	 * Returns true if the this file is used only by the given tool
	 */
	boolean isUsedExclusivelyBy(Object consumer) {
		synchronized (consumers) {
			return (consumers.size() == 1) && (consumers.contains(consumer));
		}
	}

	/**
	 * Returns true if the given tool is using this object.
	 */
	@Override
	public boolean isUsedBy(Object consumer) {
		synchronized (consumers) {
			return consumers.contains(consumer);
		}
	}

	@Override
	public ArrayList<Object> getConsumerList() {
		synchronized (consumers) {
			return new ArrayList<Object>(consumers);
		}
	}

	/**
	 * Set default content type
	 * @param doClass default domain object implementation
	 */
	public static synchronized void setDefaultContentClass(Class<?> doClass) {
		defaultDomainObjClass = doClass;
		if (contentHandlerTypeMap != null) {
			if (doClass == null) {
				contentHandlerTypeMap.remove(null);
			}
			else {
				ContentHandler ch = contentHandlerClassMap.get(doClass);
				if (ch != null) {
					contentHandlerTypeMap.put(null, ch);
				}
			}
		}
	}

	/**
	 * Get the ContentHandler associated with the specified content-type.
	 * @param contentType domain object content type
	 * @return content handler
	 */
	static synchronized ContentHandler getContentHandler(String contentType) throws IOException {
		checkContentHandlerMaps();
		ContentHandler ch = contentHandlerTypeMap.get(contentType);
		if (ch == null) {
			throw new IOException("Content handler not found for " + contentType);
		}
		return ch;
	}

	/**
	 * Get the ContentHandler associated with the specified domain object
	 * @param dobj domain object
	 * @return content handler
	 */
	public static synchronized ContentHandler getContentHandler(DomainObject dobj)
			throws IOException {
		checkContentHandlerMaps();
		ContentHandler ch = contentHandlerClassMap.get(dobj.getClass());
		if (ch == null) {
			throw new IOException("Content handler not found for " + dobj.getClass().getName());
		}
		return ch;
	}

	private static void checkContentHandlerMaps() {
		if (contentHandlerTypeMap != null) {
			return;
		}

		getContentHandlers();
		ClassSearcher.addChangeListener(contentHandlerUpdateListener);
	}

	private synchronized static void getContentHandlers() {
		contentHandlerClassMap = new HashMap<Class<?>, ContentHandler>();
		contentHandlerTypeMap = new HashMap<String, ContentHandler>();

		List<ContentHandler> handlers = ClassSearcher.getInstances(ContentHandler.class);
		for (ContentHandler ch : handlers) {
			String type = ch.getContentType();
			Class<?> DOClass = ch.getDomainObjectClass();
			if (type != null && DOClass != null) {
				contentHandlerClassMap.put(DOClass, ch);
				contentHandlerTypeMap.put(type, ch);
				continue;
			}
		}
		setDefaultContentClass(defaultDomainObjClass);
	}

	@Override
	public Map<String, String> getMetadata() {
		return metadata;
	}

	@Override
	public long getModificationNumber() {
		return modificationNumber;
	}

	protected void fatalErrorOccurred(Exception e) {
		docs.fatalErrorOccurred(e);
		for (DomainObjectChangeSupport queue : changeSupportMap.values()) {
			queue.fatalErrorOccurred(e);
		}
		throw new DomainObjectException(e);

	}

}
