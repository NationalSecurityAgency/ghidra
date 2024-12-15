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
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.datastruct.ListenerSet;

/**
 * An abstract class that provides default behavior for DomainObject(s), specifically it handles
 * listeners and change status; the derived class must provide the getDescription() method.
 */
public abstract class DomainObjectAdapter implements DomainObject {

	protected final static String DEFAULT_NAME = "untitled";

	private static HashMap<String, ContentHandler<?>> contentHandlerTypeMap; // maps content-type string to handler
	private static HashMap<Class<?>, ContentHandler<?>> contentHandlerClassMap; // maps domain object class to handler
	private static ChangeListener contentHandlerUpdateListener = new ChangeListener() {
		@Override
		public void stateChanged(ChangeEvent e) {
			initContentHandlerMaps();
		}
	};

	protected String name;
	private DomainFile domainFile;

	private DomainObjectChangeSupport docs;
	protected Map<EventQueueID, DomainObjectChangeSupport> changeSupportMap =
		new ConcurrentHashMap<EventQueueID, DomainObjectChangeSupport>();
	private volatile boolean eventsEnabled = true;

	private ListenerSet<DomainObjectClosedListener> closeListeners =
		new ListenerSet<>(DomainObjectClosedListener.class, false);
	private ListenerSet<DomainObjectFileListener> fileChangeListeners =
		new ListenerSet<>(DomainObjectFileListener.class, false);

	private ArrayList<Object> consumers;
	protected Map<String, String> metadata = new LinkedHashMap<String, String>();

	// FIXME: (see GP-2003) "changed" flag is improperly manipulated by various methods.  
	// In general, comitted transactions will trigger all valid cases of setting flag to true, 
	// there may be a few cases where setting it to false may be appropriate.  Without a transation 
	// it's unclear why it should ever need to get set true.

	// A flag indicating whether the domain object has changed.
	protected boolean changed = false;

	// a flag indicating that this object is temporary
	protected boolean temporary = false;
	protected Lock lock = new Lock("Domain Object");
	private long modificationNumber = 1;

	/**
	 * Construct a new DomainObjectAdapter. If construction of this object fails, be sure to release
	 * with consumer.
	 *
	 * @param name name of the object
	 * @param timeInterval the time (in milliseconds) to wait before the event queue is flushed. 
	 * 			If a new event comes in before the time expires the timer is reset.
	 * @param consumer the object that created this domain object
	 */
	protected DomainObjectAdapter(String name, int timeInterval, Object consumer) {
		Objects.requireNonNull(consumer, "Consumer must not be null");
		this.name = name;
		docs = new DomainObjectChangeSupport(this, timeInterval, lock);
		consumers = new ArrayList<Object>();
		consumers.add(consumer);
		if (!UserData.class.isAssignableFrom(getClass())) {
			domainFile = new DomainFileProxy(name, this);
		}
	}

	/**
	 * Invalidates any caching in a program and generate a {@link DomainObjectEvent#RESTORED}
	 * event. 
	 * NOTE: Over-using this method can adversely affect system performance.
	 */
	public void invalidate() {
		fireEvent(new DomainObjectChangeRecord(DomainObjectEvent.RESTORED));
	}

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

	@Override
	public DomainFile getDomainFile() {
		return domainFile;
	}

	/**
	 * Returns the hidden user-filesystem associated with this objects domain file, or null if
	 * unknown.
	 *
	 * @return user data file system
	 */
	protected FileSystem getAssociatedUserFilesystem() {
		if (domainFile instanceof GhidraFile) {
			return ((GhidraFile) domainFile).getUserFileSystem();
		}
		return null;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String toString() {
		String classname = getClass().getName();
		classname = classname.substring(classname.lastIndexOf('.'));
		return name + " - " + classname;
	}

	@Override
	public void setName(String newName) {
		synchronized (this) {
			if (name.equals(newName)) {
				return;
			}
			name = newName;
			changed = true;
		}
		fireEvent(new DomainObjectChangeRecord(DomainObjectEvent.RENAMED));
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

	@Override
	public boolean isChanged() {
		return changed && !temporary;
	}

	@Override
	public void setTemporary(boolean state) {
		temporary = state;
	}

	@Override
	public boolean isTemporary() {
		return temporary;
	}

	/**
	 * Set the {@link DomainFile} associated with this instance.
	 * @param df domain file
	 * @throws DomainObjectException if a severe failure occurs during the operation.
	 */
	protected void setDomainFile(DomainFile df) throws DomainObjectException {
		if (df == null) {
			throw new IllegalArgumentException("DomainFile must not be null");
		}
		if (df == domainFile) {
			return;
		}
		clearDomainObj();
		DomainFile oldDf = domainFile;
		domainFile = df;
		fireEvent(new DomainObjectChangeRecord(DomainObjectEvent.FILE_CHANGED, oldDf, df));
		fileChangeListeners.invoke().domainFileChanged(this);
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

		closeListeners.invoke().domainObjectClosed(this);
		closeListeners.clear();
	}

	@Override
	public void flushEvents() {
		docs.flush();
		for (DomainObjectChangeSupport queue : changeSupportMap.values()) {
			queue.flush();
		}
	}

	/**
	 * Return "changed" status
	 *
	 * @return true if this object has changed
	 */
	public boolean getChangeStatus() {
		return changed;
	}

	@Override
	public void addListener(DomainObjectListener l) {
		docs.addListener(l);
	}

	@Override
	public void removeListener(DomainObjectListener l) {
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
	public void addDomainFileListener(DomainObjectFileListener listener) {
		fileChangeListeners.add(listener);
	}

	@Override
	public void removeDomainFileListener(DomainObjectFileListener listener) {
		fileChangeListeners.remove(listener);
	}

	@Override
	public EventQueueID createPrivateEventQueue(DomainObjectListener listener, int maxDelay) {
		EventQueueID eventQueueID = new EventQueueID();
		DomainObjectChangeSupport queue = new DomainObjectChangeSupport(this, maxDelay, lock);
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

	@Override
	public abstract String getDescription();

	/**
	 * Fires the specified event.
	 *
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

	@Override
	public void setEventsEnabled(boolean v) {
		if (eventsEnabled != v) {
			eventsEnabled = v;
			if (eventsEnabled) {
				DomainObjectChangeRecord docr =
					new DomainObjectChangeRecord(DomainObjectEvent.RESTORED);
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

	@Override
	public boolean addConsumer(Object consumer) {
		Objects.requireNonNull(consumer, "Consumer must not be null");

		synchronized (consumers) {
			if (isClosed()) {
				return false;
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
	 * Returns true if the given consumer is using this object.
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
	 * Get the {@link ContentHandler} associated with the specified content-type.
	 *
	 * @param contentType domain object content type
	 * @return content handler
	 * @throws IOException if no content handler can be found
	 */
	public static synchronized ContentHandler<?> getContentHandler(String contentType)
			throws IOException {
		checkContentHandlerMaps();
		ContentHandler<?> ch = contentHandlerTypeMap.get(contentType);
		if (ch == null) {
			throw new IOException("Content handler not found for " + contentType);
		}
		return ch;
	}

	/**
	 * Get the {@link ContentHandler} associated with the specified domain object class
	 *
	 * @param dobjClass domain object class
	 * @return content handler
	 * @throws IOException if no content handler can be found
	 */
	public static synchronized ContentHandler<?> getContentHandler(
			Class<? extends DomainObject> dobjClass) throws IOException {
		checkContentHandlerMaps();
		ContentHandler<?> ch = contentHandlerClassMap.get(dobjClass);
		if (ch == null) {
			throw new IOException("Content handler not found for " + dobjClass.getName());
		}
		return ch;
	}

	/**
	 * Get the {@link ContentHandler} associated with the specified domain object
	 *
	 * @param dobj domain object
	 * @return content handler
	 * @throws IOException if no content handler can be found
	 */
	public static ContentHandler<?> getContentHandler(DomainObject dobj) throws IOException {
		return getContentHandler(dobj.getClass());
	}

	/**
	 * Get all {@link ContentHandler}s
	 * @return collection of content handlers
	 */
	public static Set<ContentHandler<?>> getContentHandlers() {
		checkContentHandlerMaps();
		return new HashSet<>(contentHandlerTypeMap.values());
	}

	private static void checkContentHandlerMaps() {
		if (contentHandlerTypeMap != null) {
			return;
		}

		initContentHandlerMaps();
		ClassSearcher.addChangeListener(contentHandlerUpdateListener);
	}

	private synchronized static void initContentHandlerMaps() {
		HashMap<Class<?>, ContentHandler<?>> classMap = new HashMap<>();
		HashMap<String, ContentHandler<?>> typeMap = new HashMap<>();

		@SuppressWarnings("rawtypes")
		List<ContentHandler> handlers = ClassSearcher.getInstances(ContentHandler.class);
		for (ContentHandler<?> ch : handlers) {
			String contentType = ch.getContentType();
			if (typeMap.put(contentType, ch) != null) {
				Msg.error(DomainObjectAdapter.class,
					"Multiple content handlers discovered for content type: " + contentType);
			}
			if (!(ch instanceof LinkHandler<?>)) {
				Class<? extends DomainObjectAdapter> contentClass = ch.getDomainObjectClass();
				if (classMap.put(contentClass, ch) != null) {
					Msg.error(DomainObjectAdapter.class,
						"Multiple content handlers discovered for content class: " +
							contentClass.getSimpleName());
				}
			}
		}

		contentHandlerClassMap = classMap;
		contentHandlerTypeMap = typeMap;
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
