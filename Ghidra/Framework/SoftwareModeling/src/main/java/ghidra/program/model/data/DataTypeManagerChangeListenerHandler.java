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
package ghidra.program.model.data;

import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

import java.io.IOException;
import java.io.ObjectInputStream;

import javax.swing.SwingUtilities;

/**
 *
 * Default implementation for a category change listener that sends out the
 * events to its own list of category change listeners.
 *  
 */
public class DataTypeManagerChangeListenerHandler implements DataTypeManagerChangeListener {

	private transient WeakSet<DataTypeManagerChangeListener> listenerList =
		WeakDataStructureFactory.createCopyOnReadWeakSet();

	/**
	 * Add the given category change listener.
	 * @param l the listener to be added.
	 */
	public void addDataTypeManagerListener(DataTypeManagerChangeListener l) {
		listenerList.add(l);
	}

	/**
	 * Remove the category change listener.
	 * @param l the listener to be removed.
	 */
	public void removeDataTypeManagerListener(DataTypeManagerChangeListener l) {
		listenerList.remove(l);
	}

	@Override
	public void categoryAdded(final DataTypeManager dtm, final CategoryPath path) {
		if (listenerList.isEmpty()) {
			return;
		}
		Runnable r = new Runnable() {
			@Override
			public void run() {
				for (DataTypeManagerChangeListener listener : listenerList) {
					listener.categoryAdded(dtm, path);
				}
			}
		};
		invokeRunnable(r);
	}

	@Override
	public void categoryMoved(final DataTypeManager dtm, final CategoryPath oldPath,
			final CategoryPath newPath) {
		if (listenerList.isEmpty()) {
			return;
		}
		Runnable r = new Runnable() {
			@Override
			public void run() {
				for (DataTypeManagerChangeListener listener : listenerList) {
					listener.categoryMoved(dtm, oldPath, newPath);
				}
			}
		};
		invokeRunnable(r);
	}

	@Override
	public void categoryRemoved(final DataTypeManager dtm, final CategoryPath path) {
		if (listenerList.isEmpty()) {
			return;
		}
		Runnable r = new Runnable() {
			@Override
			public void run() {
				for (DataTypeManagerChangeListener listener : listenerList) {
					listener.categoryRemoved(dtm, path);
				}
			}
		};
		invokeRunnable(r);
	}

	@Override
	public void categoryRenamed(final DataTypeManager dtm, final CategoryPath oldPath,
			final CategoryPath newPath) {

		if (listenerList.isEmpty()) {
			return;
		}
		Runnable r = new Runnable() {
			@Override
			public void run() {
				for (DataTypeManagerChangeListener listener : listenerList) {
					listener.categoryRenamed(dtm, oldPath, newPath);
				}
			}
		};
		invokeRunnable(r);
	}

	@Override
	public void dataTypeAdded(final DataTypeManager dtm, final DataTypePath path) {

		if (listenerList.isEmpty()) {
			return;
		}
		Runnable r = new Runnable() {
			@Override
			public void run() {
				for (DataTypeManagerChangeListener listener : listenerList) {
					listener.dataTypeAdded(dtm, path);
				}
			}
		};
		invokeRunnable(r);
	}

	@Override
	public void dataTypeChanged(final DataTypeManager dtm, final DataTypePath path) {

		if (listenerList.isEmpty()) {
			return;
		}
		Runnable r = new Runnable() {
			@Override
			public void run() {
				for (DataTypeManagerChangeListener listener : listenerList) {
					listener.dataTypeChanged(dtm, path);
				}
			}
		};
		invokeRunnable(r);
	}

	@Override
	public void dataTypeMoved(final DataTypeManager dtm, final DataTypePath oldPath,
			final DataTypePath newPath) {

		if (listenerList.isEmpty()) {
			return;
		}
		Runnable r = new Runnable() {
			@Override
			public void run() {
				for (DataTypeManagerChangeListener listener : listenerList) {
					listener.dataTypeMoved(dtm, oldPath, newPath);
				}
			}
		};
		invokeRunnable(r);
	}

	@Override
	public void dataTypeRemoved(final DataTypeManager dtm, final DataTypePath path) {

		if (listenerList.isEmpty()) {
			return;
		}
		Runnable r = new Runnable() {
			@Override
			public void run() {
				for (DataTypeManagerChangeListener listener : listenerList) {
					listener.dataTypeRemoved(dtm, path);
				}
			}
		};
		invokeRunnable(r);
	}

	@Override
	public void dataTypeRenamed(final DataTypeManager dtm, final DataTypePath oldPath,
			final DataTypePath newPath) {

		if (listenerList.isEmpty()) {
			return;
		}
		Runnable r = new Runnable() {
			@Override
			public void run() {
				for (DataTypeManagerChangeListener listener : listenerList) {
					listener.dataTypeRenamed(dtm, oldPath, newPath);
					listener.favoritesChanged(dtm, oldPath, false);
				}
			}
		};
		invokeRunnable(r);
	}

	private void readObject(ObjectInputStream ois) throws ClassNotFoundException, IOException {
		ois.defaultReadObject();
		listenerList = WeakDataStructureFactory.createCopyOnReadWeakSet();
	}

	private void invokeRunnable(Runnable r) {
//		if (SwingUtilities.isEventDispatchThread()) {
//			r.run();
//		}
//		else {
		SwingUtilities.invokeLater(r);
//		}
	}

	@Override
	public void dataTypeReplaced(final DataTypeManager dtm, final DataTypePath oldPath,
			final DataTypePath newPath, final DataType newDataType) {

		if (listenerList.isEmpty()) {
			return;
		}
		Runnable r = new Runnable() {
			@Override
			public void run() {
				for (DataTypeManagerChangeListener listener : listenerList) {
					listener.dataTypeReplaced(dtm, oldPath, newPath, newDataType);
				}
			}
		};
		invokeRunnable(r);
	}

	@Override
	public void favoritesChanged(final DataTypeManager dtm, final DataTypePath path,
			final boolean isFavorite) {
		if (listenerList.isEmpty()) {
			return;
		}
		Runnable r = new Runnable() {
			@Override
			public void run() {
				for (DataTypeManagerChangeListener listener : listenerList) {
					listener.favoritesChanged(dtm, path, isFavorite);
				}
			}
		};
		invokeRunnable(r);
	}

	@Override
	public void sourceArchiveChanged(final DataTypeManager dataTypeManager,
			final SourceArchive dataTypeSource) {

		if (listenerList.isEmpty()) {
			return;
		}
		Runnable r = new Runnable() {
			@Override
			public void run() {
				for (DataTypeManagerChangeListener listener : listenerList) {
					listener.sourceArchiveChanged(dataTypeManager, dataTypeSource);
				}
			}
		};
		invokeRunnable(r);
	}

	@Override
	public void sourceArchiveAdded(final DataTypeManager dataTypeManager,
			final SourceArchive dataTypeSource) {

		if (listenerList.isEmpty()) {
			return;
		}
		Runnable r = new Runnable() {
			@Override
			public void run() {
				for (DataTypeManagerChangeListener listener : listenerList) {
					listener.sourceArchiveAdded(dataTypeManager, dataTypeSource);
				}
			}
		};
		invokeRunnable(r);
	}
}
