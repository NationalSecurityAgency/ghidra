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
package ghidra.app.plugin.core.debug.gui.model;

import java.util.*;
import java.util.stream.Collectors;

import javax.swing.Icon;

import docking.widgets.tree.GTreeLazyNode;
import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.framework.model.*;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.TraceObjectBreakpointLocation;
import ghidra.trace.model.breakpoint.TraceObjectBreakpointSpec;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.iface.*;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.path.KeyPath.KeyComparator;
import ghidra.trace.util.TraceEvents;
import ghidra.util.HTMLUtilities;
import ghidra.util.LockHold;
import ghidra.util.datastruct.WeakValueHashMap;
import utilities.util.IDKeyed;

public class ObjectTreeModel implements DisplaysModified {
	public static final GIcon ICON_PENDING = new GIcon("icon.pending");

	class ListenerForChanges extends TraceDomainObjectListener
			implements DomainObjectClosedListener {
		public ListenerForChanges() {
			listenForUntyped(DomainObjectEvent.RESTORED, this::domainObjectRestored);
			listenFor(TraceEvents.OBJECT_CREATED, this::objectCreated);
			listenFor(TraceEvents.VALUE_CREATED, this::valueCreated);
			listenFor(TraceEvents.VALUE_DELETED, this::valueDeleted);
			listenFor(TraceEvents.VALUE_LIFESPAN_CHANGED, this::valueLifespanChanged);
		}

		@Override
		public void domainObjectClosed(DomainObject dobj) {
			setTrace(null);
		}

		public void domainObjectRestored(DomainObjectChangeRecord rec) {
			reloadSameTrace();
		}

		protected boolean isEventValue(TraceObjectValue value) {
			if (!value.getParent()
					.getSchema()
					.getInterfaces()
					.contains(TraceObjectEventScope.class)) {
				return false;
			}
			if (!TraceObjectEventScope.KEY_EVENT_THREAD.equals(value.getEntryKey())) {
				return false;
			}
			return true;
		}

		protected boolean isEnabledValue(TraceObjectValue value) {
			Set<Class<? extends TraceObjectInterface>> interfaces =
				value.getParent().getSchema().getInterfaces();
			if (!interfaces.contains(TraceObjectBreakpointSpec.class) &&
				!interfaces.contains(TraceObjectBreakpointLocation.class) &&
				!interfaces.contains(TraceObjectTogglable.class)) {
				return false;
			}
			if (!TraceObjectTogglable.KEY_ENABLED.equals(value.getEntryKey())) {
				return false;
			}
			return true;
		}

		private void objectCreated(TraceObject object) {
			if (object.isRoot()) {
				reload();
			}
		}

		private void valueCreated(TraceObjectValue value) {
			if (!value.getLifespan().intersects(span)) {
				return;
			}
			AbstractNode node = nodeCache.getByObject(value.getParent());
			if (node == null) {
				return;
			}
			if (isEventValue(value)) {
				refresh();
			}
			if (isEnabledValue(value)) {
				node.fireNodeChanged();
			}
			node.childCreated(value);
		}

		private void valueDeleted(TraceObjectValue value) {
			if (!value.getLifespan().intersects(span)) {
				return;
			}
			AbstractNode node = nodeCache.getByObject(value.getParent());
			if (node == null) {
				return;
			}
			if (isEventValue(value)) {
				refresh();
			}
			if (isEnabledValue(value)) {
				node.fireNodeChanged();
			}
			node.childDeleted(value);
		}

		private void valueLifespanChanged(TraceObjectValue value, Lifespan oldSpan,
				Lifespan newSpan) {
			boolean inOld = oldSpan.intersects(span);
			boolean inNew = newSpan.intersects(span);
			if (inOld == inNew) {
				return;
			}
			AbstractNode node = nodeCache.getByObject(value.getParent());
			if (node == null) {
				return;
			}
			if (isEventValue(value)) {
				refresh();
			}
			if (isEnabledValue(value)) {
				node.fireNodeChanged();
			}
			if (inNew) {
				node.childCreated(value);
			}
			else {
				node.childDeleted(value);
			}
		}
	}

	class NodeCache {
		Map<IDKeyed<TraceObjectValue>, AbstractNode> byValue = new WeakValueHashMap<>();
		Map<IDKeyed<TraceObject>, AbstractNode> byObject = new WeakValueHashMap<>();

		protected AbstractNode createNode(TraceObjectValue value) {
			if (value.isCanonical()) {
				return new CanonicalNode(value);
			}
			if (value.isObject()) {
				return new LinkNode(value);
			}
			return new PrimitiveNode(value);
		}

		protected AbstractNode getOrCreateNode(TraceObjectValue value) {
			if (value.getParent() == null) {
				root.unloadChildren();
				return root;
			}
			AbstractNode node =
				byValue.computeIfAbsent(new IDKeyed<>(value), k -> createNode(value));
			//node.unloadChildren();
			//AbstractNode node = createNode(value);
			if (value.isCanonical()) {
				byObject.put(new IDKeyed<>(value.getChild()), node);
			}
			return node;
		}

		protected AbstractNode getByValue(TraceObjectValue value) {
			return byValue.get(new IDKeyed<>(value));
		}

		protected AbstractNode getByObject(TraceObject object) {
			if (object.isRoot()) {
				return root;
			}
			return byObject.get(new IDKeyed<>(object));
		}

		public void invalidate() {
			byObject.clear();
			byValue.clear();
		}
	}

	public static class PendingNode extends GTreeLazyNode {
		@Override
		public String getName() {
			return ""; // Want it sorted to the front
		}

		@Override
		public String getDisplayText() {
			return "Refreshing...";
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return ICON_PENDING;
		}

		@Override
		public boolean isLeaf() {
			return true;
		}

		@Override
		protected List<GTreeNode> generateChildren() {
			return List.of();
		}

		@Override
		public String getToolTip() {
			return null;
		}
	}

	public abstract class AbstractNode extends GTreeLazyNode {
		public abstract TraceObjectValue getValue();

		public synchronized void addNodeSorted(AbstractNode node) {
			int i = Collections.binarySearch(getChildren(), node);
			if (i >= 0) {
				throw new AssertionError("Duplicate node name: " + node.getName());
			}
			i = -i - 1;
			addNode(i, node);
		}

		@Override
		public void dispose() {
			/**
			 * Our nodes are re-usable. They're cached so that as an item comes and goes, its
			 * corresponding node can also come and go without being re-instantiated each time.
			 * Furthermore, it's likely to have all the same children as before, too. For now, we'll
			 * just ignore dispose. If there's too many unexpected behaviors resulting from this,
			 * then perhaps we should just have dispose also remove itself from the node cache.
			 */
			// DO NOTHING
		}

		@Override
		public int compareTo(GTreeNode node) {
			if (!(node instanceof AbstractNode that)) {
				return -1;
			}
			int c;
			c = KeyComparator.CHILD.compare(this.getValue().getEntryKey(),
				that.getValue().getEntryKey());
			if (c != 0) {
				return c;
			}
			c = Lifespan.DOMAIN.compare(this.getValue().getMinSnap(), that.getValue().getMinSnap());
			if (c != 0) {
				return c;
			}
			return 0;
		}

		@Override
		public String getName() {
			return getValue().getEntryKey() + "@" + System.identityHashCode(getValue());
		}

		@Override
		public abstract String getDisplayText();

		protected void childCreated(TraceObjectValue value) {
			if (getParent() == null || !isLoaded()) {
				return;
			}
			if (isValueVisible(value)) {
				AbstractNode child = nodeCache.getOrCreateNode(value);
				addNodeSorted(child);
			}
		}

		protected void childDeleted(TraceObjectValue value) {
			if (getParent() == null || !isLoaded()) {
				return;
			}
			AbstractNode child = nodeCache.getByValue(value);
			if (child != null) {
				removeNode(child);
			}
		}

		protected AbstractNode getNode(KeyPath p, int pos) {
			if (pos >= p.size()) {
				return this;
			}
			String key = p.key(pos);
			AbstractNode matched = children().stream()
					.map(c -> (AbstractNode) c)
					.filter(c -> key.equals(c.getValue().getEntryKey()))
					.findFirst()
					.orElse(null);
			if (matched == null) {
				return null;
			}
			return matched.getNode(p, pos + 1);
		}

		public AbstractNode getNode(KeyPath p) {
			return getNode(p, 0);
		}

		protected boolean isModified() {
			return isValueModified(getValue());
		}

		protected synchronized void reloadChildrenNow() {
			if (!isLoaded()) {
				return;
			}
			// Use a merge to effect the minimal changes to set the children
			var current = List.copyOf(children());
			var generated = generateChildren();
			// NB. The two lists ought to be sorted already.
			int ic = 0;
			int ig = 0;
			int diff = 0;
			while (ic < current.size() && ig < generated.size()) {
				GTreeNode nc = current.get(ic);
				GTreeNode ng = generated.get(ig);
				int comp = nc.compareTo(ng);
				if (comp == 0) {
					ic++;
					ig++;
				}
				else if (comp < 0) {
					removeNode(nc);
					diff--;
					ic++;
				}
				else { // comp > 0
					addNode(ic + diff, ng);
					diff++;
					ig++;
				}
			}
			while (ic < current.size()) {
				GTreeNode nc = current.get(ic);
				removeNode(nc);
				// diff--; // Not really needed
				ic++;
			}
			while (ig < generated.size()) {
				GTreeNode ng = generated.get(ig);
				addNode(ic + diff, ng);
				diff++;
				ig++;
			}
		}
	}

	public class RootNode extends AbstractNode {
		@Override
		public TraceObjectValue getValue() {
			if (trace == null) {
				return null;
			}
			TraceObject root = trace.getObjectManager().getRootObject();
			if (root == null) {
				return null;
			}
			return root.getCanonicalParent(0);
		}

		@Override
		public String getName() {
			return "<Root>";
		}

		@Override
		public String getDisplayText() {
			if (trace == null) {
				return "<html><em>No&nbsp;trace&nbsp;is&nbsp;active</em>";
			}
			TraceObject root = trace.getObjectManager().getRootObject();
			if (root == null) {
				return "<html><em>Trace&nbsp;has&nbsp;no&nbsp;model</em>";
			}
			return "<html>" + HTMLUtilities
					.escapeHTML(display.getObjectDisplay(root.getCanonicalParent(0)), true);
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return DebuggerResources.ICON_DEBUGGER; // TODO
		}

		@Override
		public String getToolTip() {
			if (trace == null) {
				return "No trace is active";
			}
			TraceObject root = trace.getObjectManager().getRootObject();
			if (root == null) {
				return "Trace has no model";
			}
			return display.getObjectToolTip(root.getCanonicalParent(0));
		}

		@Override
		public boolean isLeaf() {
			return false;
		}

		@Override
		protected List<GTreeNode> generateChildren() {
			if (trace == null) {
				return List.of();
			}
			TraceObject root = trace.getObjectManager().getRootObject();
			if (root == null) {
				return List.of();
			}
			return generateObjectChildren(root);
		}

		@Override
		protected boolean isModified() {
			return false;
		}

		@Override
		protected void childCreated(TraceObjectValue value) {
			if (!isValueVisible(value)) {
				return;
			}
			if (nodeCache.getByValue(value) != null) {
				super.childCreated(value);
				return;
			}
			try (KeepTreeState keep = KeepTreeState.ifNotNull(getTree())) {
				unloadChildren();
			}
		}
	}

	public class PrimitiveNode extends AbstractNode {
		protected final TraceObjectValue value;

		public PrimitiveNode(TraceObjectValue value) {
			this.value = value;
		}

		@Override
		public TraceObjectValue getValue() {
			return value;
		}

		@Override
		protected List<GTreeNode> generateChildren() {
			return List.of();
		}

		@Override
		public String getDisplayText() {
			String html = HTMLUtilities.escapeHTML(
				value.getEntryKey() + ": " + display.getPrimitiveValueDisplay(value.getValue()),
				true);
			return "<html>" + html;
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return DebuggerResources.ICON_OBJECT_UNPOPULATED;
		}

		@Override
		public String getToolTip() {
			return display.getPrimitiveEdgeToolTip(value);
		}

		@Override
		public boolean isLeaf() {
			return true;
		}
	}

	public abstract class AbstractObjectNode extends AbstractNode {
		protected final TraceObjectValue value;
		protected final TraceObject object;

		public AbstractObjectNode(TraceObjectValue value) {
			this.value = value;
			this.object = Objects.requireNonNull(value.getChild());
		}

		@Override
		public TraceObjectValue getValue() {
			return value;
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return getObjectIcon(value, expanded);
		}
	}

	public class LinkNode extends AbstractObjectNode {
		public LinkNode(TraceObjectValue value) {
			super(value);
		}

		@Override
		public String getDisplayText() {
			return "<html>" + HTMLUtilities.escapeHTML(value.getEntryKey(), true) + ":&nbsp;<em>" +
				HTMLUtilities.escapeHTML(display.getObjectLinkDisplay(value), true) + "</em>";
		}

		@Override
		public String getToolTip() {
			return display.getObjectLinkToolTip(value);
		}

		@Override
		public boolean isLeaf() {
			return true;
		}

		@Override
		protected List<GTreeNode> generateChildren() {
			return List.of();
		}

		@Override
		protected void childCreated(TraceObjectValue value) {
			throw new AssertionError();
		}

		@Override
		protected void childDeleted(TraceObjectValue value) {
			throw new AssertionError();
		}
	}

	public class CanonicalNode extends AbstractObjectNode {
		public CanonicalNode(TraceObjectValue value) {
			super(value);
		}

		@Override
		protected List<GTreeNode> generateChildren() {
			return generateObjectChildren(object);
		}

		@Override
		public String getDisplayText() {
			return "<html>" + HTMLUtilities.escapeHTML(display.getObjectDisplay(value), true);
		}

		@Override
		public String getToolTip() {
			return display.getObjectToolTip(value);
		}

		@Override
		public Icon getIcon(boolean expanded) {
			TraceObjectValue parentValue = object.getCanonicalParent(snap);
			if (parentValue == null) {
				return super.getIcon(expanded);
			}
			if (!parentValue.getParent().getSchema().isCanonicalContainer()) {
				return super.getIcon(expanded);
			}
			if (!isOnEventPath(object)) {
				return super.getIcon(expanded);
			}
			return DebuggerResources.ICON_EVENT_MARKER;
		}

		@Override
		public boolean isLeaf() {
			return false;
		}
	}

	interface LastKeyDisplaysObjectValues extends DisplaysObjectValues {
		@Override
		default String getRawObjectDisplay(TraceObjectValue edge) {
			TraceObject object = edge.getChild();
			if (object.isRoot()) {
				return "Root";
			}
			if (edge.isCanonical()) {
				return edge.getEntryKey();
			}
			return object.getCanonicalPath().toString();
		}
	}

	protected class TreeDisplaysObjectValues implements LastKeyDisplaysObjectValues {
		@Override
		public long getSnap() {
			return snap;
		}
	}

	protected class DiffTreeDisplaysObjectValues implements LastKeyDisplaysObjectValues {
		@Override
		public long getSnap() {
			return diffSnap;
		}
	}

	private Trace trace;
	private long snap;
	private Trace diffTrace;
	private long diffSnap;
	private Lifespan span = Lifespan.ALL;
	private boolean showHidden;
	private boolean showPrimitives;
	private boolean showMethods;

	private final RootNode root = new RootNode();
	private final NodeCache nodeCache = new NodeCache();

	// TODO: User-modifiable?
	// TODO: Load and save this. Options panel? Defaults for GDB/dbgeng?
	private Map<String, Icon> icons = fillIconMap(new HashMap<>());

	private final ListenerForChanges listenerForChanges = newListenerForChanges();
	protected final DisplaysObjectValues display = new TreeDisplaysObjectValues();
	protected final DisplaysObjectValues diffDisplay = new DiffTreeDisplaysObjectValues();

	protected ListenerForChanges newListenerForChanges() {
		return new ListenerForChanges();
	}

	protected Map<String, Icon> fillIconMap(Map<String, Icon> map) {
		map.put("Process", DebuggerResources.ICON_PROCESS);
		map.put("Thread", DebuggerResources.ICON_THREAD);
		map.put("Memory", DebuggerResources.ICON_REGIONS);
		map.put("Interpreter", DebuggerResources.ICON_CONSOLE);
		map.put("Console", DebuggerResources.ICON_CONSOLE);
		map.put("Stack", DebuggerResources.ICON_PROVIDER_STACK);
		// TODO: StackFrame
		map.put("BreakpointContainer", DebuggerResources.ICON_BREAKPOINTS);
		map.put("BreakpointLocationContainer", DebuggerResources.ICON_BREAKPOINTS);
		// NOTE: Breakpoints done dynamically for enabled/disabled.
		map.put("RegisterContainer", DebuggerResources.ICON_REGISTERS);
		// TODO: Register
		map.put("ModuleContainer", DebuggerResources.ICON_MODULES);
		// TODO: single module / section
		return map;
	}

	protected TraceObject getEventObject(TraceObject object) {
		TraceObject scope = object
				.findCanonicalAncestorsInterface(TraceObjectEventScope.class)
				.findFirst()
				.orElse(null);
		if (scope == null) {
			return null;
		}
		if (scope == object) {
			return null;
		}
		TraceObjectValue eventValue =
			scope.getAttribute(snap, TraceObjectEventScope.KEY_EVENT_THREAD);
		if (eventValue == null || !eventValue.isObject()) {
			return null;
		}
		return eventValue.getChild();
	}

	protected boolean isOnEventPath(TraceObject object) {
		TraceObject eventObject = getEventObject(object);
		if (eventObject == null) {
			return false;
		}
		if (object.getCanonicalPath().isAncestor(eventObject.getCanonicalPath())) {
			return true;
		}
		return false;
	}

	protected Icon getObjectIcon(TraceObjectValue edge, boolean expanded) {
		String type = display.getObjectType(edge);
		Icon forType = icons.get(type);
		if (forType != null) {
			return forType;
		}
		if (type.contains("Breakpoint")) {
			TraceObject object = edge.getChild();
			TraceObjectValue en =
				object.getAttribute(snap, TraceObjectTogglable.KEY_ENABLED);
			// includes true or non-boolean values
			if (en == null || !Objects.equals(false, en.getValue())) {
				return DebuggerResources.ICON_SET_BREAKPOINT;
			}
			return DebuggerResources.ICON_DISABLE_BREAKPOINT;
		}
		return DebuggerResources.ICON_OBJECT_POPULATED;
		/*
		 * TODO?: Populated/unpopulated? Seems to duplicate isLeaf. The absence/presence of an
		 * expander should already communicate this info.... We could instead use icon to indicate
		 * freshness, but how would we know? The sync mode from the schema might help.
		 */
	}

	protected boolean isValueVisible(TraceObjectValue value) {
		if (!showHidden && value.isHidden()) {
			return false;
		}
		if (!showPrimitives && !value.isObject()) {
			return false;
		}
		if (!showMethods && value.isObject() && value.getChild().isMethod(snap)) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isEdgesDiffer(TraceObjectValue newEdge, TraceObjectValue oldEdge) {
		if (DisplaysModified.super.isEdgesDiffer(newEdge, oldEdge)) {
			return true;
		}
		// Hack to incorporate _display logic to differencing.
		// This ensures "boxed" primitives show as differing at the object level
		return !Objects.equals(diffDisplay.getEdgeDisplay(oldEdge),
			display.getEdgeDisplay(newEdge));
	}

	protected List<GTreeNode> generateObjectChildren(TraceObject object) {
		List<GTreeNode> result = ObjectTableModel
				.distinctCanonical(object.getValues(span).stream().filter(this::isValueVisible))
				.map(v -> nodeCache.getOrCreateNode(v))
				.sorted()
				.collect(Collectors.toList());
		return result;
	}

	public GTreeLazyNode getRoot() {
		return root;
	}

	protected void removeOldListeners() {
		if (trace != null) {
			trace.removeListener(listenerForChanges);
			trace.removeCloseListener(listenerForChanges);
		}
	}

	protected void addNewListeners() {
		if (trace != null) {
			trace.addListener(listenerForChanges);
			trace.addCloseListener(listenerForChanges);
		}
	}

	protected void refresh() {
		for (AbstractNode node : nodeCache.byObject.values()) {
			node.fireNodeChanged();
		}
		root.fireNodeChanged();
	}

	protected void reload() {
		nodeCache.invalidate();
		root.unloadChildren();
	}

	protected void reloadSameTrace() {
		try (LockHold hold = trace == null ? null : trace.lockRead()) {
			for (AbstractNode node : List.copyOf(nodeCache.byObject.values())) {
				node.reloadChildrenNow();
				node.fireNodeChanged();
			}
			root.reloadChildrenNow();
			root.fireNodeChanged();
		}
	}

	public void setTrace(Trace trace) {
		if (this.trace == trace) {
			return;
		}
		removeOldListeners();
		this.trace = trace;
		addNewListeners();
		traceChanged();
	}

	protected void traceChanged() {
		reload();
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	protected void snapChanged() {
		// Span will be set to singleton by client, if desired
		refresh();
	}

	public void setSnap(long snap) {
		if (this.snap == snap) {
			return;
		}
		this.snap = snap;
		snapChanged();
	}

	@Override
	public long getSnap() {
		return snap;
	}

	protected void diffTraceChanged() {
		refresh();
	}

	/**
	 * Set alternative trace to colorize values that differ
	 * 
	 * <p>
	 * The same trace can be used, but with an alternative snap, if desired. See
	 * {@link #setDiffSnap(long)}. One common use is to compare with the previous snap of the same
	 * trace. Another common use is to compare with the previous navigation.
	 * 
	 * @param diffTrace the alternative trace
	 */
	public void setDiffTrace(Trace diffTrace) {
		if (this.diffTrace == diffTrace) {
			return;
		}
		this.diffTrace = diffTrace;
		diffTraceChanged();
	}

	@Override
	public Trace getDiffTrace() {
		return diffTrace;
	}

	protected void diffSnapChanged() {
		refresh();
	}

	/**
	 * Set alternative snap to colorize values that differ
	 * 
	 * <p>
	 * The diff trace must be set, even if it's the same as the trace being displayed. See
	 * {@link #setDiffTrace(Trace)}.
	 * 
	 * @param diffSnap the alternative snap
	 */
	public void setDiffSnap(long diffSnap) {
		if (this.diffSnap == diffSnap) {
			return;
		}
		this.diffSnap = diffSnap;
		diffSnapChanged();
	}

	@Override
	public long getDiffSnap() {
		return diffSnap;
	}

	protected void spanChanged() {
		reloadSameTrace();
	}

	public void setSpan(Lifespan span) {
		if (Objects.equals(this.span, span)) {
			return;
		}
		this.span = span;
		spanChanged();
	}

	public Lifespan getSpan() {
		return span;
	}

	protected void showHiddenChanged() {
		reloadSameTrace();
	}

	public void setShowHidden(boolean showHidden) {
		if (this.showHidden == showHidden) {
			return;
		}
		this.showHidden = showHidden;
		showHiddenChanged();
	}

	public boolean isShowHidden() {
		return showHidden;
	}

	protected void showPrimitivesChanged() {
		reloadSameTrace();
	}

	public void setShowPrimitives(boolean showPrimitives) {
		if (this.showPrimitives == showPrimitives) {
			return;
		}
		this.showPrimitives = showPrimitives;
		showPrimitivesChanged();
	}

	public boolean isShowPrimitives() {
		return showPrimitives;
	}

	protected void showMethodsChanged() {
		reloadSameTrace();
	}

	public void setShowMethods(boolean showMethods) {
		if (this.showMethods == showMethods) {
			return;
		}
		this.showMethods = showMethods;
		showMethodsChanged();
	}

	public boolean isShowMethods() {
		return showMethods;
	}

	public AbstractNode getNode(KeyPath p) {
		return root.getNode(p);
	}
}
