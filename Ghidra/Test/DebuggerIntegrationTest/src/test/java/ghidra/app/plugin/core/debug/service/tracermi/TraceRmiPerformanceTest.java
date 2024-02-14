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
package ghidra.app.plugin.core.debug.service.tracermi;

import static org.junit.Assert.assertEquals;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.Ignore;
import org.junit.Test;

import db.*;
import generic.Unique;
import generic.test.rule.Repeated;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerIntegrationTest;
import ghidra.app.services.TraceRmiService;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.debug.api.tracermi.TraceRmiAcceptor;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.rmi.trace.TraceRmi.*;
import ghidra.rmi.trace.TraceRmi.Compiler;
import ghidra.rmi.trace.TraceRmi.RootMessage.MsgCase;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.util.LockHold;
import ghidra.util.Msg;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.database.spatial.RStarTreeMapTest.IntRect;
import ghidra.util.database.spatial.RStarTreeMapTest.MyDomainObject;
import ghidra.util.task.TaskMonitor;

@Ignore // Only want for manual testing
public class TraceRmiPerformanceTest extends AbstractGhidraHeadedDebuggerIntegrationTest {
	public static final int REGION_COUNT = 1000;
	public static final int RECORD_COUNT = 1000 * 6;

	interface Tx extends AutoCloseable {
	}

	interface TraceHandle extends AutoCloseable {
		Trace getTrace() throws Throwable;

		Tx startTx() throws Throwable;

		default void addLotsOfRegions() throws Throwable {
			try (Tx tx = startTx()) {
				AddressFactory af = getTrace().getBaseAddressFactory();
				AddressSpace space = af.getDefaultAddressSpace();
				for (int i = 0; i < REGION_COUNT; i++) {
					AddressRange range = new AddressRangeImpl(space.getAddress(i * 1024), 1024);
					addRegion(Integer.toString(i), range, "rw");
				}
			}
		}

		void addRegion(String key, AddressRange range, String perms) throws Throwable;
	}

	interface TraceMaker {
		TraceHandle createTrace() throws Throwable;
	}

	static class ApiTx implements Tx {
		private final Transaction tx;

		private ApiTx(Transaction tx) {
			this.tx = tx;
		}

		@Override
		public void close() throws Exception {
			tx.close();
		}
	}

	static class ApiTraceHandle implements TraceHandle {
		private final ToyDBTraceBuilder tb;

		public ApiTraceHandle(ToyDBTraceBuilder tb) {
			this.tb = tb;
		}

		@Override
		public Trace getTrace() throws Throwable {
			return tb.trace;
		}

		@Override
		public Tx startTx() throws Throwable {
			return new ApiTx(tb.trace.openTransaction("Test"));
		}

		@Override
		public void addRegion(String key, AddressRange range, String perms) {
			DBTraceObject region = tb.trace.getObjectManager()
					.createObject(TraceObjectKeyPath.parse("Processes[0].Memory[" + key + "]"));
			region.setValue(Lifespan.nowOn(0), "Range", range);
			region.setValue(Lifespan.nowOn(0), "R", perms.contains("r"));
			region.setValue(Lifespan.nowOn(0), "W", perms.contains("w"));
			region.setValue(Lifespan.nowOn(0), "X", perms.contains("x"));
			region.insert(Lifespan.nowOn(0), ConflictResolution.ADJUST);
		}

		@Override
		public void close() throws Exception {
			tb.close();
		}
	}

	class ApiTraceMaker implements TraceMaker {
		@Override
		public TraceHandle createTrace() throws Throwable {
			tb = new ToyDBTraceBuilder(name.getMethodName(), LANGID_TOYBE64);
			try (Transaction tx = tb.startTransaction()) {
				tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			}
			return new ApiTraceHandle(tb);
		}
	}

	static class RmiTraceHandle implements TraceHandle {
		private static final int RESULT_COUNT = REGION_COUNT * 6 + 2;
		private final TraceRmiConnection connection;
		private final Socket client;

		private final List<CompletableFuture<?>> results = new ArrayList<>(RESULT_COUNT * 5);
		private final OutputStream out;
		private final InputStream in;
		private final ExecutorService receiver = Executors.newSingleThreadExecutor();

		private int seq = 1;
		private int txid = 1000;

		public RmiTraceHandle(TraceRmiConnection connection, Socket client) throws IOException {
			this.connection = connection;
			this.client = client;
			this.out = client.getOutputStream();
			this.in = client.getInputStream();
		}

		private CompletableFuture<RootMessage> receive() {
			return CompletableFuture.supplyAsync(() -> {
				try {
					return TraceRmiHandler.recvDelimited(in);
				}
				catch (IOException e) {
					return ExceptionUtils.rethrow(e);
				}
			}, receiver);
		}

		private CompletableFuture<RootMessage> request(RootMessage msg) throws IOException {
			TraceRmiHandler.sendDelimited(out, msg, seq++);
			return receive();
		}

		private static void assertMsgCase(MsgCase expected, RootMessage msg) {
			if (msg.getMsgCase() == MsgCase.ERROR) {
				throw new AssertionError("Got RMI error: " + msg.getError().getMessage());
			}
			assertEquals(expected, msg.getMsgCase());
		}

		private CompletableFuture<Void> finishNegotiate() {
			return receive().thenAccept(reply -> {
				assertMsgCase(MsgCase.REPLY_NEGOTIATE, reply);
			});
		}

		class RmiTx implements Tx {
			private final TxId txid;

			public RmiTx(TxId txid) {
				this.txid = txid;
			}

			@Override
			public void close() throws Exception {
				results.add(doEndTx(txid));

				assertEquals(RESULT_COUNT, results.size());
				for (CompletableFuture<?> r : results) {
					r.get(1000, TimeUnit.MILLISECONDS);
				}
			}
		}

		protected TxId nextTx() {
			return TxId.newBuilder().setId(txid).build();
		}

		protected CompletableFuture<Void> doStartTx(TxId txid) throws IOException {
			RootMessage msg = RootMessage.newBuilder()
					.setRequestStartTx(RequestStartTx.newBuilder()
							.setDescription("Test")
							.setOid(DomObjId.newBuilder().setId(0))
							.setTxid(txid))
					.build();
			return request(msg).thenAccept(reply -> {
				assertMsgCase(MsgCase.REPLY_START_TX, reply);
			});
		}

		protected CompletableFuture<Void> doEndTx(TxId txid) throws IOException {
			RootMessage msg = RootMessage.newBuilder()
					.setRequestEndTx(RequestEndTx.newBuilder()
							.setAbort(false)
							.setOid(DomObjId.newBuilder().setId(0))
							.setTxid(txid))
					.build();
			return request(msg).thenAccept(reply -> {
				assertMsgCase(MsgCase.REPLY_END_TX, reply);
			});
		}

		@Override
		public Tx startTx() throws Throwable {
			TxId txid = nextTx();
			results.add(doStartTx(txid));
			return new RmiTx(txid);
		}

		private CompletableFuture<Void> createTrace(String name) throws IOException {
			RootMessage msg = RootMessage.newBuilder()
					.setRequestCreateTrace(RequestCreateTrace.newBuilder()
							.setPath(FilePath.newBuilder().setPath("Test/" + name))
							.setLanguage(Language.newBuilder().setId(LANGID_TOYBE64))
							.setCompiler(Compiler.newBuilder().setId("default"))
							.setOid(DomObjId.newBuilder().setId(0)))
					.build();
			return request(msg).thenAccept(reply -> {
				assertMsgCase(MsgCase.REPLY_CREATE_TRACE, reply);
			});
		}

		private CompletableFuture<Void> createRootObject() throws IOException {
			RootMessage msg = RootMessage.newBuilder()
					.setRequestCreateRootObject(RequestCreateRootObject.newBuilder()
							.setOid(DomObjId.newBuilder().setId(0))
							.setSchemaContext(XmlSchemaContext.serialize(SCHEMA_CTX))
							.setRootSchema(SCHEMA_SESSION.getName().toString()))
					.build();
			return request(msg).thenAccept(reply -> {
				assertMsgCase(MsgCase.REPLY_CREATE_OBJECT, reply);
			});
		}

		private CompletableFuture<Void> requestSetValue(DomObjId oid, ObjPath path,
				Lifespan lifespan, String key, Object value) throws IOException {
			RootMessage msg = RootMessage.newBuilder()
					.setRequestSetValue(RequestSetValue.newBuilder()
							.setOid(oid)
							.setValue(ValSpec.newBuilder()
									.setParent(ObjSpec.newBuilder()
											.setPath(path))
									.setKey(key)
									.setSpan(TraceRmiHandler.makeSpan(lifespan))
									.setValue(TraceRmiHandler.makeValue(value)))
							.setResolution(Resolution.CR_ADJUST))
					.build();
			return request(msg).thenAccept(reply -> {
				assertMsgCase(MsgCase.REPLY_SET_VALUE, reply);
			});
		}

		@Override
		public void addRegion(String key, AddressRange range, String perms) throws IOException {
			DomObjId oid0 = DomObjId.newBuilder().setId(0).build();
			ObjPath path = ObjPath.newBuilder().setPath("Processes[0].Memory[" + key + "]").build();
			RootMessage msgCreate = RootMessage.newBuilder()
					.setRequestCreateObject(RequestCreateObject.newBuilder()
							.setOid(oid0)
							.setPath(path))
					.build();
			results.add(request(msgCreate).thenAccept(reply -> {
				assertMsgCase(MsgCase.REPLY_CREATE_OBJECT, reply);
			}));

			results.add(requestSetValue(oid0, path, Lifespan.nowOn(0), "Range", range));
			results.add(requestSetValue(oid0, path, Lifespan.nowOn(0), "R", perms.contains("r")));
			results.add(requestSetValue(oid0, path, Lifespan.nowOn(0), "W", perms.contains("w")));
			results.add(requestSetValue(oid0, path, Lifespan.nowOn(0), "X", perms.contains("x")));

			RootMessage msgInsert = RootMessage.newBuilder()
					.setRequestInsertObject(RequestInsertObject.newBuilder()
							.setOid(oid0)
							.setObject(ObjSpec.newBuilder().setPath(path))
							.setSpan(TraceRmiHandler.makeSpan(Lifespan.nowOn(0)))
							.setResolution(Resolution.CR_ADJUST))
					.build();
			results.add(request(msgInsert).thenAccept(reply -> {
				assertMsgCase(MsgCase.REPLY_INSERT_OBJECT, reply);
			}));
		}

		@Override
		public Trace getTrace() throws Throwable {
			return Unique.assertOne(connection.getTargets()).getTrace();
		}

		@Override
		public void close() throws Exception {
			client.close();
			connection.close();
		}
	}

	class RmiTraceMaker implements TraceMaker {
		protected TraceRmiService getService() throws Throwable {
			TraceRmiService service = tool.getService(TraceRmiService.class);
			if (service != null) {
				return service;
			}
			return addPlugin(tool, TraceRmiPlugin.class);
		}

		private void startNegotiate(OutputStream out) throws IOException {
			RootMessage msg = RootMessage.newBuilder()
					.setRequestNegotiate(RequestNegotiate.newBuilder()
							.setDescription("Test")
							.setVersion(TraceRmiHandler.VERSION)
							.addAllMethods(List.of()))
					.build();
			TraceRmiHandler.sendDelimited(out, msg, 0);
		}

		@Override
		public TraceHandle createTrace() throws Throwable {
			TraceRmiService service = getService();
			TraceRmiAcceptor acceptor = service.acceptOne(new InetSocketAddress("localhost", 0));
			Socket client = new Socket();

			client.connect(acceptor.getAddress());
			startNegotiate(client.getOutputStream());
			TraceRmiConnection connection = acceptor.accept();
			RmiTraceHandle th = new RmiTraceHandle(connection, client);
			th.finishNegotiate();

			TxId txid = th.nextTx();
			th.createTrace(name.getMethodName()).get(10000, TimeUnit.MILLISECONDS);
			th.doStartTx(txid).get(1000, TimeUnit.MILLISECONDS);
			th.createRootObject().get(1000, TimeUnit.MILLISECONDS);
			th.doEndTx(txid).get(1000, TimeUnit.MILLISECONDS);
			tb = new ToyDBTraceBuilder(th.getTrace());
			return th;
		}
	}

	class NerfedRmiTraceMaker extends RmiTraceMaker {
		@Override
		protected TraceRmiService getService() throws Throwable {
			tool.removePlugins(tool.getManagedPlugins()
					.stream()
					.filter(p -> p instanceof TraceRmiPlugin)
					.toList());
			return addPlugin(tool, NerfedTraceRmiPlugin.class);
		}
	}

	static class TimeMe implements AutoCloseable {
		private final String name;
		private final long start;

		public TimeMe(String name) {
			this.name = name;
			Msg.info(this, "Starting: " + name);
			this.start = System.currentTimeMillis();
		}

		@Override
		public void close() throws Exception {
			long elapsed = System.currentTimeMillis() - start;
			Msg.info(this, "Finished: " + name + ". Took " + elapsed + " ms");
		}
	}

	@Test
	@Repeated(20) // First time will measure warm-up
	public void testMeasureViaApiIsolated() throws Throwable {
		TraceMaker tm = new ApiTraceMaker();
		try (TraceHandle th = tm.createTrace()) {
			try (TimeMe __ = new TimeMe("Add via API. Isolated.")) {
				th.addLotsOfRegions();
			}
		}
	}

	@Test
	@Repeated(2) // First time will measure warm-up
	public void testMeasureViaRmiIsolated() throws Throwable {
		TraceMaker tm = new RmiTraceMaker();
		try (TraceHandle th = tm.createTrace()) {
			try (TimeMe __ = new TimeMe("Add via RMI. Isolated.")) {
				th.addLotsOfRegions();
			}
		}
	}

	static class NerfedTraceRmiHandler extends TraceRmiHandler {
		public NerfedTraceRmiHandler(TraceRmiPlugin plugin, Socket socket) throws IOException {
			super(plugin, socket);
		}

		@Override
		protected ReplyCreateObject handleCreateObject(RequestCreateObject req) {
			return ReplyCreateObject.getDefaultInstance();
		}

		@Override
		protected ReplySetValue handleSetValue(RequestSetValue req)
				throws AddressOverflowException {
			return ReplySetValue.getDefaultInstance();
		}

		@Override
		protected ReplyInsertObject handleInsertObject(RequestInsertObject req) {
			return ReplyInsertObject.getDefaultInstance();
		}
	}

	static class NerfedTraceRmiAcceptor extends DefaultTraceRmiAcceptor {
		public NerfedTraceRmiAcceptor(TraceRmiPlugin plugin, SocketAddress address) {
			super(plugin, address);
		}

		@Override
		public NerfedTraceRmiHandler doAccept(TraceRmiAcceptor acceptor)
				throws IOException {
			Socket client = socket.accept();
			NerfedTraceRmiHandler handler = new NerfedTraceRmiHandler(plugin, client);
			handler.start();
			plugin.listeners.invoke().connected(handler, getConnectMode(), acceptor);
			return handler;
		}
	}

	public static class NerfedTraceRmiPlugin extends TraceRmiPlugin {
		public NerfedTraceRmiPlugin(PluginTool tool) {
			super(tool);
		}

		@Override
		public DefaultTraceRmiAcceptor acceptOne(SocketAddress address) throws IOException {
			NerfedTraceRmiAcceptor acceptor = new NerfedTraceRmiAcceptor(this, address);
			acceptor.start();
			listeners.invoke().waitingAccept(acceptor);
			return acceptor;
		}
	}

	@Test
	@Repeated(2)
	public void testMeasureRmiNetworkOnly() throws Throwable {
		TraceMaker tm = new NerfedRmiTraceMaker();
		try (TraceHandle th = tm.createTrace()) {
			try (TimeMe __ = new TimeMe("Add via RMI. Isolated.")) {
				th.addLotsOfRegions();
			}
		}
	}

	@Test
	@Repeated(2)
	public void testMeasurePlainTable() throws Exception {
		DBHandle handle = new DBHandle();
		// Some comparable number of fields to a DBTraceObjectValue
		Schema schema = new SchemaBuilder()
				.field("Parent", LongField.class)
				.field("EntryKey", StringField.class)
				.field("MinSnap", LongField.class)
				.field("MaxSnap", LongField.class)
				.field("Value", BinaryField.class)
				.build();

		try (TimeMe tm = new TimeMe("Plain table")) {
			try (Transaction tx = handle.openTransaction(null)) {
				Table table = handle.createTable("Test", schema);
				for (int i = 0; i < RECORD_COUNT; i++) {
					DBRecord rec = schema.createRecord(0);
					rec.setLongValue(0, 0);
					rec.setString(1, "Whatever");
					rec.setLongValue(2, 0);
					rec.setLongValue(3, Long.MAX_VALUE);

					ByteBuffer rangeEnc = ByteBuffer.allocate(18);
					rangeEnc.putShort((short) 0x204); // Made up "space id"
					rangeEnc.putLong(1024 * i);
					rangeEnc.putLong(1024 * i + 1023);
					rec.setBinaryData(4, rangeEnc.array());

					table.putRecord(rec);
				}
			}
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class TestObject extends DBAnnotatedObject {

		static final String NAME_PARENT = "Parent";
		static final String NAME_ENTRY_KEY = "EntryKey";
		static final String NAME_MIN_SNAP = "MinSnap";
		static final String NAME_MAX_SNAP = "MaxSnap";
		static final String NAME_VALUE = "Value";

		@DBAnnotatedColumn(NAME_PARENT)
		static DBObjectColumn COL_PARENT;
		@DBAnnotatedColumn(NAME_ENTRY_KEY)
		static DBObjectColumn COL_ENTRY_KEY;
		@DBAnnotatedColumn(NAME_MIN_SNAP)
		static DBObjectColumn COL_MIN_SNAP;
		@DBAnnotatedColumn(NAME_MAX_SNAP)
		static DBObjectColumn COL_MAX_SNAP;
		@DBAnnotatedColumn(NAME_VALUE)
		static DBObjectColumn COL_VALUE;

		@DBAnnotatedField(column = NAME_PARENT)
		private long parent;
		@DBAnnotatedField(column = NAME_ENTRY_KEY)
		private String entryKey;
		@DBAnnotatedField(column = NAME_MIN_SNAP)
		private long minSnap;
		@DBAnnotatedField(column = NAME_MAX_SNAP)
		private long maxSnap;
		@DBAnnotatedField(column = NAME_VALUE)
		private byte[] value;

		protected TestObject(DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
		}

		public void set(long parent, String entryKey, long minSnap, long maxSnap, byte[] value) {
			this.parent = parent;
			this.entryKey = entryKey;
			this.minSnap = minSnap;
			this.maxSnap = maxSnap;
			this.value = value;

			update(COL_PARENT, COL_ENTRY_KEY, COL_MIN_SNAP, COL_MAX_SNAP, COL_VALUE);
		}
	}

	public static class TestDomainObject extends DBCachedDomainObjectAdapter {
		protected TestDomainObject(DBHandle dbh, DBOpenMode openMode, TaskMonitor monitor,
				String name, int timeInterval, int bufSize, Object consumer) {
			super(dbh, openMode, monitor, name, timeInterval, bufSize, consumer);
		}

		@Override
		public boolean isChangeable() {
			return true;
		}

		@Override
		public String getDescription() {
			return "Test Domain Object";
		}
	}

	@Test
	@Repeated(2)
	public void testMeasureObjectStore() throws Exception {
		DBHandle handle = new DBHandle();
		TestDomainObject domObj =
			new TestDomainObject(handle, DBOpenMode.CREATE, monitor, "Test", 500, 1000, this);
		DBCachedObjectStoreFactory factory = new DBCachedObjectStoreFactory(domObj);

		try (TimeMe tm = new TimeMe("Object Store")) {
			try (Transaction tx = domObj.openTransaction("Test")) {
				DBCachedObjectStore<TestObject> store = factory.getOrCreateCachedStore("Test",
					TestObject.class, TestObject::new, false);
				for (int i = 0; i < RECORD_COUNT; i++) {
					try (LockHold hold = LockHold.lock(domObj.getReadWriteLock().writeLock())) {
						TestObject obj = store.create();

						ByteBuffer rangeEnc = ByteBuffer.allocate(18);
						rangeEnc.putShort((short) 0x204); // Made up "space id"
						rangeEnc.putLong(1024 * i);
						rangeEnc.putLong(1024 * i + 1023);
						obj.set(0, "Whatever", 0, Long.MAX_VALUE, rangeEnc.array());
					}
				}
			}
		}
	}

	@Test
	@Repeated(20)
	public void testMeasureRTree() throws Exception {
		MyDomainObject domObj = new MyDomainObject(this);

		try (TimeMe tm = new TimeMe("Object Store")) {
			try (Transaction tx = domObj.openTransaction("Test")) {
				for (int i = 0; i < RECORD_COUNT; i++) {
					domObj.map.put(
						IntRect.ALL.immutable(0, Integer.MAX_VALUE, i * 1024, i * 1024 + 1023),
						"Whatever");
				}
			}
		}
	}
}
