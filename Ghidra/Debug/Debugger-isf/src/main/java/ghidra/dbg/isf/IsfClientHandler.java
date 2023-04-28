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
package ghidra.dbg.isf;

import java.io.IOException;
import java.io.StringWriter;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.gson.JsonObject;

import ghidra.async.AsyncUtils;
import ghidra.dbg.isf.protocol.Isf;
import ghidra.dbg.isf.protocol.Isf.ErrorCode;
import ghidra.dbg.isf.protocol.Isf.RootMessage;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.ISF.IsfDataTypeWriter;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class IsfClientHandler {
	protected static final boolean LOG_ERROR_REPLY_STACKS = false;

	protected final static AtomicInteger sequencer = new AtomicInteger();

	protected static <T> T errorSendNotify(Throwable e) {
		Msg.error(IsfClientHandler.class, "Could not send notification: " + e);
		return null;
	}

	private IsfServer server;

	// Keeps strong references and tells level of subscription

	public IsfClientHandler(IsfServer server) {
		this.server = server;
	}

	protected Isf.RootMessage buildError(Isf.RootMessage req, ErrorCode code, String message) {
		return Isf.RootMessage.newBuilder()
				.setSequence(req.getSequence())
				.setErrorReply(Isf.ErrorReply.newBuilder().setCode(code).setMessage(message))
				.build();
	}

	protected RootMessage replyError(Isf.RootMessage req, Throwable e) {
		Throwable t = AsyncUtils.unwrapThrowable(e);
		if (LOG_ERROR_REPLY_STACKS) {
			Msg.debug(this, "Error caused by request " + req, e);
		}
		else {
			Msg.debug(this, "Error caused by request " + req + ": " + e);
		}
		if (t instanceof UnsupportedOperationException) {
			return buildError(req, ErrorCode.EC_NOT_SUPPORTED, t.getMessage());
		}
		return buildError(req, ErrorCode.EC_UNKNOWN, "Unknown server-side error");
	}

	protected String getVersion() {
		return "V1";
	}

	protected RootMessage processMessage(Isf.RootMessage msg) throws IOException {
		switch (msg.getMsgCase()) {
			case PING_REQUEST:
				return processPing(msg.getSequence(), msg.getPingRequest());
			case FULL_EXPORT_REQUEST:
				return processFullExport(msg.getSequence(), msg.getFullExportRequest());
			case LOOK_TYPE_REQUEST:
				return processLookType(msg.getSequence(), msg.getLookTypeRequest());
			case LOOK_SYMBOL_REQUEST:
				return processLookSym(msg.getSequence(), msg.getLookSymbolRequest());
			case LOOK_ADDRESS_REQUEST:
				return processLookAddr(msg.getSequence(), msg.getLookAddressRequest());
			case ENUM_TYPES_REQUEST:
				return processEnumTypes(msg.getSequence(), msg.getEnumTypesRequest());
			case ENUM_SYMBOLS_REQUEST:
				return processEnumSyms(msg.getSequence(), msg.getEnumSymbolsRequest());
			default:
				throw new IsfErrorException(Isf.ErrorCode.EC_BAD_REQUEST,
					"Unrecognized request: " + msg.getMsgCase());
		}
	}

	protected RootMessage processPing(int seqno, Isf.PingRequest req) {
		return Isf.RootMessage.newBuilder()
				.setSequence(seqno)
				.setPingReply(Isf.PingReply.newBuilder().setContent(req.getContent()))
				.build();
	}

	protected RootMessage processFullExport(int seqno, Isf.FullExportRequest req)
			throws IOException {
		String data = fullExport(req.getNs());
		return Isf.RootMessage.newBuilder()
				.setSequence(seqno)
				.setFullExportReply(Isf.FullExportReply.newBuilder()
						.setValue(data))
				.build();
	}

	private String fullExport(String ns) throws IOException {
		IsfDataTypeWriter isfWriter = createDataTypeWriter(server.getDataTypeManager(ns));
		return writeFrom(isfWriter);
	}

	protected RootMessage processLookType(int seqno, Isf.LookTypeRequest req) throws IOException {
		String data = lookType(req.getNs(), req.getKey());
		return Isf.RootMessage.newBuilder()
				.setSequence(seqno)
				.setLookTypeReply(Isf.LookTypeReply.newBuilder()
						.setValue(data))
				.build();
	}

	private String lookType(String ns, String key) throws IOException {
		IsfDataTypeWriter isfWriter = createDataTypeWriter(server.getDataTypeManager(ns));
		isfWriter.setSkipSymbols(true);
		isfWriter.requestType(key);
		return writeFrom(isfWriter);
	}

	protected RootMessage processLookSym(int seqno, Isf.LookSymRequest req) throws IOException {
		String data = lookSym(req.getNs(), req.getKey());
		return Isf.RootMessage.newBuilder()
				.setSequence(seqno)
				.setLookSymbolReply(Isf.LookSymReply.newBuilder()
						.setValue(data))
				.build();
	}

	private String lookSym(String ns, String key) throws IOException {
		IsfDataTypeWriter isfWriter = createDataTypeWriter(server.getDataTypeManager(ns));
		isfWriter.setSkipTypes(true);
		isfWriter.requestSymbol(key);
		return writeFrom(isfWriter);
	}

	protected RootMessage processLookAddr(int seqno, Isf.LookAddrRequest req) throws IOException {
		String data = lookAddr(req.getNs(), req.getKey());
		return Isf.RootMessage.newBuilder()
				.setSequence(seqno)
				.setLookAddressReply(Isf.LookAddrReply.newBuilder()
						.setValue(data))
				.build();
	}

	private String lookAddr(String ns, String key) throws IOException {
		IsfDataTypeWriter isfWriter = createDataTypeWriter(server.getDataTypeManager(ns));
		isfWriter.setSkipTypes(true);
		isfWriter.requestAddress(key);
		return writeFrom(isfWriter);
	}

	protected RootMessage processEnumTypes(int seqno, Isf.EnumTypesRequest req) throws IOException {
		String data = enumTypes(req.getNs());
		return Isf.RootMessage.newBuilder()
				.setSequence(seqno)
				.setEnumTypesReply(Isf.EnumTypesReply.newBuilder()
						.setValue(data))
				.build();
	}

	private String enumTypes(String ns) throws IOException {
		IsfDataTypeWriter isfWriter = createDataTypeWriter(server.getDataTypeManager(ns));
		isfWriter.setSkipSymbols(true);
		return writeFrom(isfWriter);
	}

	protected RootMessage processEnumSyms(int seqno, Isf.EnumSymsRequest req) throws IOException {
		String data = enumSyms(req.getNs());
		return Isf.RootMessage.newBuilder()
				.setSequence(seqno)
				.setEnumSymbolsReply(Isf.EnumSymsReply.newBuilder()
						.setValue(data))
				.build();
	}

	private String enumSyms(String ns) throws IOException {
		IsfDataTypeWriter isfWriter = createDataTypeWriter(server.getDataTypeManager(ns));
		isfWriter.setSkipTypes(true);
		return writeFrom(isfWriter);
	}

	private IsfDataTypeWriter createDataTypeWriter(DataTypeManager dtm) throws IOException {
		StringWriter out = new StringWriter();
		return new IsfDataTypeWriter(dtm, out);
	}

	private String writeFrom(IsfDataTypeWriter dataTypeWriter) throws IOException {
		try {
			JsonObject object =
				dataTypeWriter.getRootObject(TaskMonitor.DUMMY);
			dataTypeWriter.write(object);
		}
		catch (CancelledException e) {
			// NOTHING
		}
		finally {
			dataTypeWriter.close();
		}
		return dataTypeWriter.toString();
	}

}
