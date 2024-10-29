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
package ghidra.app.plugin.core.string.translate.libretranslate;

import static ghidra.program.model.data.TranslationSettingsDefinition.*;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.http.*;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandler;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import com.google.gson.*;

import docking.widgets.SelectFromListDialog;
import ghidra.app.plugin.core.string.translate.libretranslate.LibreTranslatePlugin.SOURCE_LANGUAGE_OPTION;
import ghidra.app.services.StringTranslationService;
import ghidra.net.HttpClients;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 * Connects to an external LibreTranslate server via HTTP.
 */
public class LibreTranslateStringTranslationService implements StringTranslationService {
	static final String CONTENT_TYPE_JSON = "application/json";
	static final String CONTENT_TYPE_HEADER = "Content-Type";
	private static final String GHIDRA_USER_AGENT = "Ghidra";

	private URI serverURI;
	private String apiKey;
	private SOURCE_LANGUAGE_OPTION sourceLanguageOption;
	private String targetLanguageCode;
	private List<SupportedLanguage> supportedLanguages;
	private int batchSize;
	private int maxRetryCount = 3;
	private int httpTimeout;
	private int httpTimeoutPerString;

	/**
	 * Creates an instance of {@link LibreTranslateStringTranslationService}
	 * 
	 * @param serverURI URL of the LibreTranslate server
	 * @param apiKey optional string, api key required to submit requests to the server
	 * @param sourceLanguageOption {@link SOURCE_LANGUAGE_OPTION} enum
	 * @param targetLanguageCode language code that the server should translate each string into
	 * @param batchSize max number of strings to submit to the server per request
	 * @param httpTimeout time to wait for a http request to finish 
	 * @param httpTimeoutPerString additional time per string element to wait for http request to finish
	 */
	public LibreTranslateStringTranslationService(URI serverURI, String apiKey,
			SOURCE_LANGUAGE_OPTION sourceLanguageOption, String targetLanguageCode, int batchSize,
			int httpTimeout, int httpTimeoutPerString) {
		String path = serverURI.getPath();
		this.serverURI = path.endsWith("/") ? serverURI : serverURI.resolve(path + "/");
		this.apiKey = Objects.requireNonNullElse(apiKey, "");
		this.sourceLanguageOption = sourceLanguageOption;
		this.targetLanguageCode = targetLanguageCode;
		this.batchSize = Math.clamp(batchSize, 1, batchSize);
		this.httpTimeout = Math.clamp(httpTimeout, 1, httpTimeout);
		this.httpTimeoutPerString = Math.clamp(httpTimeoutPerString, 1, httpTimeoutPerString);
	}

	@Override
	public String getTranslationServiceName() {
		return LibreTranslatePlugin.LIBRE_TRANSLATE_SERVICE_NAME;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("LibreTranslatePlugin", "LibreTranslatePlugin");
	}

	@Override
	public void translate(Program program, List<ProgramLocation> stringLocations,
			TranslateOptions options) {
		Msg.info(this, "LibreTranslate translate %d strings using %s"
				.formatted(stringLocations.size(), serverURI));
		TaskLauncher.launchModal("Translate Strings", monitor -> {

			monitor.initialize(stringLocations.size(), "Gathering strings");
			List<Entry<ProgramLocation, String>> sourceStrings = stringLocations.stream()
					.map(progLoc -> Map.entry(progLoc, DataUtilities.getDataAtLocation(progLoc)))
					.map(entry -> {
						monitor.incrementProgress();
						// convert progLoc->Data into progLoc->String
						StringDataInstance sdi =
							StringDataInstance.getStringDataInstance(entry.getValue());
						String s = sdi.getStringValue();
						return s != null ? Map.entry(entry.getKey(), s) : null;
					})
					.filter(Objects::nonNull)
					.toList();

			String langCode;
			switch (sourceLanguageOption) {
				case PROMPT:
					try {
						ensureSupportedLanguages(monitor);
						SupportedLanguage selectedLang = SelectFromListDialog.selectFromList(
							supportedLanguages, "Choose Source Language", "Choose",
							SupportedLanguage::getDescription);
						if (selectedLang == null) {
							return;
						}
						langCode = selectedLang.langCode;
					}
					catch (IOException e) {
						showError("Error Fetching Supported Languages",
							"Failed to retrieve list of supported languages", e);
						return;
					}
					break;
				case AUTO:
				default:
					langCode = "auto";
					break;
			}

			try {
				List<ProgramLocation> successfulStrings =
					translate(program, sourceStrings, langCode, monitor);
				int failCount = sourceStrings.size() - successfulStrings.size();
				if (failCount > 0) {
					Msg.showWarn(this, null, "Translation Incomplete",
						"%d of %d strings not translated".formatted(failCount,
							stringLocations.size()));
				}
			}
			catch (IOException e) {
				showError("LibreTranslate Error", "Error when translating strings", e);
			}
		});
	}

	private List<ProgramLocation> translate(Program program,
			List<Entry<ProgramLocation, String>> srcStrings, String srcLangCode,
			TaskMonitor monitor) throws IOException {

		List<ProgramLocation> successfulStrings = new ArrayList<>();

		program.withTransaction("Translate strings", () -> {
			try {
				monitor.initialize(srcStrings.size(), "Translating strings");
				for (int srcIndex = 0; srcIndex < srcStrings.size(); srcIndex += batchSize) {
					monitor.checkCancelled();
					List<Entry<ProgramLocation, String>> subList = srcStrings.subList(srcIndex,
						Math.min(srcStrings.size(), srcIndex + batchSize));

					List<String> subListStrs = subList.stream().map(e -> e.getValue()).toList();

					long start_ts = System.currentTimeMillis();
					String jsonResponseStr = null;
					for (int retryCount = 0; retryCount < maxRetryCount; retryCount++) {
						// NOTE: some strings cause the LibreTranslate server to take much longer
						// to respond, which would be the most likely cause of timeout
						// issues.  Repeating the same request will cause the same timeout error,
						// so instead the retryCount is used to scale the timeout.
						long timeout =
							(this.httpTimeout + (subListStrs.size() * httpTimeoutPerString)) *
								(retryCount + 1);

						HttpRequest request =
							createTranslateRequest(subListStrs, srcLangCode, timeout);
						if (retryCount != 0) {
							monitor.setMessage(
								"Retrying translate request (%d)".formatted(retryCount));
						}
						try {
							jsonResponseStr =
								asyncRequest(request, BodyHandlers.ofString(), monitor);
							break;
						}
						catch (HttpTimeoutException e) {
							if (retryCount == maxRetryCount - 1) {
								throw new IOException(
									"Timeout during translate request, %d of %d strings completed"
											.formatted(successfulStrings.size(), srcStrings.size()),
									e);
							}
							Msg.error(this, "LibreTranslate timeout on translate request for: %s"
									.formatted(subListStrs));
						}
					}

					List<String> subResults = parseTranslateResponse(jsonResponseStr, subListStrs);
					for (int resultIndex = 0; resultIndex < subResults.size(); resultIndex++) {
						ProgramLocation progLoc = subList.get(resultIndex).getKey();
						// FUTURE feature: we could attempt to detect if the original string wasn't
						// translated by comparing the original string subListStrs.get(resultIndex)
						// with the xlatedValue.
						String xlatedValue = subResults.get(resultIndex);
						if (xlatedValue != null && !xlatedValue.trim().isEmpty()) {
							Data data = DataUtilities.getDataAtLocation(progLoc);
							TRANSLATION.setTranslatedValue(data, xlatedValue);
							TRANSLATION.setShowTranslated(data, true);
							monitor.increment();
							successfulStrings.add(progLoc);
						}
					}

					long elapsed = System.currentTimeMillis() - start_ts;
					int sps = subList.size() / Math.max(1, (int) (elapsed / 1000));
					Msg.debug(this, "LibreTranslate translate batch %d/%d strings, %dms"
							.formatted(successfulStrings.size(), srcStrings.size(), elapsed));
					monitor.setMessage(
						"Translating strings (%d strings per second)".formatted(sps));
				}
			}
			catch (CancelledException e) {
				// stop loop without error
			}
		});

		Msg.info(this, "Finished LibreTranslate, %d/%d strings".formatted(srcStrings.size(),
			successfulStrings.size()));
		return successfulStrings;
	}

	private HttpRequest createTranslateRequest(List<String> sourceStrings, String sourceLangCode,
			long timeout) throws IOException {
		Map<String, Object> requestParams = Map.of( // see libretranslate's website for api params
			"q", sourceStrings,  // query strings
			"source", sourceLangCode, // source lang code, eg "yy", or "auto"
			"target", targetLanguageCode, // target lang code, eg. "en"
			"format", "text", // "text" or "html", we always want text
			"alternatives", 0, // TODO: not using alternative answers yet
			"api_key", apiKey);

		HttpRequest request = request("translate", timeout)		// build request
				.header(CONTENT_TYPE_HEADER, CONTENT_TYPE_JSON)
				.POST(ofJsonEncodedParams(requestParams))
				.build();
		return request;
	}

	private List<String> parseTranslateResponse(String jsonResponseStr, List<String> requestedStrs)
			throws IOException {
		List<String> results = new ArrayList<>();
		try {
			JsonObject json = JsonParser.parseString(jsonResponseStr).getAsJsonObject();
			JsonElement xlatedTextEle = json.get("translatedText");
			if (xlatedTextEle == null) {
				throw new JsonSyntaxException("Bad json data for translatedText value");
			}
			JsonArray xlatedTexts = xlatedTextEle.getAsJsonArray();
			if (xlatedTexts.size() != requestedStrs.size()) {
				throw new IllegalStateException("LibreTranslate response size mismatch");
			}

			// NOTE: if translate request was marked as "auto" source lang, the response will have
			// a "detectedLanguage" : { "confidence": int, "language": str } property.

			for (int resultIndex = 0; resultIndex < xlatedTexts.size(); resultIndex++) {
				results.add(xlatedTexts.get(resultIndex).getAsString());
			}
			return results;
		}
		catch (IllegalStateException | JsonSyntaxException e) {
			Msg.error(this, "Error parsing translate result: " + resultToSafeStr(jsonResponseStr));
			throw new IOException("Bad data in json response", e);
		}
		catch (Throwable th) {
			Msg.error(this, "Error parsing translate result: " + resultToSafeStr(jsonResponseStr));
			throw th;
		}
	}

	/**
	 * Information about a language supported by LibreTranslate
	 * @param name language name
	 * @param langCode 2 digit code
	 * @param targets list of other languages that this language can be translated into
	 */
	public record SupportedLanguage(String name, String langCode, List<String> targets) {
		public String getDescription() {
			return "%s (%s)".formatted(name, langCode);
		}
	}

	private void ensureSupportedLanguages(TaskMonitor monitor) throws IOException {
		try {
			if (supportedLanguages == null || supportedLanguages.isEmpty()) {
				supportedLanguages = getSupportedLanguages(monitor);
				if (supportedLanguages != null && !supportedLanguages.isEmpty()) {
					supportedLanguages.add(0,
						new SupportedLanguage("Autodetect", "auto", List.of()));
				}
			}
		}
		catch (CancelledException e) {
			throw new IOException("Failed to get supported language list: request cancelled");
		}
	}

	/**
	 * Returns a list of languages that the LibreTranslate server supports.
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @return list of {@link SupportedLanguage} records
	 * @throws IOException if error connecting or excessive time to respond
	 * @throws CancelledException if cancelled
	 */
	public List<SupportedLanguage> getSupportedLanguages(TaskMonitor monitor)
			throws IOException, CancelledException {
		HttpRequest request =
			request("languages").header(CONTENT_TYPE_HEADER, CONTENT_TYPE_JSON).GET().build();

		String jsonResponseStr = asyncRequest(request, BodyHandlers.ofString(), monitor);

		try {
			// [ { "code": "en", "name": "English", "targets": ["ar", ...
			JsonArray json = JsonParser.parseString(jsonResponseStr).getAsJsonArray();
			List<SupportedLanguage> results = new ArrayList<>();
			for (int i = 0; i < json.size(); i++) {
				SupportedLanguage supportedLang =
					parseSupportedLangJson(json.get(i).getAsJsonObject());
				results.add(supportedLang);
			}
			Collections.sort(results, (o1, o2) -> o1.langCode.compareTo(o2.langCode));
			return results;
		}
		catch (IllegalStateException | JsonSyntaxException e) {
			throw new IOException("Bad data in json response: " + jsonResponseStr, e);
		}
	}

	private SupportedLanguage parseSupportedLangJson(JsonObject obj) {
		if (obj.get("code") == null || obj.get("name") == null || obj.get("targets") == null) {
			throw new JsonSyntaxException("Bad json data for supported language");
		}
		String srcLangCode = obj.get("code").getAsString();
		String srcLangName = obj.get("name").getAsString();
		JsonArray targets = obj.get("targets").getAsJsonArray();
		List<String> targetLangCodes = new ArrayList<>();
		targets.forEach(targetEle -> {
			targetLangCodes.add(targetEle.getAsString());
		});
		return new SupportedLanguage(srcLangName, srcLangCode, targetLangCodes);
	}

	private <T> T asyncRequest(HttpRequest request, BodyHandler<T> bodyHandler, TaskMonitor monitor)
			throws CancelledException, IOException {
		CompletableFuture<HttpResponse<T>> futureResponse =
			HttpClients.getHttpClient().sendAsync(request, bodyHandler);
		CancelledListener l = () -> futureResponse.cancel(true);
		monitor.addCancelledListener(l);

		try {
			HttpResponse<T> response = futureResponse.get();

			int statusCode = response.statusCode();
			if (statusCode != HttpURLConnection.HTTP_OK) {
				Msg.debug(this, "HTTP request [%s], response: %d, body: %s".formatted(request.uri(),
					statusCode, resultToSafeStr(response.body().toString())));
				throw new IOException(
					"Bad HTTP result [%d] for request [%s]".formatted(statusCode, request.uri()));
			}

			String responseContentType =
				response.headers().firstValue(CONTENT_TYPE_HEADER).orElse("missing");
			if (!CONTENT_TYPE_JSON.equals(responseContentType)) {
				throw new IOException(
					"Bad content-type in result: [%s]".formatted(responseContentType));
			}

			return response.body();
		}
		catch (InterruptedException e) {
			throw new CancelledException("Request canceled");
		}
		catch (ExecutionException e) {
			// if possible, unwrap the exception that happened inside the future
			Throwable cause = e.getCause();
			Msg.error(this, "Error during HTTP request [%s]".formatted(request.uri()), cause);
			throw (cause instanceof IOException)
					? (IOException) cause
					: new IOException("Error during HTTP request", cause);
		}
		finally {
			monitor.removeCancelledListener(l);
		}

	}

	private static BodyPublisher ofJsonEncodedParams(Map<String, Object> params) {
		JsonObject obj = new JsonObject();
		params.forEach((k, v) -> {
			if (v instanceof String str) {
				obj.addProperty(k, str);
			}
			else if (v instanceof Number num) {
				obj.addProperty(k, num);
			}
			else if (v instanceof Boolean bool) {
				obj.addProperty(k, bool);
			}
			else if (v instanceof List list) {
				JsonArray jsonArray = new JsonArray();
				for (Object listEle : list) {
					jsonArray.add(listEle.toString());
				}
				obj.add(k, jsonArray);
			}
		});
		return BodyPublishers.ofString(obj.toString());
	}

	private HttpRequest.Builder request(String str) throws IOException {
		return request(str, httpTimeout);
	}

	private HttpRequest.Builder request(String str, long timeoutMS) throws IOException {
		try {
			return HttpRequest.newBuilder(serverURI.resolve(str))
					.timeout(Duration.ofMillis(timeoutMS))
					.setHeader("User-Agent", GHIDRA_USER_AGENT);
		}
		catch (IllegalArgumentException e) {
			throw new IOException(e);
		}
	}

	private void showError(String title, String msg, Throwable th) {
		String summary = th.getMessage();
		if (summary == null || summary.isBlank()) {
			summary = th.getClass().getSimpleName();
		}
		Msg.showError(this, null, title,
			"%s: %s\n\nLibreTranslate server URL: %s".formatted(msg, summary, serverURI), th);

	}

	private String resultToSafeStr(String s) {
		if (s.length() > 200) {
			s = s.substring(0, 200) + "....";
		}
		return s;
	}
}
