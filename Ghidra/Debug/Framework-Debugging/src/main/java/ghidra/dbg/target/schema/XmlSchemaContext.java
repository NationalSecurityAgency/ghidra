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
package ghidra.dbg.target.schema;

import java.io.*;
import java.util.*;

import org.jdom.*;
import org.jdom.input.SAXBuilder;

import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.DefaultTargetObjectSchema.DefaultAttributeSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.*;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;

public class XmlSchemaContext extends DefaultSchemaContext {
	protected static final Set<String> TRUES = Set.of("true", "yes", "y", "1");

	protected static boolean parseBoolean(Element ele, String attrName) {
		return TRUES.contains(ele.getAttributeValue(attrName, "no").toLowerCase());
	}

	public static String serialize(SchemaContext ctx) {
		return XmlUtilities.toString(contextToXml(ctx));
	}

	public static Element contextToXml(SchemaContext ctx) {
		Element result = new Element("context");
		for (TargetObjectSchema schema : ctx.getAllSchemas()) {
			Element schemaElem = schemaToXml(schema);
			if (schemaElem != null) {
				result.addContent(schemaElem);
			}
		}
		return result;
	}

	public static Element attributeSchemaToXml(AttributeSchema as) {
		Element attrElem = new Element("attribute");
		if (!as.getName().equals("")) {
			XmlUtilities.setStringAttr(attrElem, "name", as.getName());
		}
		XmlUtilities.setStringAttr(attrElem, "schema", as.getSchema().toString());
		if (as.isRequired()) {
			XmlUtilities.setStringAttr(attrElem, "required", "yes");
		}
		if (as.isFixed()) {
			XmlUtilities.setStringAttr(attrElem, "fixed", "yes");
		}
		if (as.isHidden()) {
			XmlUtilities.setStringAttr(attrElem, "hidden", "yes");
		}
		return attrElem;
	}

	public static Element schemaToXml(TargetObjectSchema schema) {
		if (!TargetObject.class.isAssignableFrom(schema.getType())) {
			return null;
		}
		if (schema == EnumerableTargetObjectSchema.OBJECT) {
			return null;
		}

		Element result = new Element("schema");
		XmlUtilities.setStringAttr(result, "name", schema.getName().toString());
		for (Class<? extends TargetObject> iface : schema.getInterfaces()) {
			Element ifElem = new Element("interface");
			XmlUtilities.setStringAttr(ifElem, "name", DebuggerObjectModel.requireIfaceName(iface));
			result.addContent(ifElem);
		}

		if (schema.isCanonicalContainer()) {
			XmlUtilities.setStringAttr(result, "canonical", "yes");
		}
		XmlUtilities.setStringAttr(result, "elementResync",
			schema.getElementResyncMode().name());
		XmlUtilities.setStringAttr(result, "attributeResync",
			schema.getAttributeResyncMode().name());

		for (Map.Entry<String, SchemaName> ent : schema.getElementSchemas().entrySet()) {
			Element elemElem = new Element("element");
			XmlUtilities.setStringAttr(elemElem, "index", ent.getKey());
			XmlUtilities.setStringAttr(elemElem, "schema", ent.getValue().toString());
			result.addContent(elemElem);
		}
		Element deElem = new Element("element");
		XmlUtilities.setStringAttr(deElem, "schema", schema.getDefaultElementSchema().toString());
		result.addContent(deElem);

		for (AttributeSchema as : schema.getAttributeSchemas().values()) {
			Element attrElem = attributeSchemaToXml(as);
			result.addContent(attrElem);
		}
		AttributeSchema das = schema.getDefaultAttributeSchema();
		Element daElem = attributeSchemaToXml(das);
		result.addContent(daElem);

		return result;
	}

	public static XmlSchemaContext deserialize(String xml) throws JDOMException {
		return deserialize(xml.getBytes());
	}

	public static XmlSchemaContext deserialize(byte[] xml) throws JDOMException {
		try {
			return deserialize(new ByteArrayInputStream(xml));
		}
		catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	public static XmlSchemaContext deserialize(File file) throws JDOMException, IOException {
		return deserialize(new FileInputStream(file));
	}

	public static XmlSchemaContext deserialize(InputStream is) throws JDOMException, IOException {
		SAXBuilder sb = XmlUtilities.createSecureSAXBuilder(false, false);
		Document doc = sb.build(Objects.requireNonNull(is));
		return contextFromXml(doc.getRootElement());
	}

	public static XmlSchemaContext contextFromXml(Element contextElem) {
		XmlSchemaContext ctx = new XmlSchemaContext();
		for (Element schemaElem : XmlUtilities.getChildren(contextElem, "schema")) {
			ctx.schemaFromXml(schemaElem);
		}
		return ctx;
	}

	protected final Map<String, SchemaName> names = new HashMap<>();

	public synchronized SchemaName name(String name) {
		return names.computeIfAbsent(name, SchemaName::new);
	}

	public TargetObjectSchema schemaFromXml(Element schemaElem) {
		SchemaBuilder builder = builder(name(schemaElem.getAttributeValue("name", "")));

		for (Element ifaceElem : XmlUtilities.getChildren(schemaElem, "interface")) {
			String ifaceName = ifaceElem.getAttributeValue("name");
			Class<? extends TargetObject> iface = TargetObject.INTERFACES_BY_NAME.get(ifaceName);
			if (iface == null) {
				Msg.warn(this, "Unknown interface name: '" + ifaceName + "'");
			}
			else {
				builder.addInterface(iface);
			}
		}

		builder.setCanonicalContainer(parseBoolean(schemaElem, "canonical"));
		builder.setElementResyncMode(
			ResyncMode.valueOf(schemaElem.getAttributeValue("elementResync")));
		builder.setAttributeResyncMode(
			ResyncMode.valueOf(schemaElem.getAttributeValue("attributeResync")));

		for (Element elemElem : XmlUtilities.getChildren(schemaElem, "element")) {
			SchemaName schema = name(elemElem.getAttributeValue("schema"));
			String index = elemElem.getAttributeValue("index", "");
			builder.addElementSchema(index, schema, elemElem);
		}

		for (Element attrElem : XmlUtilities.getChildren(schemaElem, "attribute")) {
			SchemaName schema = name(attrElem.getAttributeValue("schema"));
			boolean required = parseBoolean(attrElem, "required");
			boolean fixed = parseBoolean(attrElem, "fixed");
			boolean hidden = parseBoolean(attrElem, "hidden");

			String name = attrElem.getAttributeValue("name", "");
			builder.addAttributeSchema(
				new DefaultAttributeSchema(name, schema, required, fixed, hidden), attrElem);
		}

		return builder.buildAndAdd();
	}
}
