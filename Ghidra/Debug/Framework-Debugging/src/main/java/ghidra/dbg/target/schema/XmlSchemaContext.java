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
	protected static final String ELEM_CONTEXT = "context";
	protected static final String ATTR_CANONICAL = "canonical";
	protected static final String ELEM_SCHEMA = "schema";
	protected static final String ATTR_ELEMENT_RESYNC = "elementResync";
	protected static final String ATTR_ATTRIBUTE_RESYNC = "attributeResync";
	protected static final String ELEM_INTERFACE = "interface";
	protected static final String ELEM_ELEMENT = "element";
	protected static final String ATTR_INDEX = "index";
	protected static final String ELEM_ATTRIBUTE = "attribute";
	protected static final String ATTR_NAME = "name";
	protected static final String ATTR_SCHEMA = "schema";
	protected static final String ATTR_REQUIRED = "required";
	protected static final String ATTR_FIXED = "fixed";
	protected static final String ATTR_HIDDEN = "hidden";
	protected static final String ELEM_ATTRIBUTE_ALIAS = "attribute-alias";
	protected static final String ATTR_FROM = "from";
	protected static final String ATTR_TO = "to";
	protected static final String YES = "yes";
	protected static final Set<String> TRUES = Set.of("true", YES, "y", "1");

	protected static boolean parseBoolean(Element ele, String attrName) {
		return TRUES.contains(ele.getAttributeValue(attrName, "no").toLowerCase());
	}

	public static String serialize(SchemaContext ctx) {
		return XmlUtilities.toString(contextToXml(ctx));
	}

	public static Element contextToXml(SchemaContext ctx) {
		Element result = new Element(ELEM_CONTEXT);
		for (TargetObjectSchema schema : ctx.getAllSchemas()) {
			Element schemaElem = schemaToXml(schema);
			if (schemaElem != null) {
				result.addContent(schemaElem);
			}
		}
		return result;
	}

	public static Element attributeSchemaToXml(AttributeSchema as) {
		Element attrElem = new Element(ELEM_ATTRIBUTE);
		if (!as.getName().equals("")) {
			XmlUtilities.setStringAttr(attrElem, ATTR_NAME, as.getName());
		}
		XmlUtilities.setStringAttr(attrElem, ATTR_SCHEMA, as.getSchema().toString());
		if (as.isRequired()) {
			XmlUtilities.setStringAttr(attrElem, ATTR_REQUIRED, YES);
		}
		if (as.isFixed()) {
			XmlUtilities.setStringAttr(attrElem, ATTR_FIXED, YES);
		}
		if (as.isHidden()) {
			XmlUtilities.setStringAttr(attrElem, ATTR_HIDDEN, YES);
		}
		return attrElem;
	}

	public static Element aliasToXml(Map.Entry<String, String> alias) {
		Element aliasElem = new Element(ELEM_ATTRIBUTE_ALIAS);
		XmlUtilities.setStringAttr(aliasElem, ATTR_FROM, alias.getKey());
		XmlUtilities.setStringAttr(aliasElem, ATTR_TO, alias.getValue());
		return aliasElem;
	}

	public static Element schemaToXml(TargetObjectSchema schema) {
		if (!TargetObject.class.isAssignableFrom(schema.getType())) {
			return null;
		}
		if (schema == EnumerableTargetObjectSchema.OBJECT) {
			return null;
		}

		Element result = new Element(ELEM_SCHEMA);
		XmlUtilities.setStringAttr(result, ATTR_NAME, schema.getName().toString());
		for (Class<? extends TargetObject> iface : schema.getInterfaces()) {
			Element ifElem = new Element(ELEM_INTERFACE);
			XmlUtilities.setStringAttr(ifElem, ATTR_NAME,
				DebuggerObjectModel.requireIfaceName(iface));
			result.addContent(ifElem);
		}

		if (schema.isCanonicalContainer()) {
			XmlUtilities.setStringAttr(result, ATTR_CANONICAL, YES);
		}
		XmlUtilities.setStringAttr(result, ATTR_ELEMENT_RESYNC,
			schema.getElementResyncMode().name());
		XmlUtilities.setStringAttr(result, ATTR_ATTRIBUTE_RESYNC,
			schema.getAttributeResyncMode().name());

		for (Map.Entry<String, SchemaName> ent : schema.getElementSchemas().entrySet()) {
			Element elemElem = new Element(ELEM_ELEMENT);
			XmlUtilities.setStringAttr(elemElem, ATTR_INDEX, ent.getKey());
			XmlUtilities.setStringAttr(elemElem, ATTR_SCHEMA, ent.getValue().toString());
			result.addContent(elemElem);
		}
		Element deElem = new Element(ELEM_ELEMENT);
		XmlUtilities.setStringAttr(deElem, ATTR_SCHEMA,
			schema.getDefaultElementSchema().toString());
		result.addContent(deElem);

		for (Map.Entry<String, AttributeSchema> ent : schema.getAttributeSchemas().entrySet()) {
			AttributeSchema as = ent.getValue();
			if (!ent.getKey().equals(as.getName())) {
				// Exclude aliases here
				continue;
			}
			Element attrElem = attributeSchemaToXml(as);
			result.addContent(attrElem);
		}
		AttributeSchema das = schema.getDefaultAttributeSchema();
		Element daElem = attributeSchemaToXml(das);
		result.addContent(daElem);

		// Yes, these will be the "resolved" aliases, but I think that's okay.
		for (Map.Entry<String, String> alias : schema.getAttributeAliases().entrySet()) {
			Element aliasElem = aliasToXml(alias);
			result.addContent(aliasElem);
		}

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
		for (Element schemaElem : XmlUtilities.getChildren(contextElem, ELEM_SCHEMA)) {
			ctx.schemaFromXml(schemaElem);
		}
		return ctx;
	}

	protected final Map<String, SchemaName> names = new HashMap<>();

	public synchronized SchemaName name(String name) {
		return names.computeIfAbsent(name, SchemaName::new);
	}

	private String requireAttributeValue(Element elem, String name) {
		String value = elem.getAttributeValue(name);
		if (value == null) {
			throw new IllegalArgumentException(
				"Missing attribute '%s' in %s".formatted(name, elem));
		}
		return value;
	}

	public TargetObjectSchema schemaFromXml(Element schemaElem) {
		SchemaBuilder builder = builder(name(schemaElem.getAttributeValue(ATTR_NAME, "")));

		for (Element ifaceElem : XmlUtilities.getChildren(schemaElem, ELEM_INTERFACE)) {
			String ifaceName = requireAttributeValue(ifaceElem, ATTR_NAME);
			Class<? extends TargetObject> iface = TargetObject.INTERFACES_BY_NAME.get(ifaceName);
			if (iface == null) {
				Msg.warn(this, "Unknown interface name: '" + ifaceName + "'");
			}
			else {
				builder.addInterface(iface);
			}
		}

		builder.setCanonicalContainer(parseBoolean(schemaElem, ATTR_CANONICAL));
		builder.setElementResyncMode(ResyncMode.valueOf(
			schemaElem.getAttributeValue(ATTR_ELEMENT_RESYNC, ResyncMode.NEVER.name())));
		builder.setAttributeResyncMode(ResyncMode.valueOf(
			schemaElem.getAttributeValue(ATTR_ATTRIBUTE_RESYNC, ResyncMode.NEVER.name())));

		for (Element elemElem : XmlUtilities.getChildren(schemaElem, ELEM_ELEMENT)) {
			SchemaName schema = name(requireAttributeValue(elemElem, ATTR_SCHEMA));
			String index = elemElem.getAttributeValue(ATTR_INDEX, "");
			builder.addElementSchema(index, schema, elemElem);
		}

		for (Element attrElem : XmlUtilities.getChildren(schemaElem, ELEM_ATTRIBUTE)) {
			SchemaName schema = name(requireAttributeValue(attrElem, ATTR_SCHEMA));
			boolean required = parseBoolean(attrElem, ATTR_REQUIRED);
			boolean fixed = parseBoolean(attrElem, ATTR_FIXED);
			boolean hidden = parseBoolean(attrElem, ATTR_HIDDEN);

			String name = attrElem.getAttributeValue(ATTR_NAME, "");
			builder.addAttributeSchema(
				new DefaultAttributeSchema(name, schema, required, fixed, hidden), attrElem);
		}

		for (Element aliasElem : XmlUtilities.getChildren(schemaElem, ELEM_ATTRIBUTE_ALIAS)) {
			String from = requireAttributeValue(aliasElem, ATTR_FROM);
			String to = requireAttributeValue(aliasElem, ATTR_TO);
			builder.addAttributeAlias(from, to, aliasElem);
		}

		return builder.buildAndAdd();
	}
}
