<?xml version='1.0'?>
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<xsl:import href="http://docbook.sourceforge.net/release/xsl/1.79.1/html/chunk.xsl"/>

<xsl:include href="decompileplugin_common.xsl" />

<!-- Bump up the heading levels so that "chapter" gets and h1 header -->

<xsl:template name="component.title">
  <xsl:param name="node" select="."/>
  
  <xsl:variable name="level">
    <xsl:choose>
      <xsl:when test="ancestor::section">
    <xsl:value-of select="count(ancestor::section)+1"/>
      </xsl:when>
      <xsl:when test="ancestor::sect">6</xsl:when>
      <xsl:when test="ancestor::sect">5</xsl:when>
      <xsl:when test="ancestor::sect">4</xsl:when>
      <xsl:when test="ancestor::sect">3</xsl:when>
      <xsl:when test="ancestor::sect">2</xsl:when>
      <xsl:otherwise>1</xsl:otherwise>
    </xsl:choose>
  </xsl:variable>

  <!--  Let's handle the case where a component (bibliography, for example)
        occurs inside a section; will we need parameters for this? -->

  <xsl:element name="h{$level}">
    <xsl:attribute name="class">title</xsl:attribute>
    <xsl:call-template name="anchor">
      <xsl:with-param name="node" select="$node"/>
      <xsl:with-param name="conditional" select="0"/>
    </xsl:call-template>
    <xsl:apply-templates select="$node" mode="object.title.markup">
      <xsl:with-param name="allow-anchors" select="1"/>
    </xsl:apply-templates>
  </xsl:element>
</xsl:template>

<xsl:template name="body.attributes">
  <!-- Remove all BODY attributes so that CSS stylesheet can provide everything -->
</xsl:template>

<xsl:param name="suppress.navigation" select="1"/>  <!-- Turn off header/footer navigation links -->

<xsl:param name="use.id.as.filename" select="1"/>  <!-- Split up into files based on id attribute -->

<xsl:param name="html.stylesheet" select="'help/shared/DefaultStyle.css'"/>    <!-- Use our custom cascading style sheet -->

<xsl:param name="chunk.section.depth" select="0"/>

<xsl:param name="chunker.output.indent" select="'yes'"/>   <!-- Do proper indenting of html -->

<xsl:param name="chunker.output.encoding" select="'UTF-8'"/>  <!-- Encode the chunks as UTF-8 files -->

<xsl:param name="admon.graphics" select="1"/>  <!-- Turn on graphic icon for important/note tags -->

<xsl:param name="admon.textlabel" select="0"/>  <!-- Don't display title for important/note tags -->

<xsl:param name="admon.graphics.path" select="'help/shared/'"/>
</xsl:stylesheet>
