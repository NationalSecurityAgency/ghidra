<?xml version='1.0'?>
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<xsl:import href="http://docbook.sourceforge.net/release/xsl/current/fo/docbook.xsl"/>

<xsl:include href="decompileplugin_common.xsl" />

<!-- Turn on italics for cross-references -->
<xsl:template match="sect1|sect2|sect3|sect4|sect5|section|simplesect"
	      mode="insert.title.markup">
  <xsl:param name="purpose"/>
  <xsl:param name="xrefstyle"/>
  <xsl:param name="title"/>

  <xsl:choose>
    <xsl:when test="$purpose = 'xref'">
      <fo:inline font-style="italic">
	<xsl:copy-of select="$title"/>
      </fo:inline>
    </xsl:when>
    <xsl:otherwise>
      <xsl:copy-of select="$title"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<xsl:param name="fop1.extensions" select="1"/>  <!-- Use fop extensions when converting to pdf -->

<xsl:param name="alignment" select="'left'"/>   <!-- Justify normal text (only) on the left -->

<xsl:param name="draft.mode" select="'no'"/>    <!-- Turn off the draft background watermark -->

<xsl:param name="admon.graphics" select="1"/>  <!-- Turn on graphic icon for important/note tags -->

<xsl:param name="admon.textlabel" select="0"/>  <!-- Don't display title for important/note tags -->

<xsl:param name="admon.graphics.path" select="'../../../build/pdf/images/'"/>

</xsl:stylesheet>
