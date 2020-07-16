<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

  <xsl:import href="/usr/share/sgml/docbook/stylesheet/xsl/docbook-xsl/fo/docbook.xsl"/>

  <xsl:include href="cspec_common.xsl" />

  <!-- Use fop extensions when converting to pdf -->
  <xsl:param name="fop1.extensions" select="1"/>

  <!-- Justify normal text (only) on the left -->
  <xsl:param name="alignment" select="'left'"/>

  <!-- Turn off the draft background watermark -->
  <xsl:param name="draft.mode" select="'no'"/>

</xsl:stylesheet>
