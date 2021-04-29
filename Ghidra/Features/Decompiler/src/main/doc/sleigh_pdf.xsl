<?xml version='1.0'?>
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<xsl:import href="http://docbook.sourceforge.net/release/xsl/current/fo/docbook.xsl"/>

<xsl:include href="sleigh_common.xsl" />

<xsl:param name="fop1.extensions" select="1"/>  <!-- Use fop extensions when converting to pdf -->

<xsl:param name="alignment" select="'left'"/>   <!-- Justify normal text (only) on the left -->

<xsl:param name="draft.mode" select="'no'"/>    <!-- Turn off the draft background watermark -->

</xsl:stylesheet>
