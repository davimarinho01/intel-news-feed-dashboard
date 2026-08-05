BeforeAll {
    . (Join-Path $PSScriptRoot "..\modules\Sources.ps1")
}

Describe "Get-RssNodeText" {
    It "returns a plain string unchanged" {
        Get-RssNodeText "Hello World" | Should -Be "Hello World"
    }

    It "returns an empty string for null input" {
        Get-RssNodeText $null | Should -Be ""
    }

    It "unwraps InnerText from a CDATA-wrapped XmlElement" {
        # Regression test: Dark Reading's RSS wraps title/link in CDATA, which
        # Invoke-RestMethod surfaces as an XmlElement instead of a plain string.
        [xml]$Doc = "<root><title><![CDATA[15 TP-Link Bugs Expose Risks in Zero-Trust Provisioning]]></title></root>"
        $Node = $Doc.root.title
        $Node.GetType().Name | Should -Be "XmlElement"
        Get-RssNodeText $Node | Should -Be "15 TP-Link Bugs Expose Risks in Zero-Trust Provisioning"
    }
}
