package burp;

import java.net.URL;

public class ASPNETVersionIssue extends CustomScanIssue
{
	public ASPNETVersionIssue(
							  IHttpService httpService,
                              URL url,
                              IHttpRequestResponse[] httpMessages,
                              String version)
	{
		super(
			httpService,
			url,
			httpMessages,
			"ASP.NET Version - " + version,
            "The X-AspNet-Version response header value has been detected",
            "Low"
		);
	}
}