package burp;

import java.net.URL;

public class PotentialXSSIssue extends CustomScanIssue
{
    public PotentialXSSIssue(
                            IHttpService httpService,
                            URL url,
                            IHttpRequestResponse[] httpMessages,
                            IParameter parameter)
    {
        super(
            httpService,
            url,
            httpMessages,
            "Potential XSS",
            "The value of the URL parameter " + parameter.getName() + " was found in the response body",
            "Information"
        );
    }

    @Override
    public String getConfidence()
    {
        return "Firm";
    }

}