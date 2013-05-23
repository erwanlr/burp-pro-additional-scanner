package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    
    public CustomScanIssue(
                           IHttpService httpService,
                           URL url,
                           IHttpRequestResponse[] httpMessages,
                           String name,
                           String detail,
                           String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }
    
    @Override
    public URL getUrl()
    {
        return url;
    }
    
    @Override
    public String getIssueName()
    {
        return name;
    }
    
    @Override
    public int getIssueType()
    {
        return 0;
    }
    
    @Override
    public String getSeverity()
    {
        return severity;
    }
    
    @Override
    public String getConfidence()
    {
        return "Certain";
    }
    
    @Override
    public String getIssueBackground()
    {
        return null;
    }
    
    @Override
    public String getRemediationBackground()
    {
        return null;
    }
    
    @Override
    public String getIssueDetail()
    {
        return detail;
    }
    
    @Override
    public String getRemediationDetail()
    {
        return null;
    }
    
    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }
    
    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }
}